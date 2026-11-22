#!/usr/bin/env python3
"""Validate the provider catalog structure, semantics, and official signature."""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = ROOT / "catalog" / "providers.catalog.json"
SCHEMA_PATH = ROOT / "catalog" / "providers.catalog.schema.json"
SIGNATURE_PATH = ROOT / "catalog" / "providers.catalog.sig"
PUBLIC_KEY_PATH = ROOT / "trust" / "official-catalog-public-key.spki.b64"
MAX_CATALOG_BYTES = 5 * 1024 * 1024
SUPPORTED_SCHEMA_VERSION = 1
SENSITIVE_KEYS = re.compile(
    r"(?:api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|"
    r"password|passwd|authorization|private[_-]?key|credential)",
    re.IGNORECASE,
)
SECRET_TEXT = re.compile(
    r"-----BEGIN (?:EC |RSA |OPENSSH )?PRIVATE KEY-----|"
    r"\bBearer\s+[A-Za-z0-9._~+/-]{12,}|"
    r"\bsk-[A-Za-z0-9_-]{20,}"
)


class CatalogError(ValueError):
    """Raised when a catalog violates a repository contract."""


def _pairs_without_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise CatalogError(f"Duplicate JSON object key: {key}")
        result[key] = value
    return result


def strict_json_loads(data: bytes, label: str) -> object:
    try:
        return json.loads(
            data.decode("utf-8-sig"),
            object_pairs_hook=_pairs_without_duplicates,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CatalogError(f"{label} is not valid UTF-8 JSON: {exc}") from exc


def normalize_host(host: str) -> str:
    if not isinstance(host, str) or not host or host != host.strip():
        raise CatalogError(f"Invalid host entry: {host!r}")
    if any(marker in host for marker in ("://", "/", "\\", "@", "*", "?", "#")):
        raise CatalogError(f"Host must be a bare exact host name: {host!r}")
    if host.endswith("."):
        raise CatalogError(f"Host must not have a trailing dot: {host!r}")
    try:
        return ipaddress.ip_address(host).compressed.lower()
    except ValueError:
        pass

    try:
        ascii_host = host.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise CatalogError(f"Invalid IDN host: {host!r}") from exc
    if len(ascii_host) > 253 or not ascii_host:
        raise CatalogError(f"Invalid DNS host length: {host!r}")
    labels = ascii_host.split(".")
    if any(
        not label
        or len(label) > 63
        or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
        for label in labels
    ):
        raise CatalogError(f"Invalid DNS host: {host!r}")
    if host != ascii_host:
        raise CatalogError(f"Host must be canonical lowercase ASCII: {host!r}")
    return ascii_host


def _walk(obj: object, path: str = "$"):
    if isinstance(obj, dict):
        for key, value in obj.items():
            if SENSITIVE_KEYS.search(key):
                raise CatalogError(f"Credential-shaped field at {path}.{key}")
            yield from _walk(value, f"{path}.{key}")
    elif isinstance(obj, list):
        for index, value in enumerate(obj):
            yield from _walk(value, f"{path}[{index}]")
    elif isinstance(obj, str):
        if SECRET_TEXT.search(obj):
            raise CatalogError(f"Credential-shaped text at {path}")


def _validate_pointer(pointer: object, path: str) -> None:
    if not isinstance(pointer, str) or not pointer.startswith("/"):
        raise CatalogError(f"JSON Pointer at {path} must start with '/'")
    if re.search(r"~(?![01])", pointer):
        raise CatalogError(f"Invalid RFC 6901 escape in JSON Pointer at {path}: {pointer}")


def _check_recipe(recipe: dict, provider_id: str, capability: str, trusted_hosts: set[str]) -> None:
    status = recipe.get("status")
    strategy = recipe.get("strategy")
    label = f"provider {provider_id!r} {capability} recipe"
    if status == "unknown" and strategy != "unknown":
        raise CatalogError(f"{label} has unknown status with non-unknown strategy")
    if status == "unsupported" and strategy != "unsupported":
        raise CatalogError(f"{label} has unsupported status with a runnable strategy")
    if status == "supported" and strategy in ("unknown", "unsupported"):
        raise CatalogError(f"{label} has supported status with non-runnable strategy")
    if status != "supported" and any(key in recipe for key in ("request", "requests", "response", "outputs")):
        raise CatalogError(f"{label} must not define executable mappings unless supported")
    if "quotaDisplay" in recipe and capability != "keyUsage":
        raise CatalogError(f"{label} cannot declare quotaDisplay outside keyUsage")

    if capability == "keyUsage":
        request = recipe.get("request", {})
        if (
            status != "supported"
            or strategy != "new-api-token-usage"
            or any(key in recipe for key in ("requests", "response", "outputs"))
            or request.get("method") != "GET"
            or request.get("auth") != "bearer"
            or ("url" in request) == ("path" in request)
        ):
            raise CatalogError(f"{label} requires one New API bearer GET to a URL or path")

    request_ids: set[str] = set()
    requests = list(recipe.get("requests", []))
    if isinstance(recipe.get("request"), dict):
        requests.append(recipe["request"])
    for request in requests:
        request_id = request.get("id")
        if request_id in request_ids:
            raise CatalogError(f"{label} has duplicate request id {request_id!r}")
        if request_id is not None:
            request_ids.add(request_id)
        if "url" in request:
            try:
                parsed = urlsplit(request["url"])
                _ = parsed.port
            except ValueError as exc:
                raise CatalogError(f"{label} contains an invalid static request URL") from exc
            if parsed.scheme.lower() != "https" or parsed.username or parsed.password or parsed.query or parsed.fragment:
                raise CatalogError(f"{label} contains an unsafe static request URL")
            if normalize_host(parsed.hostname or "") not in trusted_hosts:
                raise CatalogError(f"{label} static URL host is absent from trustedHosts")
        if "path" in request and (request["path"].startswith("//") or "\\" in request["path"]):
            raise CatalogError(f"{label} contains a non-relative request path")
    mappings = []
    if isinstance(recipe.get("response"), dict):
        mappings.append(recipe["response"])
    if isinstance(recipe.get("outputs"), dict):
        mappings.append(recipe["outputs"])
    for mapping in mappings:
        for field_name, field_mapping in mapping.items():
            if isinstance(field_mapping, dict):
                pointer = field_mapping.get("pointer")
                if pointer is not None:
                    _validate_pointer(pointer, f"{label}.{field_name}")
                request_id = field_mapping.get("requestId")
                if request_id is not None and request_id not in request_ids:
                    raise CatalogError(f"{label}.{field_name} references unknown request id {request_id!r}")


def validate_catalog(catalog: object, schema: object) -> None:
    if not isinstance(schema, dict) or schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        raise CatalogError("Schema must declare JSON Schema Draft 2020-12")
    if not isinstance(catalog, dict):
        raise CatalogError("Catalog root must be an object")
    Draft202012Validator.check_schema(schema)
    errors = sorted(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(catalog),
        key=lambda error: tuple(str(part) for part in error.absolute_path),
    )
    if errors:
        first = errors[0]
        where = ".".join(str(part) for part in first.absolute_path) or "$"
        raise CatalogError(f"Schema error at {where}: {first.message}")
    if catalog["schemaVersion"] != SUPPORTED_SCHEMA_VERSION:
        raise CatalogError(f"Unsupported schemaVersion {catalog['schemaVersion']}")
    if not isinstance(catalog["catalogVersion"], int) or isinstance(catalog["catalogVersion"], bool):
        raise CatalogError("catalogVersion must be an integer")
    providers = catalog["providers"]
    if not providers:
        raise CatalogError("Catalog must contain at least one provider")

    provider_ids: set[str] = set()
    for provider in providers:
        provider_id = provider["id"]
        folded_id = provider_id.casefold()
        if folded_id in provider_ids:
            raise CatalogError(f"Duplicate provider ID: {provider_id}")
        provider_ids.add(folded_id)

        exact_hosts = [normalize_host(host) for host in provider["match"]["exactHosts"]]
        trusted_hosts = [normalize_host(host) for host in provider["trustedHosts"]]
        for hosts, label in ((exact_hosts, "exactHosts"), (trusted_hosts, "trustedHosts")):
            if len(set(hosts)) != len(hosts):
                raise CatalogError(f"Provider {provider_id!r} has duplicate normalized {label}")

        route_ids: set[str] = set()
        route_urls: set[str] = set()
        for route in provider["routes"]:
            route_id = route["id"].casefold()
            if route_id in route_ids:
                raise CatalogError(f"Provider {provider_id!r} has duplicate route ID: {route['id']}")
            route_ids.add(route_id)
            try:
                parsed = urlsplit(route["baseUrl"])
                route_port = parsed.port
            except ValueError as exc:
                raise CatalogError(f"Provider {provider_id!r} has a route URL with an invalid port") from exc
            if parsed.scheme.lower() != "https" and not (
                parsed.hostname in ("localhost", "127.0.0.1", "::1")
            ):
                raise CatalogError(f"Provider {provider_id!r} route must use HTTPS or loopback")
            if parsed.username or parsed.password or parsed.query or parsed.fragment:
                raise CatalogError(f"Provider {provider_id!r} route URL contains unsafe components")
            route_host = normalize_host(parsed.hostname or "")
            if route_host not in trusted_hosts:
                raise CatalogError(f"Provider {provider_id!r} route host is absent from trustedHosts")
            normalized_url = f"{parsed.scheme.lower()}://{route_host}"
            if route_port is not None and not (
                (parsed.scheme.lower() == "https" and route_port == 443)
                or (parsed.scheme.lower() == "http" and route_port == 80)
            ):
                normalized_url += f":{route_port}"
            normalized_url += parsed.path.rstrip("/")
            if normalized_url in route_urls:
                raise CatalogError(f"Provider {provider_id!r} has duplicate route URL: {route['baseUrl']}")
            route_urls.add(normalized_url)

        for capability, recipe in provider["capabilities"].items():
            _check_recipe(recipe, provider_id, capability, set(trusted_hosts))

    # The catalog is descriptor data only: reject recognizable credential fields/text.
    tuple(_walk(catalog))


def verify_signature(catalog_bytes: bytes, signature_text: str, public_key_text: str) -> None:
    try:
        signature = base64.b64decode(signature_text.strip(), validate=True)
        public_key_der = base64.b64decode(public_key_text.strip(), validate=True)
        public_key = serialization.load_der_public_key(public_key_der)
    except (ValueError, TypeError) as exc:
        raise CatalogError(f"Signature or public key encoding is invalid: {exc}") from exc
    if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(public_key.curve, ec.SECP256R1):
        raise CatalogError("Official verification key must be an ECDSA P-256 SPKI key")
    if len(signature) == 64:
        r = int.from_bytes(signature[:32], "big")
        s = int.from_bytes(signature[32:], "big")
        signature = utils.encode_dss_signature(r, s)
    try:
        public_key.verify(signature, catalog_bytes, ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError) as exc:
        raise CatalogError("Detached signature does not verify over the exact catalog bytes") from exc


def validate_files(
    catalog_bytes: bytes,
    schema_bytes: bytes,
    signature_text: str,
    public_key_text: str,
) -> tuple[dict, dict]:
    if len(catalog_bytes) > MAX_CATALOG_BYTES:
        raise CatalogError(f"Catalog exceeds {MAX_CATALOG_BYTES} bytes")
    catalog = strict_json_loads(catalog_bytes, "Catalog")
    schema = strict_json_loads(schema_bytes, "Schema")
    validate_catalog(catalog, schema)
    verify_signature(catalog_bytes, signature_text, public_key_text)
    return catalog, schema


def main() -> int:
    try:
        catalog_bytes = CATALOG_PATH.read_bytes()
        schema_bytes = SCHEMA_PATH.read_bytes()
        signature_text = SIGNATURE_PATH.read_text(encoding="ascii")
        public_key_text = PUBLIC_KEY_PATH.read_text(encoding="ascii")
        catalog, _schema = validate_files(catalog_bytes, schema_bytes, signature_text, public_key_text)
    except (OSError, CatalogError) as exc:
        print(f"CATALOG_VALIDATION=FAIL: {exc}", file=sys.stderr)
        return 1

    public_key_der = base64.b64decode(public_key_text.strip())
    print(f"CATALOG_VALIDATION=PASS")
    print(f"schemaVersion={catalog['schemaVersion']}")
    print(f"catalogVersion={catalog['catalogVersion']}")
    print(f"providers={len(catalog['providers'])}")
    print(f"catalog_sha256={hashlib.sha256(catalog_bytes).hexdigest()}")
    print(f"schema_sha256={hashlib.sha256(schema_bytes).hexdigest()}")
    print(f"signature_sha256={hashlib.sha256(SIGNATURE_PATH.read_bytes()).hexdigest()}")
    print(f"public_key_sha256={hashlib.sha256(public_key_der).hexdigest()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
