from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.verify_catalog import (  # noqa: E402
    CATALOG_PATH,
    PUBLIC_KEY_PATH,
    SCHEMA_PATH,
    SIGNATURE_PATH,
    CatalogError,
    MAX_CATALOG_BYTES,
    strict_json_loads,
    validate_catalog,
    validate_files,
    verify_signature,
)


class ProviderCatalogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog_bytes = CATALOG_PATH.read_bytes()
        cls.schema_bytes = SCHEMA_PATH.read_bytes()
        cls.signature = SIGNATURE_PATH.read_text(encoding="ascii")
        cls.public_key = PUBLIC_KEY_PATH.read_text(encoding="ascii")
        cls.catalog = strict_json_loads(cls.catalog_bytes, "Catalog")
        cls.schema = strict_json_loads(cls.schema_bytes, "Schema")

    def test_current_payload_schema_and_signature_validate(self) -> None:
        catalog, _schema = validate_files(
            self.catalog_bytes, self.schema_bytes, self.signature, self.public_key
        )
        self.assertEqual(catalog["schemaVersion"], 1)
        self.assertEqual(catalog["catalogVersion"], 7)
        self.assertEqual(len(catalog["providers"]), 8)

    def test_expected_provider_ids_and_conservative_heju_capabilities(self) -> None:
        providers = {provider["id"]: provider for provider in self.catalog["providers"]}
        self.assertEqual(
            set(providers),
            {
                "generic-responses",
                "deepseek",
                "xai",
                "modelflare",
                "new-api",
                "router-cheap",
                "openrouter",
                "hejuapi",
            },
        )
        heju = providers["hejuapi"]["capabilities"]
        self.assertEqual(heju["balance"]["status"], "unknown")
        self.assertEqual(heju["usage"]["request"]["path"], "/dashboard/billing/usage")
        self.assertEqual(heju["keyUsage"]["request"]["url"], "https://www.hejuapi.com/api/usage/token/")
        self.assertEqual(heju["keyUsage"]["quotaDisplay"], {
            "currency": "USD", "symbol": "$", "rawUnitsPerBaseUnit": 500000,
        })

    def test_key_usage_requires_a_bearer_get(self) -> None:
        def add_invalid_key_usage(catalog: dict) -> None:
            heju = next(provider for provider in catalog["providers"] if provider["id"] == "hejuapi")
            heju["capabilities"]["keyUsage"]["request"]["auth"] = "none"

        self._expect_invalid(add_invalid_key_usage)

    def test_quota_display_requires_a_positive_divisor(self) -> None:
        def change_divisor(catalog: dict) -> None:
            heju = next(provider for provider in catalog["providers"] if provider["id"] == "hejuapi")
            heju["capabilities"]["keyUsage"]["quotaDisplay"]["rawUnitsPerBaseUnit"] = 0

        self._expect_invalid(change_divisor)

    def test_payload_tampering_invalidates_signature(self) -> None:
        tampered = bytearray(self.catalog_bytes)
        tampered[-1] ^= 1
        with self.assertRaises(CatalogError):
            verify_signature(bytes(tampered), self.signature, self.public_key)

    def test_mismatched_signature_fixture_is_rejected(self) -> None:
        fixture = ROOT / "tests" / "fixtures" / "signature-mismatch.json"
        with self.assertRaises(CatalogError):
            verify_signature(fixture.read_bytes(), self.signature, self.public_key)

    def _expect_invalid(self, mutate) -> None:
        candidate = copy.deepcopy(self.catalog)
        mutate(candidate)
        with self.assertRaises(CatalogError):
            validate_catalog(candidate, self.schema)

    def test_duplicate_provider_id_is_rejected(self) -> None:
        self._expect_invalid(lambda c: c["providers"].append(copy.deepcopy(c["providers"][0])))

    def test_noncanonical_host_is_rejected(self) -> None:
        self._expect_invalid(lambda c: c["providers"][0]["match"]["exactHosts"].__setitem__(0, "https://example.com"))

    def test_duplicate_route_id_is_rejected(self) -> None:
        def mutate(c):
            provider = c["providers"][0]
            provider["routes"].append(copy.deepcopy(provider["routes"][0]))
        self._expect_invalid(mutate)

    def test_unsupported_wire_api_is_rejected_by_schema(self) -> None:
        self._expect_invalid(lambda c: c["providers"][0]["codex"].__setitem__("wireApi", "chat-completions"))

    def test_unsupported_capability_strategy_combination_is_rejected(self) -> None:
        self._expect_invalid(
            lambda c: c["providers"][0]["capabilities"]["models"].__setitem__("strategy", "unsupported")
        )

    def test_route_with_embedded_credentials_is_rejected(self) -> None:
        self._expect_invalid(
            lambda c: c["providers"][0]["routes"][0].__setitem__(
                "baseUrl", "https://user:secret@example.com/v1"
            )
        )

    def test_single_request_url_must_use_trusted_host(self) -> None:
        self._expect_invalid(
            lambda c: c["providers"][0]["capabilities"]["models"]["request"].__setitem__(
                "url", "https://untrusted.example/models"
            )
        )

    def test_bad_json_pointer_escape_is_rejected(self) -> None:
        def mutate(c):
            for provider in c["providers"]:
                for recipe in provider["capabilities"].values():
                    for mapping_name in ("response", "outputs"):
                        mapping = recipe.get(mapping_name, {})
                        for field in mapping.values():
                            if isinstance(field, dict) and "pointer" in field:
                                field["pointer"] = "/data/~2invalid"
                                return
            self.fail("Expected at least one pointer in the current catalog")
        self._expect_invalid(mutate)

    def test_credential_field_is_rejected(self) -> None:
        self._expect_invalid(lambda c: c["providers"][0].__setitem__("apiKey", "sk-example"))

    def test_unknown_descriptor_field_is_rejected(self) -> None:
        self._expect_invalid(lambda c: c["providers"][0].__setitem__("unknown", True))

    def test_future_schema_version_is_rejected(self) -> None:
        self._expect_invalid(lambda c: c.__setitem__("schemaVersion", 2))

    def test_missing_evidence_field_is_rejected_by_schema(self) -> None:
        self._expect_invalid(lambda c: c["providers"][0]["evidence"][0].pop("verifiedAt"))

    def test_oversized_catalog_is_rejected_before_parsing(self) -> None:
        with self.assertRaises(CatalogError):
            validate_files(
                b" " * (MAX_CATALOG_BYTES + 1),
                self.schema_bytes,
                self.signature,
                self.public_key,
            )

    def test_duplicate_json_keys_are_rejected(self) -> None:
        with self.assertRaises(CatalogError):
            strict_json_loads(b'{"schemaVersion":1,"schemaVersion":1}', "fixture")


if __name__ == "__main__":
    unittest.main()
