# LLM Provider Catalog

Language-neutral provider descriptors for applications that need to identify OpenAI Responses-compatible endpoints and describe bounded, read-only capability probes.

The repository contains the canonical JSON catalog, its JSON Schema, and the existing detached signature. It does not contain an HTTP client, provider execution engine, credentials, or a package for any particular runtime. Consumers remain responsible for enforcing their own supported contract; Codex Control Center uses the separately maintained LLM ProviderKit for execution-side parsing and planning.

## Contents

- `catalog/providers.catalog.json` — signed catalog payload (schema version 1, content version 4).
- `catalog/providers.catalog.schema.json` — Draft 2020-12 structural schema.
- `catalog/providers.catalog.sig` — base64 detached ECDSA signature over the exact JSON bytes.
- `trust/official-catalog-public-key.spki.b64` — public verification key only.
- `tools/verify_catalog.py` and `tests/` — independent schema, semantic, and signature checks.

## Validate

Use Python 3.12 or newer:

```powershell
python -m pip install -r tools/requirements.txt
python tools/verify_catalog.py
python -m unittest discover -s tests -v
```

The verifier checks strict JSON parsing, Draft 2020-12 schema rules, cross-field safety rules, and the detached signature against the checked-in public key. It never needs a signing key or provider credentials.

## Contract and trust

See [the format guide](docs/FORMAT.md), [security model](docs/SECURITY.md), [signing procedure](docs/SIGNING.md), and [versioning policy](docs/VERSIONING.md).
