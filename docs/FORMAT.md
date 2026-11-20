# Catalog format

The payload is UTF-8 JSON. The checked-in signed payload is `catalog/providers.catalog.json`; its bytes are the signature input, so whitespace, encoding, and line endings are significant. The schema is JSON Schema Draft 2020-12 and is referenced by the payload using a relative `$schema` URI.

The top-level `schemaVersion` selects the descriptor contract; `catalogVersion` identifies a content revision. Each provider has a stable kebab-case `id`, exact host matches, a Codex wire API declaration, one or more routes, an explicit trusted-host allowlist, and `models`, `balance`, and `usage` capability recipes. Evidence records the source and verification time for asserted behavior.

Capability recipes are declarative data. Supported recipes may describe bounded GET/HEAD requests and JSON response mappings; they do not execute themselves. Unknown capability status must remain unknown. A catalog consumer must enforce the contract it supports and must not infer billing semantics from absent evidence.

Host entries are canonical lowercase DNS names or IP literals without a scheme, path, port, wildcard, or surrounding whitespace. Route URLs use HTTPS, except loopback development endpoints permitted by the consumer contract. Route URLs must not embed credentials, query strings, or fragments.

Response pointers use RFC 6901 JSON Pointer escaping. A tilde is permitted only as `~0` or `~1`. Multi-request recipe identifiers must be unique and response mappings may refer only to declared identifiers.
