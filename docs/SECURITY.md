# Security model

The catalog is public declarative data. It must never contain credentials, bearer tokens, private keys, or user-specific provider configuration. The repository publishes only the official public verification key.

Consumers must verify the detached signature over the exact catalog bytes before treating a downloaded copy as official. Structural validation alone does not establish authenticity. Local user-defined provider descriptors should remain a separate trust layer and must not be represented as official catalog content.

Host matching is exact. Consumers must not replace it with suffix or substring matching. Credential-bearing inspection requests must be limited to the provider's explicit `trustedHosts` allowlist, bounded by the consumer's request and response limits, and restricted to read-only methods. Catalog recipes do not authorize a consumer to make arbitrary network requests.

The repository verifier rejects duplicate JSON keys, duplicate provider and route identifiers, noncanonical or invalid hosts, unsafe route URLs, unsupported strategy/status combinations, invalid JSON Pointer escapes, credential-shaped fields, and oversized catalogs. These checks are additional data-integrity rules; consumers still need their own runtime safeguards.

## Key handling

The public key is `trust/official-catalog-public-key.spki.b64`. Its SHA-256 fingerprint is printed by the verifier. The corresponding private signing key is held outside this repository and is never needed by validation, CI, or consumer applications. Do not commit a private key, signing request, or signing environment output.
