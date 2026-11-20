# Versioning

`schemaVersion` changes only when the descriptor contract changes in a way that requires a consumer implementation change. A consumer must reject a schema version it does not support.

`catalogVersion` increases for every published content change. Do not reuse a content version for different bytes. The `updatedAt` value is informational UTC metadata; it is part of the signed payload and therefore changes require a new signature.

Catalog changes must preserve evidence, conservative capability status, exact host allowlists, and the established provider execution contract. Do not add speculative billing, quota, or usage support. The repository is a public data contract, not a software package or runtime update service.
