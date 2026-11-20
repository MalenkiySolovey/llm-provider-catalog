# Signature format and signing

`catalog/providers.catalog.sig` contains base64-encoded ECDSA P-256/SHA-256 signature bytes over the exact contents of `catalog/providers.catalog.json`. Verification accepts the two formats already supported by the official consumer verifier: 64-byte IEEE P1363 (`r || s`) and ASN.1 DER sequence.

The public SPKI key is committed at `trust/official-catalog-public-key.spki.b64`. The private key is intentionally not part of this repository. Normal contributor and CI workflows only verify signatures. A content change that needs a new official signature must be signed by the existing authorized key holder through the established protected signing process; never generate a replacement key as a shortcut.

After signing, run `python tools/verify_catalog.py` and `python -m unittest discover -s tests -v`. The verifier reports SHA-256 digests for the payload, schema, signature, and public key. Consumers should pin the catalog repository commit and verify both the commit identity and the detached signature.
