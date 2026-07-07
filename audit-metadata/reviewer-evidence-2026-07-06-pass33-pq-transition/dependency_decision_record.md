# Dependency decision record

## Decision

No toy or educational ML-DSA implementation was integrated. The patch includes an optional adapter for `cryptography` ML-DSA APIs, but the sandbox environment did not expose the `cryptography.hazmat.primitives.asymmetric.mldsa` module, so real ML-DSA signing and verification remain blocked in this environment.

## Rationale

- ML-DSA is the NIST FIPS 204 digital signature profile targeted by `pq-mldsa-v1`.
- `pq-mlkem-v1` is reserved for key establishment/transport, not transaction signing.
- Pure-Python educational ML-DSA packages were rejected for protocol signing because they are not appropriate as production cryptographic dependencies.
- liboqs-style bindings remain possible future candidates but require reproducible system dependency pinning, CI verification, and external cryptographic review.

## Consequence

The transition is scaffolding-only in this pass. Closed/public testnet signing should remain blocked until real ML-DSA is integrated, pinned, tested, and externally reviewed.
