# Patch note

The first live local two-node post-PQ rehearsal exposed an Ed25519-era API bound: `/v1/accounts/tx/register` rejected ML-DSA public keys because the request model capped `pubkey` at 256 characters.

The patch keeps the field bounded but raises the account registration skeleton route cap to 4096 characters, enough for hex-encoded ML-DSA-65 public keys.

A regression test was added to ensure the account registration skeleton accepts a real generated ML-DSA public key while preserving the existing route behavior.
