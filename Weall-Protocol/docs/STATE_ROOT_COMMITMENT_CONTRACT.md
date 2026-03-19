# State root commitment contract

`src/weall/runtime/state_hash.py` is consensus-critical.

The committed `state_root` is the SHA-256 of canonical JSON after recursively
stripping the following ephemeral keys from the working state snapshot:

- `created_ms`
- `bft`
- `meta`
- `tip_hash`
- `tip_ts_ms`

These fields are excluded because they are operational metadata, local runtime
bookkeeping, or circular tip-tracking data rather than durable ledger
semantics.

Any independent implementation must match this exact stripping set to remain
state-root compatible with this build.
