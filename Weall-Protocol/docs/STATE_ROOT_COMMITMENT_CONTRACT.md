# State root commitment contract

`src/weall/runtime/state_hash.py` is consensus-critical.

The committed `state_root` is the SHA-256 of canonical JSON produced by a
path-aware projection of the working state snapshot.

Only these **top-level** fields are excluded entirely:

- `created_ms`
- `bft`
- `tip_hash`
- `tip_ts_ms`

Top-level `state["meta"]` is mixed-use and is therefore not discarded as a
whole. The state-root projection commits the protocol-semantic keys enumerated
by `_CONSENSUS_META_KEYS` in `state_hash.py` (for example protocol/profile
identity, schema/tx-index identity, mempool/helper execution policy,
constitutional clock policy, and recent-block-anchor activation height) while
excluding node-local runtime posture such as `runtime_open`, shutdown status,
observer mode, operator notes, and clock warnings.

Nested application objects are canonicalized without recursively stripping
names such as `meta` or `created_ms`. A nested `meta` field may affect future
state transitions (for example legacy group membership policy) and therefore
must remain root-bound.

Dictionary keys are stringified and sorted, list order is preserved, and the
result is encoded as compact UTF-8 JSON before SHA-256 hashing.

Any independent implementation must match this exact path-aware projection to
remain state-root compatible with this build.
