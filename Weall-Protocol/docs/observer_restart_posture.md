# Observer Restart Posture

This batch hardens validator restart safety.

## Runtime behavior

- Every executor startup marks the persisted node state as `last_shutdown_clean=false` immediately.
- A graceful API/process shutdown calls `mark_clean_shutdown()` and flips the flag back to `true`.
- In production mode, if the previous shutdown was not clean, validator signing is disabled on the next boot unless `WEALL_ALLOW_DIRTY_SIGNING=1` is set explicitly.
- Operators may also force observer mode using `WEALL_OBSERVER_MODE=1`.

## Consensus impact

When observer mode is active the node will:

- refuse to propose blocks
- refuse to emit votes
- refuse to emit timeout messages

It can still verify blocks, observe QCs, catch up, and serve diagnostics.

## Diagnostics

`bft_diagnostics()` now reports:

- `validator_signing_enabled`
- `observer_mode`
- `signing_block_reason`
- `last_shutdown_clean`

This makes operator posture visible before a validator resumes signing.
