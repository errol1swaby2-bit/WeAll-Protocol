# Constitutional Clock

WeAll testnet procedure uses finalized block height as the constitutional clock.

The manifest-pinned target is 20 seconds per block:

- `constitutional_clock.enabled: true`
- `target_block_interval_ms: 20000`
- `empty_blocks_enabled: true`
- `procedure_time_source: finalized_block_height`
- `block_time_derivation: genesis_time_plus_height_times_interval`
- `no_fast_forward: true`
- `no_height_skip: true`

The authoritative procedural rule is block-height based:

```text
deadline_height = start_height + window_blocks
current_procedure_height >= deadline_height
```

Frontend countdowns are only estimates derived from block height and the manifest-pinned interval. Browser time, API server time, and local node wall-clock time do not open voting, close appeals, or finalize outcomes.

In constitutional-clock profiles, authorized producers create heartbeat blocks so proposal and dispute windows continue to progress even when there are no user transactions. Observer nodes follow committed/finalized height and must not produce or sign heartbeat blocks.

Blocks may be late because decentralized networks have latency and downtime. Blocks must not skip heights or fast-forward through missed time. A missed interval delays the chain; it does not erase deliberation or appeal rights.
