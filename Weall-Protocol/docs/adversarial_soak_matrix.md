# Adversarial Soak Matrix

This batch extends the local BFT soak harness so operators and CI can exercise the highest-risk liveness and safety transitions identified in the production-readiness audit.

## Covered fault classes

- temporary validator partition with delayed heal
- child-before-parent proposal delivery
- validator restart from persisted SQLite state
- validator epoch bump during an active run
- stale QC replay after an epoch transition

## CLI example

```bash
PYTHONPATH=src python scripts/bft_fault_injection_soak.py \
  --work-dir /tmp/weall-bft-soak \
  --rounds 12 \
  --partition-rounds 3,4 \
  --delay-child-first-every 3 \
  --restart-every 4 \
  --epoch-bump-rounds 5,9 \
  --stale-qc-replay-target v2 \
  --chain-id weall-adversarial-soak
```

## Output signals to watch

- `converged`: all followers ended on the same finalized tip as the leader
- `restart_events`: how many node restarts were injected
- `epoch_bump_events`: how many validator epoch transitions were injected
- `stale_qc_replay_attempts`: how many stale QCs were replayed after an epoch bump
- `stale_qc_replay_rejections`: how many of those stale QCs were rejected

A passing run should converge and reject every replayed stale QC.
