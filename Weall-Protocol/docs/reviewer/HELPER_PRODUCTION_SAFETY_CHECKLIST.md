# Helper production safety checklist

Status: **helper execution is gated/experimental and production helper execution remains disabled**.

Helpers may accelerate execution only after they prove they do not change consensus results. Helpers do not replace consensus, validator signatures, block admission, deterministic replay, or state-root verification.

## Required safety topics before production enablement

| Topic | Required reviewer evidence | Current posture |
|---|---|---|
| Deterministic assignment | Helper selection depends only on canonical inputs such as validator set, lane id, block context, and plan id. | Future hardening evidence required. |
| Lane partitioning | Every node maps transactions to the same conflict lanes. | Covered by lane/conflict tests, not a production topology claim. |
| Canonical ordering | Transactions are ordered deterministically before helper execution. | Covered by deterministic block/lane tests, still gated. |
| Deterministic receipts | Helper receipts are canonical, domain separated, and context-bound. | Runtime checks exist; production topology proof remains open. |
| Merge behavior | Lane outputs merge in canonical reproducible order. | Merge admission tests exist; public production enablement remains false. |
| Crash safety | Restarting a node reproduces helper planning/results or safely falls back. | Restart equivalence tests exist; multi-node external proof remains open. |
| Byzantine/malformed result rejection | Malformed, mismatched, duplicate, stale, or malicious helper outputs are rejected deterministically. | Adversarial tests exist; public production claim remains false. |
| Serial equivalence | Helper execution must match serial execution results for supported tx families. | Corpus exists but must expand before enablement. |
| Helper execution root binding | Helper metadata and roots bind to block context and are replay-checked. | Root-binding tests exist; still gated. |
| Replay behavior | Leader/follower/observer replay must produce identical roots with helper metadata present. | Local tests exist; external/multi-node proof remains open. |
| Fail-closed invalid metadata | Invalid helper metadata must reject/fall back deterministically rather than continue unsafely. | Runtime/tests support fail-closed posture; production topology disabled. |

## Targeted test command

```bash
cd Weall-Protocol
PYTHONPATH=src python -m pytest -q \
  tests/test_helper_restart_equivalence.py \
  tests/test_helper_replay_guard.py \
  tests/test_helper_replay_guard_plan_binding.py \
  tests/test_helper_replay_merge_adversarial.py \
  tests/test_helper_store_conflict_timeout_recovery.py \
  tests/test_protocol_blocker_safety.py \
  tests/prod/test_production_helper_topology_hardening_plan.py \
  tests/prod/test_helper_production_safety_checklist.py
```

## Explicit non-claims

- Production helper execution is not enabled.
- Helper mode does not grant protocol authority.
- Missing helpers must not halt block production in the current launch posture.
- Local scripts and frontend UI cannot enable helper production mode.
- Public beta/mainnet readiness cannot be inferred from helper-local tests.

The future proof slot remains `docs/proofs/production-helper-topology-hardening/2026-07-05/` and the generated blocker artifact remains `generated/production_helper_topology_hardening_plan_v1_5.json`.
