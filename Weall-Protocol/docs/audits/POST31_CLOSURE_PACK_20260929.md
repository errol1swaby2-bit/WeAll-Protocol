# Post-PR31 Closure Pack

Base commit: `9913952a6f4e2babe51eea794a143a70dd443866`

This pack closes the three new findings identified by the recursive audit performed after PR #31 merged. It is intentionally limited to code defects; external-evidence/public-beta release blockers remain separate.

## POST31-001 — mandatory SYSTEM completeness

Follower replay now requires exact equality between the independently reconstructed mandatory pre-SYSTEM queue-ID sequence and the received pre-phase prefix. A user transaction, empty queue ID, unknown queue ID, omission, duplication, or reordering cannot satisfy that prefix boundary. Existing post-phase queue-binding and completeness checks remain in their established rejection order. Rejected candidates do not mutate the committed follower state.

Regression: `test_post31_001_user_replacement_cannot_satisfy_required_pre_system_prefix`.

## POST31-002 — mandatory SYSTEM capacity priority

Candidate construction now treats deterministic post-phase SYSTEM work as higher priority than optional mempool utilization. If post work makes a candidate exceed the hard block transaction cap, the builder deterministically rebuilds from the same committed pre-state with a reduced canonical mempool prefix. Mandatory SYSTEM work alone exceeding the cap still fails closed.

Regression: `test_post31_002_mandatory_post_system_work_trims_user_tail_instead_of_rejecting_block`.

## POST31-003 — runtime posture split-brain

Account-ID policy, public state-route policy, and the direct API entrypoint now share `weall.runtime.protocol_profile.runtime_mode()`. With no explicit mode and no unsafe-dev override, all three resolve to production. `WEALL_UNSAFE_DEV=1` remains the explicit compatibility path to testnet posture when `WEALL_MODE` is absent.

Regressions: `test_post31_003_unset_mode_has_one_fail_safe_production_posture` and `test_post31_003_unsafe_dev_override_is_shared_by_all_mode_consumers`.

## Validation

Focused closure suite:

```text
............                                                             [100%]
12 passed in 2.99s
```

Full backend suite:

```text
........................................................................ [ 92%]
........................................................................ [ 93%]
........................................................................ [ 95%]
....................................................................s... [ 96%]
........................................................................ [ 98%]
........................................................................ [ 99%]
.....                                                                    [100%]
4612 passed, 1 skipped in 429.31s (0:07:09)
```

The builder also ran generated-artifact, v2 derivative, v1.5 public-readiness, public-claim freshness, and current-verified-claims checks before creating this pack. Exact file SHA-256 values and toolchain versions are recorded in `artifacts/post31-closure/manifest.json`.
