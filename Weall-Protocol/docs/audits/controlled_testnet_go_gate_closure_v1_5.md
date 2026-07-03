# Controlled Testnet Go-Gate Closure Audit v1.5

This audit explains why the v1.5 public-readiness artifact checker previously reported remaining blockers even after the repository had enough bounded evidence to run a controlled testnet go-gate. The goal is not to claim public beta or mainnet readiness. The goal is to make the repository truthful about the narrower state: controlled-testnet go-gate evidence is ready to run while public beta blockers remain visible.

## Verdict

The controlled-testnet go-gate may be marked **ready to run** when all deterministic in-repository mechanism artifacts, public-only safety artifacts, launch-matrix guardrails, transcript schemas, and reviewer runbooks are present and fresh.

That does **not** mean:

- public beta readiness;
- public mainnet readiness;
- public multi-validator BFT readiness;
- live economics readiness;
- production helper execution readiness;
- automatic protocol-upgrade software apply readiness;
- legal/compliance readiness.

The current safe claim is:

> WeAll has a controlled-testnet go-gate manifest that is ready to run, with public beta and mainnet claims still blocked by explicit external evidence, legal, UX, operator, and hardening gates.

## Why the checker was still failing

The failure was caused by evidence semantics, not by a newly discovered consensus flaw.

Several generated artifacts used `ok=false` to mean “public beta blockers remain.” That made downstream controlled-testnet checks fail even though those artifacts were correctly refusing to claim public beta readiness. This created an impossible condition: the repository had to keep public-beta blockers open, but the controlled-testnet go-gate treated open blockers as a failed manifest.

This audit separates three states:

1. **artifact inventory is current** — deterministic evidence files and blocker classifications are fresh;
2. **controlled-testnet go-gate is ready to run** — local/static/rehearsal gates are present and high-risk features remain blocked;
3. **public beta is ready** — external operator transcripts, legal/compliance review, rendered/public observer evidence, and production-hardening gates are complete.

Only the first two are allowed by this patch.

## Blocker classification

| ID | Severity | Category | Current disposition |
| --- | --- | --- | --- |
| AUD-618-P0-001 | P0 | external evidence | Keep open. Requires independent validator/operator transcript and adversarial multi-node proof before public beta/mainnet claims. |
| AUD-618-P0-002 | P0 | external evidence/legal | Keep open. Requires counsel/control attestation before public token/economic/governance claims. |
| AUD-618-P0-003 | P0 | mainnet hardening | Keep open. Protocol upgrades are public record-only and scheduled by block height; automatic artifact apply/migration/rollback remains disabled. |
| AUD-618-P1-001 | P1 | closed artifact gate | Closed by expanded API response vector evidence. |
| AUD-618-P1-002 | P1 | closed artifact gate | Closed by launch-disabled/frontend/API blocker evidence. |
| AUD-618-P1-003 | P1 | external evidence | Keep open. State-root vectors exist, but external cross-machine attestation remains required. |
| AUD-618-P1-004 | P1 | external operator evidence | Keep open. Storage/IPFS durability proof remains simulated/local until real daemon/operator transcript. |
| AUD-618-P1-005 | P1 | mainnet hardening | Keep open. Production helper execution remains disabled pending production-topology proof. |
| AUD-618-P1-006 | P1 | closed release-evidence gate | Closed by tracked release-evidence manifest and clean-clone gate wiring. |
| AUD-628-P1-001 | P1 | external observer evidence | Keep open. Public observer launch still needs open-download/state-sync/rendered journey transcript. |
| AUD-618-P2-001 | P2 | UX follow-up | Safe to reduce with bounded frontend/docs/tests; not enough to claim public beta. |
| AUD-618-P2-002 | P2 | UX follow-up | Safe to reduce with bounded tx propagation lifecycle surface; not enough to claim public beta. |
| AUD-618-P2-003 | P2 | observability follow-up | Partially reduced by status surfaces; incident timeline can be improved later. |
| AUD-618-P3-001 | P3 | closed docs gate | Closed by node-mode quickstart documentation. |

## Safe closures before NLnet first-round review

The safe closures are the documentation/artifact truth-boundary corrections only:

- classify all blocker rows in `generated/public_beta_blocker_report_v1_5.json`;
- keep public beta readiness false while making the blocker report itself release-safe;
- include public-only and provider-independence artifacts in the release-evidence manifest;
- make the controlled-testnet go-gate ready to run only when high-risk launch-matrix features stay disabled;
- expose the protocol-upgrade lifecycle as public, record-only, block-height scheduled metadata in the testnet capability surface and frontend dashboard.

## Gates that must remain open

These blockers should not be closed before NLnet first-round selection unless new external evidence exists:

- independent validator/operator transcript;
- storage/IPFS real daemon/operator transcript;
- external public observer clean-clone/open-download transcript;
- rendered frontend operator journey from a fresh checkout;
- legal/compliance counsel/control attestation;
- production helper execution proof;
- automatic protocol-upgrade apply/migration/rollback proof;
- public multi-validator BFT proof;
- live economics activation proof.

These are good candidates for funded mainnet-readiness hardening, not blockers to hide.

## Protocol upgrade reviewer surface

The public testnet capability endpoint now reports a reviewer-facing protocol-upgrade lifecycle summary:

- declaration transaction: `PROTOCOL_UPGRADE_DECLARE`;
- scheduled activation transaction: `PROTOCOL_UPGRADE_ACTIVATE`;
- activation clock: block height;
- active behavior: public record-only metadata;
- disabled behavior: automatic software apply, migration execution, rollback execution, economics activation.

The frontend node dashboard renders this as “Public record-only, block-height scheduled” when the node reports the record-only lifecycle boundary.

## Performance evidence status

The repository contains the block-schedule survivability harness and reviewer wording that allows a local 2350 TPS claim only when matching evidence exists for the submitted commit. This audit did not locate tracked, commit-bound 2350 TPS evidence in the generated release artifacts.

Allowed wording remains:

> Local sustained-load testing reached approximately 2350 TPS under the documented test harness.

Use that wording only when the matching `rehearsal-evidence/` JSON or transcript is captured for the submitted commit and attached outside ignored local output.

Forbidden wording remains:

> WeAll is globally ready for 2350 TPS.

> WeAll is mainnet-scale.

## Required verification commands

```bash
PYTHONPATH=src python scripts/check_v15_public_readiness_artifacts.py
PYTHONPATH=src:scripts python scripts/run_controlled_testnet_go_gate_v1_5.py --check
PYTHONPATH=src python -m pytest -q \
  tests/test_controlled_testnet_go_gate.py \
  tests/prod/test_public_beta_evidence_gates.py \
  tests/test_testnet_mechanism_coverage.py \
  tests/test_protocol_upgrade_height_scheduled_lifecycle.py \
  tests/test_public_only_protocol_redesign.py
```

## Remaining truthful claim boundary

After this audit, the repository may say:

> Controlled-testnet go-gate manifest is ready to run, and public beta/mainnet readiness remains blocked by explicit external-evidence and hardening gates.

It must not say:

> Public beta is ready.

> Public mainnet is ready.

> Public multi-validator BFT is complete.

> Live economics are active.

> Automatic protocol upgrades execute.
