# Public Beta Blocker Status

Current allowed claim: **WeAll is ready for controlled internal/public-observer rehearsal candidate, with public beta readiness still blocked by explicit external evidence, counsel-review, upgrade-execution, storage, validator, replay, observer, and helper-topology gates.**

This document preserves blocker truth for reviewer use. It must not be used to imply public beta, public mainnet, public validator, public multi-validator BFT, live-economics, automatic-upgrade, production-helper, legal-approval, or public storage-market readiness.

## Current status

| Field | Current value |
|---|---:|
| `public_beta_ready` | `false` |
| `blocker_catalog_count` | 14 |
| `closed_in_repository_count` | 7 |
| `remaining_blocker_count` | 7 |
| `remaining_external_evidence_required_count` | 7 |
| `p0_open_count` | 3 |
| `p1_open_count` | 4 |
| Current tx canon checkpoint | 236 tx types, version 1.25.0 |

Do not hide or soften these values. The closed entries show repository progress; the open entries remain real readiness blockers.

## Canonical sources

- `generated/public_beta_blocker_report_v1_5.json`
- `generated/final_public_observer_controlled_testnet_go_gate_v1_5.json`
- `generated/release_evidence_manifest_v1_5.json`
- `docs/reviewer/CURRENT_READINESS_STATEMENT.md`
- `docs/reviewer/EVIDENCE_INDEX.md`
- `docs/audits/public_observer_testnet_readiness_plan_v1_5.md`
- `docs/reviewer/CURRENT_TESTNET_READINESS_STATEMENT.md`

## Closed in repository

The 7 closed entries are closed only by repository artifacts, tests, docs, or source gates. They do not close missing external evidence gates.

| Count | Meaning |
|---:|---|
| 7 | Closed in repository by generated artifacts, release manifest gates, frontend/source gates, or docs gates. |

## Remaining open blockers

| Blocker | Severity | Current status | Remaining evidence |
|---|---:|---|---|
| `AUD-618-P0-001` | P0 | External evidence required | Independent controlled validator/operator transcript. |
| `AUD-618-P0-002` | P0 | External evidence required | Real counsel or controlled legal/compliance attestation. |
| `AUD-618-P0-003` | P0 | Future execution hardening required | Future executable upgrade staging/rollback proof. |
| `AUD-618-P1-003` | P1 | External evidence required | External/two-machine replay transcript. |
| `AUD-618-P1-004` | P1 | External evidence required | Real storage/IPFS daemon/operator transcript. |
| `AUD-618-P1-005` | P1 | Future topology hardening required | Future production helper topology proof. |
| `AUD-628-P1-001` | P1 | External evidence required | External clean-clone/open-download/state-sync/frontend rendered journey transcript. |

## Canonical testnet readiness tier mapping

| Tier | Label | Meaning |
|---|---|---|
| Tier A | Controlled local reviewer testnet | Same-machine/local evidence for reviewer inspection only. |
| Tier B | Public observer testnet | Requires only an external clean-clone/open-download observer transcript before public observer launch wording can be considered. |
| Tier C | Controlled validator rehearsal | Can reduce validator evidence risk with invited operators, but it does not claim public validator safety. |
| Tier D | Public validator beta / mainnet hardening | Requires public validator, BFT, storage, helper, upgrade, legal, and replay evidence before any broader readiness wording. |

See `docs/audits/public_observer_testnet_readiness_plan_v1_5.md` and `docs/reviewer/CURRENT_TESTNET_READINESS_STATEMENT.md` for the longer tier mapping.

## What can safely be said

The repository can say that it is a controlled internal/public-observer rehearsal candidate with explicit public beta blockers still open. It can point reviewers to generated artifacts, local gates, and transcript templates.

## What must not be said

Do not claim public beta readiness, public mainnet readiness, public validator safety, public multi-validator BFT readiness, live economics readiness, automatic protocol upgrade readiness, executable migration readiness, rollback execution readiness, production helper execution readiness, legal/compliance approval, public storage-market readiness, complete anti-Sybil/collusion detection, or complete public identity infrastructure.

## Evidence closure rule

Only real evidence closes open blockers. Local scripts can prove that templates and checks exist; they cannot self-certify external operator runs, counsel/control review, cross-machine replay, real storage/IPFS operation, public observer open-download behavior, production helper topology, or executable upgrade/rollback behavior.

## Strict external evidence boundary

For blocker IDs `AUD-618-P0-001`, `AUD-618-P1-003`, and related external transcript blockers, only external evidence can close the blocker. Local scripts, local generated artifacts, proof templates, or founder-operated rehearsals are not enough to close those blockers.

For `AUD-618-P1-004`, real storage/IPFS operator evidence must pass strict-release validation before the storage/IPFS blocker can be closed. Template files and local simulations do not close the blocker.
