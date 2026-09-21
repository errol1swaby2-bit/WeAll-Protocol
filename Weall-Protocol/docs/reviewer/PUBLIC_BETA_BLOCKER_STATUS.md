# Public Beta Blocker Status

Current allowed claim: **WeAll is a pre-public-testnet protocol implementation under active hardening, with local/devnet/public-observer-oriented evidence present and public beta readiness still blocked by explicit external observer, replay, validator/operator, storage, legal, upgrade-execution, and helper-topology gates. Independent cryptographic review remains a separate launch gate.**

This document preserves blocker truth for reviewer use. It must not be used to imply public beta, public mainnet, public validator, public multi-validator BFT, live-economics, automatic-upgrade, production-helper, legal-approval, or public storage-market readiness.

## Current status

| Field | Current value |
|---|---|
| `public_beta_ready` | `false` |
| Mutable blocker counts | Read directly from `generated/public_beta_blocker_report_v1_5.json`; this document intentionally does not duplicate them. |
| Current tx canon checkpoint | Read directly from `generated/tx_index.json`; this document intentionally does not duplicate mutable canon totals or version values. |

Do not hide or soften the authoritative generated values. Entries closed in the repository show repository progress; open entries remain real readiness blockers.

## Canonical sources

- `generated/public_beta_blocker_report_v1_5.json`
- `generated/final_public_observer_controlled_testnet_go_gate_v1_5.json`
- `generated/release_evidence_manifest_v1_5.json`
- `docs/reviewer/CURRENT_READINESS_STATEMENT.md`
- `docs/reviewer/EVIDENCE_INDEX.md`
- `docs/audits/public_observer_testnet_readiness_plan_v1_5.md`
- `docs/reviewer/CURRENT_TESTNET_READINESS_STATEMENT.md`

## Closed in repository

Entries marked closed in the canonical blocker report are closed only by repository artifacts, tests, docs, or source gates. They do not close missing external evidence gates.

Read the canonical blocker report for the current closed-entry count and IDs.

## Remaining open blockers

| Blocker | Severity | Current status | Remaining evidence |
|---|---:|---|---|
| `AUD-618-P0-001` | P0 | External evidence required | Independent controlled validator/operator transcript. |
| `AUD-618-P0-002` | P0 | External evidence required | Real counsel or controlled legal/compliance attestation. |
| `AUD-618-P0-003` | P0 | Future execution hardening required | Future executable upgrade staging/rollback proof. |
| `AUD-633-P0-004` | P0 | External cryptographic review required | Fresh profile-aware post-transition rehearsal evidence, browser/local signing-boundary review, helper/evidence-signing production gate, and external cryptographic review. |
| `AUD-618-P1-003` | P1 | External evidence required | External/two-machine replay transcript. |
| `AUD-618-P1-004` | P1 | External evidence required | Real storage/IPFS daemon/operator transcript. |
| `AUD-618-P1-005` | P1 | Future topology hardening required | Future production helper topology proof. |
| `AUD-628-P1-001` | P1 | External evidence required | External clean-clone/open-download/state-sync/frontend rendered journey transcript. |

## Canonical testnet readiness tier mapping

| Tier | Label | Meaning |
|---|---|---|
| Tier A | Controlled local reviewer testnet | Same-machine/local evidence for reviewer inspection only. |
| Tier B | Public observer testnet | Requires the external clean-clone/open-download observer evidence plus every blocker that the generated go-gate marks as required before public-observer wording, including the post-transition cryptographic-review gate. |
| Tier C | Controlled validator rehearsal | Can reduce validator evidence risk with invited operators, but it does not claim public validator safety. |
| Tier D | Public validator beta / mainnet hardening | Requires public validator, BFT, storage, helper, upgrade, legal, replay, and cryptographic-review evidence before any broader readiness wording. |

See `docs/audits/public_observer_testnet_readiness_plan_v1_5.md` and `docs/reviewer/CURRENT_TESTNET_READINESS_STATEMENT.md` for the longer tier mapping.

## What can safely be said

The repository can say that it is a pre-public-testnet implementation under active hardening with bounded local/devnet/public-observer-oriented evidence. Controlled-testnet mechanism completion remains NO-GO until production helper state-root/restart equivalence is proven. It can point reviewers to generated artifacts, local gates, and transcript templates.

## What must not be said

Do not claim public beta readiness, public mainnet readiness, public validator safety, public multi-validator BFT readiness, live economics readiness, automatic protocol upgrade readiness, executable migration readiness, rollback execution readiness, production helper execution readiness, completed production cryptographic audit, production post-quantum security, quantum-proof security, legal/compliance approval, public storage-market readiness, complete anti-Sybil/collusion detection, or complete public identity infrastructure.

## Evidence closure rule

Only real evidence closes open blockers. Local scripts can prove that templates and checks exist; they cannot self-certify external operator runs, counsel/control review, cross-machine replay, real storage/IPFS operation, public observer open-download behavior, production helper topology, executable upgrade/rollback behavior, or independent cryptographic review.

## Strict external evidence boundary

For blocker IDs `AUD-618-P0-001`, `AUD-618-P1-003`, and related external transcript blockers, only external evidence can close the blocker. Local scripts, local generated artifacts, proof templates, or founder-operated rehearsals are not enough to close those blockers.

For `AUD-618-P1-004`, real storage/IPFS operator evidence must pass strict-release validation before the storage/IPFS blocker can be closed. Template files and local simulations do not close the blocker.
