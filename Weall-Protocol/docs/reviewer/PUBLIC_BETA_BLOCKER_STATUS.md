# Public Beta Blocker Status

This reviewer note explains how to read
`generated/public_beta_blocker_report_v1_5.json` without confusing the full
blocker catalog with the still-open public beta blockers.

## Current count model

| Count | Meaning | Value |
| --- | --- | ---: |
| `blocker_catalog_count` | Full catalog entries preserved for audit continuity. | 14 |
| `blocker_count` | Compatibility alias for `blocker_catalog_count`. | 14 |
| `closed_in_repository_count` | Entries closed by tracked repo artifacts, docs, generated gates, or frontend/source evidence. | 7 |
| `remaining_blocker_count` | Entries still blocking public beta claims. | 7 |
| `remaining_external_evidence_required_count` | Still-open blockers that need external evidence or attestation before public beta. | 7 |
| `p0_open_count` | Still-open P0 blockers. | 3 |
| `p1_open_count` | Still-open P1 blockers. | 4 |
| `p2_open_count` | Still-open P2 blockers. | 0 |
| `p3_open_count` | Still-open P3 blockers. | 0 |

`public_beta_ready` must remain `false` while any of the seven still-open
external evidence or mainnet-hardening gates are unresolved.

## Still-open P0/P1 blocker list

- `AUD-618-P0-001` — independent public validator/operator transcript.
- `AUD-618-P0-002` — legal/compliance counsel attestation.
- `AUD-618-P0-003` — executable protocol upgrade staging/rollback proof. Current repository status is record-only; see `docs/testnet/UPGRADE_EXECUTION_HARDENING_PLAN.md` and `generated/protocol_upgrade_execution_hardening_plan_v1_5.json` for the future hardening checklist.
- `AUD-618-P1-003` — external machine replay transcript.
- `AUD-618-P1-004` — real IPFS/storage operator transcript.
- `AUD-618-P1-005` — production helper topology enablement gate.
- `AUD-628-P1-001` — external public observer open-download/state-sync/rendered journey transcript.

## Closed repository blocker list

- `AUD-618-P1-001` — API response vector expansion gate.
- `AUD-618-P1-002` — frontend/API launch-disabled blocker snapshot.
- `AUD-618-P1-006` — release evidence manifest and clean-clone gate.
- `AUD-618-P2-001` — frontend operator wizard source gate.
- `AUD-618-P2-002` — transaction propagation lifecycle source gate.
- `AUD-618-P2-003` — operator incident timeline source gate.
- `AUD-618-P3-001` — node-mode quickstart docs gate.

## Allowed and forbidden claims

Allowed: WeAll has a current, conservative blocker inventory and remains a
controlled testnet candidate with explicit public-beta evidence gates.

Forbidden: public beta readiness, mainnet readiness, public multi-validator BFT,
live economics, automatic protocol upgrades, production helper execution, legal
clearance, public storage-market readiness, or public validator safety.

## Verification

```bash
cd ~/WeAll-Protocol/Weall-Protocol
source .venv/bin/activate

PYTHONPATH=src:scripts python scripts/gen_public_beta_blocker_report_v1_5.py --check
PYTHONPATH=src python scripts/check_v15_public_readiness_artifacts.py
```

## Canonical testnet readiness tier mapping

The current readiness plan is maintained in
`docs/audits/public_observer_testnet_readiness_plan_v1_5.md` and summarized in
`docs/reviewer/CURRENT_TESTNET_READINESS_STATEMENT.md`.

| Tier | Scope | Blockers/evidence handled |
| --- | --- | --- |
| Tier A | Controlled local reviewer testnet | Local deterministic artifacts, release hygiene, controlled-testnet mechanism gates, source-level UX evidence. |
| Tier B | Public observer testnet | `AUD-628-P1-001` external open-download/state-sync/rendered journey transcript and `AUD-618-P1-003` external replay transcript. |
| Tier C | Controlled validator rehearsal | `AUD-618-P0-001` can be reduced by invited operator rehearsal without claiming public validator safety. |
| Tier D | Public validator beta / mainnet hardening | `AUD-618-P0-002`, `AUD-618-P0-003`, `AUD-618-P1-004`, and `AUD-618-P1-005`; plus any remaining public-validator/storage/helper/economics/legal gates. |

The current external-evidence targets are:

- `AUD-628-P1-001` — external public observer open-download/state-sync/rendered journey transcript.
- `AUD-618-P1-003` — external cross-machine replay transcript proving identical state roots, vectors, and tx-index hash.
- `AUD-618-P1-004` — real storage/IPFS daemon/operator transcript proving publish, pin, retrieval, wrong-CID rejection, corrupt-content rejection, revalidation, and durability evidence.
- `AUD-618-P0-001` — independent controlled validator/operator transcript proving fresh clone, node registration, operator readiness, validator-candidate path, readiness receipt, controlled activation rehearsal, observer bypass rejection, and restart fail-closed evidence.

A local founder-run transcript may improve the runbook, but only external evidence
from the documented commit can close these blockers.

For `AUD-628-P1-001`, only an external clean-clone/open-download state-sync/rendered journey transcript can close the blocker. For `AUD-618-P1-003`, only an external cross-machine replay transcript from the documented commit can close the blocker. For `AUD-618-P1-004`, only a real storage/IPFS daemon/operator transcript with strict-release validation can close the blocker. For `AUD-618-P0-001`, only an invited or independent operator controlled validator transcript with strict-release validation can close the blocker.

## Legal/compliance evidence pack

`AUD-618-P0-002` remains open. The counsel-review preparation pack lives at:

- `docs/legal/COUNSEL_REVIEW_EVIDENCE_PACK.md`;
- `docs/testnet/LEGAL_COMPLIANCE_EVIDENCE_PACK.md`;
- `docs/proofs/legal-compliance-counsel/2026-07-05/ATTESTATION_TEMPLATE.json`.

These files are non-lawyer drafts and templates only. They do not provide legal
advice, do not mark WeAll legally approved, and do not close the blocker. Closure
requires a real counsel or controlled external attestation for the exact commit
that passes strict-release validation:

```bash
PYTHONPATH=src:scripts python scripts/validate_external_operator_transcript_v1_5.py \
  --kind legal_compliance_attestation \
  --strict-release \
  --path <attestation.json>
```
