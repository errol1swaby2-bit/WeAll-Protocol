# Current testnet readiness statement

Status: bounded public observer / controlled testnet launch-candidate framing.

This is the canonical reviewer-facing statement for the current repository. It
must be read together with:

- `generated/public_beta_blocker_report_v1_5.json`;
- `generated/controlled_testnet_go_gate_v1_5.json`;
- `docs/reviewer/PUBLIC_BETA_BLOCKER_STATUS.md`;
- `docs/audits/public_observer_testnet_readiness_plan_v1_5.md`.

## Current allowed claim

WeAll is a controlled-testnet candidate with a conservative public-beta blocker
inventory. The repository evidence supports continued bounded public observer /
controlled-testnet launch preparation, provided public beta remains unclaimed
until the seven still-open external evidence and mainnet-hardening gates are
satisfied.

If the external public observer transcript has not been captured yet, the
strongest allowed claim is:

> Ready for controlled internal/public-observer rehearsal candidate, with public
> beta readiness still blocked by explicit external evidence gates.

## Current blocker count semantics

| Field | Current value | Meaning |
| --- | ---: | --- |
| `blocker_catalog_count` / `blocker_count` | 14 | Full blocker catalog preserved for continuity. |
| `closed_in_repository_count` | 7 | Entries closed by tracked repository artifacts, docs, generated gates, or source-level UX evidence. |
| `remaining_blocker_count` | 7 | Entries still blocking public beta claims. |
| `remaining_external_evidence_required_count` | 7 | Open blockers that require independent transcripts, real-operator proof, counsel attestation, or future hardening evidence. |
| `p0_open_count` | 3 | Still-open P0 blockers. |
| `p1_open_count` | 4 | Still-open P1 blockers. |
| `p2_open_count` | 0 | No open P2 blockers. |
| `p3_open_count` | 0 | No open P3 blockers. |

`public_beta_ready` must remain `false` while any still-open blocker remains.

## Readiness tier summary

- Tier A — controlled local reviewer testnet: repository hygiene, deterministic
  artifact checks, public-only/economics-off boundaries, and local reviewer
  flows.
- Tier B — public observer testnet: external open-download observer transcript,
  state sync, frontend rendered journey, and honest transaction lifecycle.
- Tier C — controlled validator rehearsal: invited operator/validator-candidate
  rehearsal with authority boundaries fail-closed.
- Tier D — public validator beta / mainnet hardening: counsel attestation,
  public BFT/operator proof, executable upgrade proof, real storage proof,
  production helper proof, and public network hardening.

## Remaining blockers by tier

| Blocker | Required tier/evidence |
| --- | --- |
| `AUD-628-P1-001` | Tier B external public observer open-download/state-sync/rendered journey transcript. |
| `AUD-618-P1-003` | Tier B or later external/two-machine replay transcript proving identical state roots and tx index hash. |
| `AUD-618-P0-001` | Tier C rehearsal can reduce; Tier D/public validator evidence needed before public validator safety claims. |
| `AUD-618-P0-002` | Tier D counsel attestation. |
| `AUD-618-P0-003` | Tier D executable protocol upgrade staging/rollback proof. |
| `AUD-618-P1-004` | Tier D real storage/IPFS operator transcript. |
| `AUD-618-P1-005` | Tier D production helper topology enablement proof. |

## What is currently unclaimed

The repository must not claim:

- public beta readiness;
- public mainnet readiness;
- public multi-validator BFT readiness;
- public validator safety;
- live economics readiness;
- automatic software upgrade readiness;
- executable migration/rollback readiness;
- production helper execution readiness;
- legal/compliance approval;
- public storage-market readiness;
- complete anti-Sybil/collusion detection;
- complete public identity infrastructure.

## Next recommended evidence pass

Next pass: capture or prepare `AUD-628-P1-001`, the external public observer
open-download transcript.

The exact checklist is maintained in
`docs/audits/public_observer_testnet_readiness_plan_v1_5.md` under “Canonical
next external transcript.” A founder-run local rehearsal can improve the script
or documentation, but it must not close the external blocker.

## Verification

```bash
cd ~/WeAll-Protocol/Weall-Protocol
source .venv/bin/activate

PYTHONPATH=src python -m pytest -q tests/prod/test_public_observer_testnet_readiness_docs.py
PYTHONPATH=src python scripts/check_v15_public_readiness_artifacts.py
PYTHONPATH=src python scripts/check_release_hygiene_v1_5.py
```
