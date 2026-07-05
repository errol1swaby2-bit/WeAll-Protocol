# WeAll Release / Reviewer Checklist

This checklist is for reviewer-facing documentation and bounded rehearsal preparation after Passes 10–27. It does not escalate readiness claims.

Current allowed claim: **WeAll is ready for controlled internal/public-observer rehearsal candidate, with public beta readiness still blocked by explicit external evidence, counsel-review, upgrade-execution, storage, validator, replay, observer, and helper-topology gates.**

## Current status

| Claim area | Status | Required boundary |
|---|---:|---|
| Controlled internal/public-observer rehearsal candidate | GO | May be used only with the blocker caveat above. |
| Public beta readiness | NO-GO | `public_beta_ready=false` must remain visible. |
| Public observer launch claim | NO-GO | External open-download observer transcript is still required. |
| Public mainnet readiness | NO-GO | Mainnet hardening remains future work. |
| Public validator / public multi-validator BFT readiness | NO-GO | Independent validator/operator transcript remains required. |
| Live economics | NO-GO | Economics remain locked; no live fees/transfers/rewards/slashing claim. |
| Automatic upgrades | NO-GO | Upgrade execution, migration execution, and rollback execution are disabled. |
| Production helper execution | NO-GO | Helper topology remains a hardening gate. |
| Legal/compliance approval | NO-GO | Counsel/control review remains open. |
| Public storage-market readiness | NO-GO | Real operator storage/IPFS evidence remains required. |

Current tx canon checkpoint: **236 tx types, version 1.25.0**.

## Required repository checks

Run from the backend directory:

```bash
cd ~/WeAll-Protocol/Weall-Protocol
source .venv/bin/activate

PYTHONPATH=src:scripts python scripts/gen_public_beta_blocker_report_v1_5.py --check
PYTHONPATH=src python scripts/gen_release_evidence_manifest_v1_5.py --check
PYTHONPATH=src python scripts/check_v15_public_readiness_artifacts.py
PYTHONPATH=src python scripts/check_reviewer_truth_boundaries.py
PYTHONPATH=src python -m pytest -q \
  tests/test_release_docs_truth_sync.py \
  tests/test_reviewer_language_cleanup.py \
  tests/prod/test_final_public_observer_controlled_testnet_go_gate.py \
  tests/prod/test_public_beta_evidence_gates.py \
  tests/prod/test_public_observer_testnet_readiness_docs.py \
  tests/test_public_readiness_artifacts_v15.py
```

If README or reviewer docs changed in the reviewed commit, also run:

```bash
PYTHONPATH=src python scripts/check_release_hygiene_v1_5.py
```

For the complete local backend safety sweep when time allows:

```bash
PYTHONPATH=src python -m compileall -q src/weall
bash scripts/secret_guard.sh
PYTHONPATH=src:scripts python scripts/gen_final_public_observer_controlled_testnet_go_gate_v1_5.py --check
PYTHONPATH=src:scripts python scripts/gen_public_beta_blocker_report_v1_5.py --check
PYTHONPATH=src:scripts python scripts/gen_release_evidence_manifest_v1_5.py --check
PYTHONPATH=src python scripts/check_v15_public_readiness_artifacts.py
PYTHONPATH=src python scripts/check_release_hygiene_v1_5.py
```

## Frontend reviewer checks

Run from the frontend directory before any rendered-journey claim:

```bash
cd ~/WeAll-Protocol/web
npm run typecheck
npm run build
node scripts/test_first_run_tester_journey_source.mjs
node scripts/test_transaction_lifecycle_rendered_evidence_source.mjs
node scripts/test_node_operator_journey_incident_response_source.mjs
node scripts/test_rendered_civic_loop_source.mjs
```

Frontend checks prove rendering/source-contract behavior only. They do not override backend artifacts and they do not close external evidence blockers by themselves.

## Evidence package map

| Package | Path | Must remain true |
|---|---|---|
| Current readiness statement | `Weall-Protocol/docs/reviewer/CURRENT_READINESS_STATEMENT.md` | The allowed claim is bounded and public beta remains blocked. |
| Evidence index | `Weall-Protocol/docs/reviewer/EVIDENCE_INDEX.md` | Implemented evidence, generated artifacts, local gates, external evidence, and future hardening are separated. |
| Public beta blocker status | `Weall-Protocol/docs/reviewer/PUBLIC_BETA_BLOCKER_STATUS.md` | 14 blockers visible; 7 closed in repo; 7 open. |
| Final go-gate doc | `Weall-Protocol/docs/testnet/FINAL_PUBLIC_OBSERVER_CONTROLLED_TESTNET_GO_GATE.md` | GO only for controlled internal/public-observer rehearsal candidate. |
| Public observer quickstart | `Weall-Protocol/docs/testnet/PUBLIC_OBSERVER_QUICKSTART.md` | Boot steps are transcript collection steps, not public-readiness authority. |
| Testnet launch checklist | `Weall-Protocol/docs/testnet/TESTNET_LAUNCH_CHECKLIST.md` | Launch wording remains conservative. |
| Production posture | `Weall-Protocol/docs/PRODUCTION_POSTURE.md` | Fail-closed and disabled surfaces remain explicit. |
| Versioning strategy | `Weall-Protocol/docs/PROTOCOL_VERSIONING_STRATEGY.md` | Tx canon and upgrade record-only boundaries remain current. |
| Generated blocker report | `Weall-Protocol/generated/public_beta_blocker_report_v1_5.json` | `public_beta_ready=false`; `blocker_catalog_count=14`; `closed_in_repository_count=7`; `remaining_blocker_count=7`. |
| Release evidence manifest | `Weall-Protocol/generated/release_evidence_manifest_v1_5.json` | Claim boundaries remain false for public beta, mainnet, live economics, public validator, automatic upgrades, production helpers, and storage-market readiness. |
| Proof templates | `Weall-Protocol/docs/proofs/` | External transcript templates remain available and unfilled unless real evidence is attached. |

## Blocker truth that must not be hidden

- Public beta readiness remains false.
- The blocker catalog remains 14 entries.
- 7 entries are closed in repository.
- 7 entries remain open as external evidence or mainnet-hardening gates.
- P0 open count remains 3.
- P1 open count remains 4.
- Local scripts and generated artifacts can prove repository consistency, but they cannot self-certify missing external operator, counsel, storage, replay, helper, observer, or upgrade-execution evidence.

## External evidence still required

| Blocker | Evidence still required |
|---|---|
| `AUD-618-P0-001` | Independent controlled validator/operator transcript. |
| `AUD-618-P0-002` | Real counsel or controlled legal/compliance attestation. |
| `AUD-618-P0-003` | Future executable upgrade staging/rollback proof. |
| `AUD-618-P1-003` | External/two-machine replay transcript. |
| `AUD-618-P1-004` | Real storage/IPFS daemon/operator transcript. |
| `AUD-618-P1-005` | Future production helper topology proof. |
| `AUD-628-P1-001` | External clean-clone/open-download/state-sync/frontend rendered journey transcript. |

## Major protocol surfaces to inspect

- account/profile;
- public social;
- public groups;
- governance;
- disputes/reviews;
- transaction lifecycle;
- node/operator surfaces;
- observer boot;
- external evidence packages.

## Intentionally disabled surfaces

The current release package must continue to say that live economics, fees/transfers/rewards/slashing, public validator/BFT readiness, automatic upgrades, executable migrations/rollbacks, production helper execution, legal approval, and public storage-market readiness are not enabled or not claimed.

## Commit hygiene before publishing a patch

```bash
git status --short
git diff --check
PYTHONPATH=src:scripts python scripts/gen_public_beta_blocker_report_v1_5.py --check
PYTHONPATH=src python scripts/gen_release_evidence_manifest_v1_5.py --check
PYTHONPATH=src python scripts/check_v15_public_readiness_artifacts.py
PYTHONPATH=src python scripts/check_reviewer_truth_boundaries.py
PYTHONPATH=src python scripts/check_release_hygiene_v1_5.py
```

Suggested commit message for this documentation pass:

```text
Refresh reviewer documentation truth boundaries
```
