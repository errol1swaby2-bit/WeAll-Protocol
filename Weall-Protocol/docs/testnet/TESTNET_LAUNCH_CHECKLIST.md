# Testnet Launch Checklist

Use this checklist before any bounded testnet communication. It preserves the current conservative status after Passes 10–27.

Current allowed claim: **WeAll is ready for controlled internal/public-observer rehearsal candidate, with public beta readiness still blocked by explicit external evidence, counsel-review, upgrade-execution, storage, validator, replay, observer, and helper-topology gates.**

## Go / No-Go summary

GO: controlled internal/public-observer rehearsal candidate.

NO-GO: public beta readiness, public observer launch claim while `AUD-628-P1-001` remains open, public mainnet readiness, public validator safety, public multi-validator BFT readiness, live economics readiness, automatic protocol upgrade readiness, executable migration/rollback readiness, production helper execution readiness, legal/compliance approval, and public storage-market readiness.

Current tx canon checkpoint: **236 tx types, version 1.25.0**.

## Repository-side checks

```bash
cd ~/WeAll-Protocol/Weall-Protocol
source .venv/bin/activate

PYTHONPATH=src python -m compileall -q src/weall
bash scripts/secret_guard.sh
PYTHONPATH=src:scripts python scripts/gen_final_public_observer_controlled_testnet_go_gate_v1_5.py --check
PYTHONPATH=src:scripts python scripts/gen_public_beta_blocker_report_v1_5.py --check
PYTHONPATH=src:scripts python scripts/gen_release_evidence_manifest_v1_5.py --check
PYTHONPATH=src python scripts/check_v15_public_readiness_artifacts.py
PYTHONPATH=src python scripts/check_reviewer_truth_boundaries.py
PYTHONPATH=src python scripts/check_release_hygiene_v1_5.py
PYTHONPATH=src python -m pytest -q tests/prod/test_final_public_observer_controlled_testnet_go_gate.py
```

Expected blocker boundary: `public_beta_ready=false`; `blocker_catalog_count=14`; `closed_in_repository_count=7`; `remaining_blocker_count=7`; `p0_open_count=3`; `p1_open_count=4`.

## Documentation truth checks

```bash
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

## Frontend checks

```bash
cd ~/WeAll-Protocol/web
npm run typecheck
npm run build
node scripts/test_first_run_tester_journey_source.mjs
node scripts/test_transaction_lifecycle_rendered_evidence_source.mjs
node scripts/test_node_operator_journey_incident_response_source.mjs
node scripts/test_rendered_civic_loop_source.mjs
```

Frontend checks support rendered journey evidence. They do not make frontend state protocol authority.

## Public observer boot rehearsal

```bash
cd ~/WeAll-Protocol/Weall-Protocol
source .venv/bin/activate
WEALL_PUBLIC_TESTNET=1 bash scripts/boot_public_observer_testnet.sh
```

Capture the command output and status endpoints listed in `docs/testnet/PUBLIC_OBSERVER_QUICKSTART.md` if preparing an external observer transcript.

## External evidence still required before public beta or public observer launch claims

- `AUD-628-P1-001`: external public observer open-download/state-sync/frontend rendered journey transcript.
- `AUD-618-P1-003`: external cross-machine replay transcript.
- `AUD-618-P1-004`: real storage/IPFS daemon/operator transcript.
- `AUD-618-P0-001`: independent controlled validator/operator transcript.
- `AUD-618-P0-002`: real counsel/control legal/compliance attestation.
- `AUD-618-P0-003`: future executable upgrade staging/rollback proof.
- `AUD-618-P1-005`: future production helper topology proof.

## Evidence package map

| Evidence | Path |
|---|---|
| Readiness statement | `docs/reviewer/CURRENT_READINESS_STATEMENT.md` |
| Evidence index | `docs/reviewer/EVIDENCE_INDEX.md` |
| Public beta blocker status | `docs/reviewer/PUBLIC_BETA_BLOCKER_STATUS.md` |
| Final go-gate doc | `docs/testnet/FINAL_PUBLIC_OBSERVER_CONTROLLED_TESTNET_GO_GATE.md` |
| Public observer quickstart | `docs/testnet/PUBLIC_OBSERVER_QUICKSTART.md` |
| Public beta blocker report | `generated/public_beta_blocker_report_v1_5.json` |
| Release evidence manifest | `generated/release_evidence_manifest_v1_5.json` |
| Final go-gate artifact | `generated/final_public_observer_controlled_testnet_go_gate_v1_5.json` |
| External proof templates | `docs/proofs/` |

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

## Final communication rule

Allowed wording: “Ready for controlled internal/public-observer rehearsal candidate, with public beta readiness still blocked by explicit external evidence, counsel-review, upgrade-execution, storage, validator, replay, observer, and helper-topology gates.”

Forbidden wording: “public beta ready”, “mainnet ready”, “public validator safe”, “public multi-validator BFT ready”, “live economics ready”, “automatic upgrades ready”, “legal/compliance approved”, “production helper ready”, or “public storage-market ready”.
