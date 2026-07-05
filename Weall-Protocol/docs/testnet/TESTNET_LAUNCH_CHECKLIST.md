# Testnet Launch Checklist

Use this checklist before any bounded testnet communication.

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
PYTHONPATH=src python scripts/check_release_hygiene_v1_5.py
PYTHONPATH=src python -m pytest -q tests/prod/test_final_public_observer_controlled_testnet_go_gate.py
```

## Frontend checks

```bash
cd ~/WeAll-Protocol/web
npm run typecheck
npm run build
node scripts/test_first_run_tester_journey_source.mjs
node scripts/test_transaction_lifecycle_rendered_evidence_source.mjs
node scripts/test_node_operator_journey_incident_response_source.mjs
```

## External evidence still required before public beta or public observer launch claims

- `AUD-628-P1-001`: external public observer open-download/state-sync/frontend rendered journey transcript.
- `AUD-618-P1-003`: external cross-machine replay transcript.
- `AUD-618-P1-004`: real storage/IPFS daemon/operator transcript.
- `AUD-618-P0-001`: independent controlled validator/operator transcript.
- `AUD-618-P0-002`: real counsel/control legal/compliance attestation.
- `AUD-618-P0-003`: future executable upgrade staging/rollback proof.
- `AUD-618-P1-005`: future production helper topology proof.

## Final communication rule

Allowed wording: "Ready for controlled internal/public-observer rehearsal candidate, with public beta readiness still blocked by explicit external evidence gates."

Forbidden wording: "public beta ready", "mainnet ready", "public validator safe", "public multi-validator BFT ready", "live economics ready", "automatic upgrades ready", "legal/compliance approved", "production helper ready", or "public storage market ready".

## Go/no-go summary

GO: controlled internal/public-observer rehearsal candidate.

NO-GO: public beta readiness, public mainnet readiness, public validator safety, live economics readiness, automatic protocol upgrade readiness, production helper execution readiness, legal/compliance approval, and public storage-market readiness.
