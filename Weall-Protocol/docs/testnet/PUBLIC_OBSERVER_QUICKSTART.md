# Public Observer Quickstart

Current allowed claim: **WeAll is ready for controlled internal/public-observer rehearsal candidate, with public beta readiness still blocked by explicit external evidence, counsel-review, upgrade-execution, storage, validator, replay, observer, and helper-topology gates.**

This quickstart is for bounded observer rehearsal and transcript collection. It is not a public beta, public mainnet, public validator, public multi-validator BFT, live-economics, automatic-upgrade, production-helper, legal-approval, or public storage-market readiness claim.

## Go / No-Go boundary

GO: controlled internal/public-observer rehearsal candidate.

NO-GO: public beta readiness, public mainnet readiness, public validator safety, public multi-validator BFT readiness, live economics readiness, automatic protocol upgrade readiness, executable migration/rollback readiness, production helper execution readiness, legal/compliance approval, and public storage-market readiness.

Current tx canon checkpoint: **236 tx types, version 1.25.0**.

## 1. Clone and enter backend

```bash
git clone <repo-url> WeAll-Protocol
cd WeAll-Protocol/Weall-Protocol
```

Use the exact commit under review. Capture `git rev-parse HEAD` in any external transcript.

## 2. Create environment

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.lock
pip install -e .
```

## 3. Verify repository truth boundaries

```bash
PYTHONPATH=src:scripts python scripts/gen_final_public_observer_controlled_testnet_go_gate_v1_5.py --check
PYTHONPATH=src:scripts python scripts/gen_public_beta_blocker_report_v1_5.py --check
PYTHONPATH=src python scripts/gen_release_evidence_manifest_v1_5.py --check
PYTHONPATH=src python scripts/check_v15_public_readiness_artifacts.py
PYTHONPATH=src python scripts/check_reviewer_truth_boundaries.py
```

Expected boundary: `public_beta_ready=false`; controlled rehearsal candidate may be true; public beta/mainnet/live-economics/public-validator/automatic-upgrade/production-helper/legal/storage readiness must remain false or unclaimed.

## 4. Boot observer mode

```bash
WEALL_PUBLIC_TESTNET=1 bash scripts/boot_public_observer_testnet.sh
```

Observer boot should use signed/pinned chain commitments, seed registry, trust roots, and endpoint evidence. Endpoint advertisements are connection hints and freshness evidence; they do not grant validator status.

## 5. Inspect backend status

Expected backend status output: `readyz` returns an OK/ready response, `status` and `chain/identity` expose the chain identity/height surface, seed and validator routes show signed discovery/validator endpoint status, observer edge status separates local queue state from upstream acceptance/confirmation, and testnet capabilities keep high-risk launch claims disabled.

```bash
curl -s http://127.0.0.1:8000/v1/readyz | python3 -m json.tool
curl -s http://127.0.0.1:8000/v1/status | python3 -m json.tool
curl -s http://127.0.0.1:8000/v1/chain/identity | python3 -m json.tool
curl -s http://127.0.0.1:8000/v1/nodes/seeds | python3 -m json.tool
curl -s http://127.0.0.1:8000/v1/nodes/validators | python3 -m json.tool
curl -s http://127.0.0.1:8000/v1/observer/edge/status | python3 -m json.tool
curl -s http://127.0.0.1:8000/v1/status/testnet-capabilities | python3 -m json.tool
```

## 6. Frontend check

```bash
cd ../web
npm ci
npm run typecheck
npm run build
node scripts/test_rendered_civic_loop_source.mjs
```

Expected frontend check output: typecheck and build complete without errors, and the source rendered-civic-loop check exits successfully. These checks prove source/build health only; they do not prove browser E2E behavior or protocol finality.

Open the frontend and capture the first-run journey using `Weall-Protocol/docs/testnet/FIRST_15_MINUTES.md`. Frontend screenshots or source checks are supportive evidence only; frontend state is not protocol authority.

## 7. Evidence package map

| Evidence | Path |
|---|---|
| Final go-gate artifact | `generated/final_public_observer_controlled_testnet_go_gate_v1_5.json` |
| Public beta blocker report | `generated/public_beta_blocker_report_v1_5.json` |
| Release evidence manifest | `generated/release_evidence_manifest_v1_5.json` |
| Public observer launch requirements | `generated/public_observer_launch_evidence_requirements_v1_5.json` |
| Open-download transcript runbook | `docs/testnet/PUBLIC_OBSERVER_OPEN_DOWNLOAD_TRANSCRIPT.md` |
| Proof templates | `docs/proofs/` |
| Current readiness statement | `docs/reviewer/CURRENT_READINESS_STATEMENT.md` |
| Evidence index | `docs/reviewer/EVIDENCE_INDEX.md` |
| Blocker status | `docs/reviewer/PUBLIC_BETA_BLOCKER_STATUS.md` |

## 8. Evidence warning

This local quickstart does not close `AUD-628-P1-001`. Closure requires the external open-download transcript package described in `docs/testnet/PUBLIC_OBSERVER_OPEN_DOWNLOAD_TRANSCRIPT.md`.

## 9. What remains disabled

Live economics, fees/transfers/rewards/slashing, public validator/BFT readiness, automatic upgrades, executable migrations/rollbacks, production helper execution, legal approval, and public storage-market readiness remain disabled or unclaimed.
