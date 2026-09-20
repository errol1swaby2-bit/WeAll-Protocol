# WeAll Release Verification Checklist

This checklist is for bounded repository verification and rehearsal preparation against the current generated readiness artifacts. It does not escalate readiness claims.

Current allowed claim: **WeAll is a pre-public-testnet protocol implementation under active hardening, with local/devnet/public-observer-oriented evidence present and public beta readiness still blocked by explicit external observer, replay, validator/operator, storage, legal, upgrade-execution, and helper-topology gates.** Independent cryptographic review remains a separate launch gate.

## Current status

| Claim area | Status | Required boundary |
|---|---:|---|
| Bounded local/devnet/public-observer-oriented rehearsal | GO for local verification only | Local repository evidence is not a controlled-testnet mechanism-complete claim. |
| Controlled-testnet mechanism completion | NO-GO | Production helper state-root/restart equivalence remains incomplete in the current generated go-gate. |
| Public beta readiness | NO-GO | `public_beta_ready=false` must remain visible in the generated blocker report. |
| Public observer launch claim | NO-GO | External open-download observer transcript is still required. |
| Public mainnet readiness | NO-GO | Mainnet hardening remains future work. |
| Public validator / public multi-validator BFT readiness | NO-GO | Independent validator/operator transcript remains required. |
| Live economics | NO-GO | Economics remain locked; no live fees/transfers/rewards/slashing claim. |
| Automatic upgrades | NO-GO | Upgrade execution, migration execution, and rollback execution are disabled. |
| Production helper execution | NO-GO | Helper topology remains a hardening gate. |
| Production cryptographic audit / post-quantum security | NO-GO | Fresh profile-aware post-transition evidence and external cryptographic review remain required. |
| Legal/compliance approval | NO-GO | Counsel/control review remains open. |
| Public storage-market readiness | NO-GO | Real operator storage/IPFS evidence remains required. |

Canonical transaction count/version: see `Weall-Protocol/generated/tx_index.json`.
Canonical blocker totals/severity counts: see `Weall-Protocol/generated/public_beta_blocker_report_v1_5.json`.
Canonical release claim boundaries: see `Weall-Protocol/generated/release_evidence_manifest_v1_5.json`.

## Required repository checks

Run from the backend directory:

```bash
cd ~/WeAll-Protocol/Weall-Protocol
source .venv/bin/activate

PYTHONPATH=src:scripts python scripts/gen_public_beta_blocker_report_v1_5.py --check
PYTHONPATH=src python scripts/gen_release_evidence_manifest_v1_5.py --check
PYTHONPATH=src python scripts/check_v15_public_readiness_artifacts.py
PYTHONPATH=src python scripts/check_reviewer_truth_boundaries.py
PYTHONPATH=src python scripts/check_public_claim_freshness.py
PYTHONPATH=src python scripts/gen_current_verified_claims.py --check
PYTHONPATH=src python -m pytest -q \
  tests/test_release_docs_truth_sync.py \
  tests/test_reviewer_language_cleanup.py \
  tests/test_current_document_registry.py \
  tests/prod/test_final_public_observer_controlled_testnet_go_gate.py \
  tests/prod/test_public_beta_evidence_gates.py \
  tests/prod/test_public_observer_testnet_readiness_docs.py \
  tests/test_public_readiness_artifacts_v15.py
```

If current-facing documentation changed in the commit, also run:

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
PYTHONPATH=src python scripts/check_public_claim_freshness.py
PYTHONPATH=src python scripts/check_release_hygiene_v1_5.py
```

## Frontend verification checks

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

Frontend checks prove rendering/source-contract behavior only. They do not override backend artifacts and do not close external evidence blockers by themselves.

## Evidence package map

| Package | Path | Must remain true |
|---|---|---|
| Current verified claims | `Weall-Protocol/docs/CURRENT_VERIFIED_CLAIMS.md` | Current claims remain bounded to generated repository evidence. |
| Current readiness statement | `Weall-Protocol/docs/reviewer/CURRENT_READINESS_STATEMENT.md` | Public beta remains blocked. |
| Evidence index | `Weall-Protocol/docs/reviewer/EVIDENCE_INDEX.md` | Implemented evidence, generated artifacts, local gates, external evidence, and future hardening remain separated. |
| Public beta blocker status | `Weall-Protocol/generated/public_beta_blocker_report_v1_5.json` | Generated blocker state is authoritative. |
| Final go-gate doc | `Weall-Protocol/docs/testnet/FINAL_PUBLIC_OBSERVER_CONTROLLED_TESTNET_GO_GATE.md` | Controlled-testnet mechanism completion remains bounded by the generated go-gate. |
| Public observer quickstart | `Weall-Protocol/docs/testnet/PUBLIC_OBSERVER_QUICKSTART.md` | Boot steps are transcript collection steps, not public-readiness authority. |
| Testnet launch checklist | `Weall-Protocol/docs/testnet/TESTNET_LAUNCH_CHECKLIST.md` | Launch wording remains conservative. |
| Production posture | `Weall-Protocol/docs/PRODUCTION_POSTURE.md` | Fail-closed and disabled surfaces remain explicit. |
| Versioning strategy | `Weall-Protocol/docs/PROTOCOL_VERSIONING_STRATEGY.md` | Transaction canon and upgrade record-only boundaries remain current. |
| Release evidence manifest | `Weall-Protocol/generated/release_evidence_manifest_v1_5.json` | Disabled/unclaimed launch boundaries remain generated truth. |
| Proof templates | `Weall-Protocol/docs/proofs/` | External transcript templates remain unfilled unless real evidence is attached. |

## Blocker truth that must not be hidden

- Public beta readiness remains false.
- Open blocker IDs, totals, severities, and repository-closure state must be read from `Weall-Protocol/generated/public_beta_blocker_report_v1_5.json`, not duplicated here.
- Local scripts and generated artifacts can prove repository consistency, but they cannot self-certify missing external operator, counsel, storage, replay, helper, observer, upgrade-execution, or cryptographic-review evidence.

## External evidence still required

The authoritative open blocker list and its required evidence are generated in `Weall-Protocol/generated/public_beta_blocker_report_v1_5.json`. The current classes include independent validator/operator evidence, legal/compliance evidence, executable upgrade staging/rollback evidence, fresh profile-aware cryptographic evidence plus external review, cross-machine replay, real storage/IPFS operation, production helper topology, and an external clean-clone/open-download observer journey.

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

The current release package must continue to say that live economics, fees/transfers/rewards/slashing, public validator/BFT readiness, automatic upgrades, executable migrations/rollbacks, production helper execution, completed production cryptographic audit, production post-quantum security, legal approval, and public storage-market readiness are not enabled or not claimed.

## Commit hygiene before publishing a patch

```bash
git status --short
git diff --check
PYTHONPATH=src:scripts python scripts/gen_public_beta_blocker_report_v1_5.py --check
PYTHONPATH=src python scripts/gen_release_evidence_manifest_v1_5.py --check
PYTHONPATH=src python scripts/check_v15_public_readiness_artifacts.py
PYTHONPATH=src python scripts/check_public_claim_freshness.py
PYTHONPATH=src python scripts/check_reviewer_truth_boundaries.py
PYTHONPATH=src python scripts/check_release_hygiene_v1_5.py
```
