# Reviewer Evidence Index

Current allowed claim: **WeAll is a pre-public-testnet protocol implementation under active hardening, with local/devnet/public-observer-oriented evidence present and public beta readiness still blocked by explicit external observer, replay, validator/operator, storage, legal, upgrade-execution, and helper-topology gates.**

This index separates implemented repository evidence, generated artifacts, local/controlled rehearsal readiness, external evidence still required, and future mainnet-readiness hardening. It does not claim public beta, public mainnet, public multi-validator BFT/public validator safety, live economics, automatic upgrades, production helper execution, legal approval, or public storage-market readiness.

## Current status

| Category | Status | Canonical source |
|---|---:|---|
| Controlled internal/public-observer rehearsal candidate | GO | `generated/final_public_observer_controlled_testnet_go_gate_v1_5.json` |
| Public beta readiness | NO-GO | `generated/public_beta_blocker_report_v1_5.json` keeps `public_beta_ready=false` |
| Public observer launch claim | NO-GO | `AUD-628-P1-001` remains open |
| Public mainnet readiness | NO-GO | Remaining mainnet-hardening gates remain open |
| Live economics | NO-GO | Release claim boundaries remain false |
| Automatic upgrade execution | NO-GO | Upgrade execution remains record-only/non-executable |
| Legal/compliance approval | NO-GO | Attestation remains required |

Current tx canon checkpoint: **236 tx types, version 1.25.0**.

## Evidence status legend

| Status label | Meaning | Claim boundary |
|---|---|---|
| Generated artifact | Deterministic repository output produced by a checked-in generator. | Proves repo consistency only; not external evidence by itself. |
| Local repository evidence | Source, tests, docs, or local command output from this checkout. | Supports controlled rehearsal review only. |
| Template-only proof slot | Checked-in schema/runbook for future evidence capture. | Does not close blockers and must not be cited as completed external evidence. |
| Completed limited proof | Attached proof from a bounded prior rehearsal. | May support the exact bounded claim stated in that proof; does not close broader public beta/mainnet gates. |
| External blocker-closing evidence | Fresh operator/counsel transcript package from the exact commit with validation output. | Required before escalating claims or closing the corresponding open blocker. |

## Implemented repository evidence

| Evidence | Path | Reviewer use |
|---|---|---|
| Tx canon checkpoint | `generated/tx_index.json`, `generated/tx_contract_map.json` | Confirms the current 236 tx type canon and contract coverage. |
| API contract map | `generated/api_contract_map_v1_5.json` | Maps implemented API routes to reviewer surfaces. |
| API response vectors | `generated/api_response_vectors_v1_5.json` | Provides route response evidence for current status/capability surfaces. |
| Failure code registry | `generated/failure_code_registry_v1_5.json` | Documents expected failure modes and gate language. |
| Public-only protocol docs/tests | `docs/PUBLIC_ONLY_PROTOCOL.md`, `tests/test_public_only_protocol_redesign.py` | Confirms protocol-native private/opaque social payloads are unsupported. |
| Release truth docs | `docs/TRUTH_BOUNDARY.md`, `docs/PRODUCTION_POSTURE.md`, `docs/PROTOCOL_VERSIONING_STRATEGY.md` | Defines claim boundaries and fail-closed requirements. |
| Testnet runbooks | `docs/testnet/` | Provides controlled rehearsal and external transcript instructions. |
| Pass 29 pre-rehearsal flow audit | `docs/audits/comprehensive_protocol_flow_audit_before_two_node_v1_5.md` | Classifies major user/operator/reviewer flows and records low-risk fixes before two-node rehearsal. |
| Pass 30 documentation/evidence audit | `docs/audits/documentation_evidence_package_audit_before_two_node_v1_5.md` | Classifies reviewer docs, runbooks, generated artifacts, and proof templates before two-node rehearsal. |
| README-to-implementation traceability | `docs/reviewer/README_TO_IMPLEMENTATION_TRACEABILITY.md` | Maps major README claims to implementation files, tests, generated artifacts, proof templates, disabled launch gates, and explicit open blockers. |

## Generated artifacts

| Artifact | Path | Current meaning |
|---|---|---|
| Public beta blocker report | `generated/public_beta_blocker_report_v1_5.json` | 14 blockers cataloged; 7 closed in repository; 7 open; `public_beta_ready=false`. |
| Release evidence manifest | `generated/release_evidence_manifest_v1_5.json` | Tracks release artifacts and disabled claim boundaries. |
| Final public-observer go-gate | `generated/final_public_observer_controlled_testnet_go_gate_v1_5.json` | Allows only controlled internal/public-observer rehearsal candidate wording. |
| Public observer launch requirements | `generated/public_observer_launch_evidence_requirements_v1_5.json` | Defines external observer transcript requirements. |
| Protocol upgrade hardening plan | `generated/protocol_upgrade_execution_hardening_plan_v1_5.json` | Documents future executable upgrade proof; execution remains disabled. |
| Production helper topology hardening plan | `generated/production_helper_topology_hardening_plan_v1_5.json` | Documents future helper topology proof; production helper execution remains disabled. |
| External operator transcript requirements | `generated/external_operator_transcript_requirements_v1_5.json` | Defines validation schemas for external evidence. |

## Local / controlled readiness evidence

The current local package supports a controlled internal/public-observer rehearsal candidate. It includes:

- backend public-readiness artifact checks;
- release-evidence manifest check;
- reviewer truth-boundary scan;
- final go-gate artifact check;
- controlled two-node/readiness runbooks;
- public observer boot quickstart;
- frontend type/build/source checks.

Local/controlled evidence is useful for review, but local scripts are not authoritative for external readiness claims.

## Proof package distinctions

| Proof area | Path | Current status | Reviewer instruction |
|---|---|---|---|
| Controlled-devnet observer live gate | `docs/proofs/controlled-devnet-observer-live-gate/` | Completed limited proof for a controlled-devnet two-machine observer live gate. | May be cited only for that bounded controlled-devnet result; it does not close current public beta blockers. |
| Public observer open-download | `docs/proofs/public-observer-open-download/2026-07-05/` | Template-only proof slot. | not completed external evidence; does not close `AUD-628-P1-001`. |
| External cross-machine replay | `docs/proofs/external-cross-machine-replay/2026-07-05/` | Template-only proof slot. | not completed external evidence; does not close `AUD-618-P1-003`. |
| Real storage/IPFS operator | `docs/proofs/real-storage-ipfs-operator/2026-07-05/` | Template-only proof slot. | not completed external evidence; does not close `AUD-618-P1-004`. |
| Independent validator/operator | `docs/proofs/independent-controlled-validator-operator/2026-07-05/` | Template-only proof slot. | not completed external evidence; does not close `AUD-618-P0-001`. |
| Legal/compliance counsel | `docs/proofs/legal-compliance-counsel/2026-07-05/` | Template-only proof slot. | not completed external evidence; does not close `AUD-618-P0-002`. |
| Protocol upgrade execution | `docs/proofs/protocol-upgrade-execution-hardening/2026-07-05/` | Template-only future hardening proof slot. | not completed external evidence; does not close `AUD-618-P0-003`. |
| Production helper topology | `docs/proofs/production-helper-topology-hardening/2026-07-05/` | Template-only future hardening proof slot. | not completed external evidence; does not close `AUD-618-P1-005`. |

## Reviewer trust posture additions

| Area | Reviewer-visible file | Current meaning | Verification |
|---|---|---|---|
| Public-only direction / DM quarantine | `docs/reviewer/DIRECT_MESSAGE_TRANSACTION_QUARANTINE.md` | Direct/private/encrypted messaging is absent from active public-testnet tx canon and out of scope for the NLnet claim. | `PYTHONPATH=src python -m pytest -q tests/test_direct_message_transaction_quarantine.py` |
| Observer proof tiers | `docs/testnet/OBSERVER_PROOF_POSTURE_AND_CAPTURE.md` | Separates local observer proof, same-machine dual-node proof, and remote two-machine signed observer proof. | Runbook only unless transcripts are captured under `audit-metadata/reviewer-evidence-YYYY-MM-DD/`. |
| Helper safety posture | `docs/reviewer/HELPER_PRODUCTION_SAFETY_CHECKLIST.md` | Production helper execution is disabled; checklist maps future safety evidence topics. | `PYTHONPATH=src python -m pytest -q tests/prod/test_helper_production_safety_checklist.py` |
| Accessibility posture | `docs/reviewer/ACCESSIBILITY_REVIEW_CHECKLIST.md` | Basic source-level accessibility posture exists; full WCAG compliance is not claimed. | `cd ../web && npm run test:accessibility-source && npm run test:reviewer-critical-source` |
| Frontend reviewer-critical flows | `web/scripts/test_reviewer_critical_flows_source.mjs` | Source check covers account recovery, async/live PoH, posting/feed, groups, disputes, governance, locked wallet/economics, observer copy, and no active private messaging claim. | `cd ../web && npm run test:reviewer-critical-source` |

## External evidence still required

| Blocker | Exact evidence required before escalation |
|---|---|
| `AUD-628-P1-001` | External clean-clone/open-download/state-sync/frontend rendered journey transcript |
| `AUD-618-P1-003` | External/two-machine replay transcript |
| `AUD-618-P1-004` | Real storage/IPFS daemon/operator transcript |
| `AUD-618-P0-001` | Independent controlled validator/operator transcript |
| `AUD-618-P0-002` | Real counsel or controlled legal/compliance attestation |
| `AUD-618-P0-003` | Future executable upgrade staging/rollback proof |
| `AUD-618-P1-005` | Future production helper topology proof |

The corresponding templates and runbooks live under `docs/proofs/` and `docs/testnet/`. They should be completed only with real external evidence.

## Future mainnet-readiness hardening

The following remain future hardening gates, not present-tense readiness claims:

- independent public validator/operator proof and public multi-validator BFT evidence;
- executable protocol upgrade staging, migration, and rollback proof;
- real storage/IPFS operator durability proof and storage-market posture;
- production helper topology proof;
- legal/compliance attestation for public claims.

## Major protocol surfaces

| Surface | Evidence pointers |
|---|---|
| Account/profile | API contract map, response vectors, profile/account docs, PoH docs. |
| Public social | Feed/content/comment API vectors and frontend rendered/source checks. |
| Public groups | Group flow readiness docs and member-gated participation checks. |
| Governance | Governance rendered journey docs, block-height lifecycle checks, and upgrade-record boundary docs. |
| Disputes/reviews | Dispute/review rendered journey docs, review-vote evidence, and restricted evidence boundaries. |
| Transaction lifecycle | Tx canon artifacts, tx status API vectors, lifecycle rendered evidence docs. |
| Node/operator surfaces | Status/operator/mempool/discovery routes, secret guard, release hygiene, onboarding docs. |
| Observer boot | Public observer quickstart and open-download transcript template. |
| External evidence packages | Proof templates under `docs/proofs/` plus validation scripts. |

## Reviewer verification path

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


### Pass 33 post-quantum signing blocker

- `AUD-633-P0-004`: reproducible real ML-DSA verifier/signing integration, PQ-signed seed/trust-root materials, migrated authority signatures, and external cryptographic review remain required before controlled/public testnet signing can be claimed.
