# Documentation and evidence package audit before two-node rehearsal v1.5

Pass: 30
Purpose: reviewer-facing documentation/evidence audit before the next two-node/public-observer rehearsal.

Current allowed claim: **WeAll is ready for controlled internal/public-observer rehearsal candidate, with public beta readiness still blocked by explicit external evidence, counsel-review, upgrade-execution, storage, validator, replay, observer, and helper-topology gates.**

This audit does not claim public beta readiness, public mainnet readiness, public validator safety, public multi-validator BFT readiness, live economics readiness, production helper execution readiness, automatic upgrade readiness, executable migration or rollback readiness, legal/compliance approval, or public storage-market readiness.

Boundary reminder: generated artifacts prove repository consistency only. Evidence templates prepare future transcript capture only. Local scripts and frontend state are not protocol authority and do not close external evidence blockers by themselves.

## Inputs inspected

- Project entry points: root `README.md`, backend `README.md`, `RELEASE_CHECKLIST.md`, `CONTRIBUTING.md`, and `SECURITY.md`.
- Reviewer docs: `docs/reviewer/CURRENT_READINESS_STATEMENT.md`, `docs/reviewer/CURRENT_TESTNET_READINESS_STATEMENT.md`, `docs/reviewer/EVIDENCE_INDEX.md`, `docs/reviewer/PUBLIC_BETA_BLOCKER_STATUS.md`, and `docs/reviewer/NLNET_CURRENT_STATE_UPDATE_2026_08.md`.
- Testnet/runbooks: `docs/testnet/FIRST_15_MINUTES.md`, `docs/testnet/PUBLIC_OBSERVER_QUICKSTART.md`, `docs/testnet/TESTNET_LAUNCH_CHECKLIST.md`, `docs/testnet/FINAL_PUBLIC_OBSERVER_CONTROLLED_TESTNET_GO_GATE.md`, public observer discovery quickstarts, legal/compliance evidence pack, upgrade hardening plan, and helper topology hardening plan.
- Evidence/proof areas: `docs/proofs/`, `docs/legal/`, and `docs/audits/`.
- Generated artifacts: public beta blocker report, release evidence manifest, final public observer go-gate, external transcript requirements, upgrade hardening plan, production helper topology plan, tx/api/helper maps, failure registry, and testnet mechanism completion artifact.

## Artifact truth checkpoint

| Check | Current value |
| --- | --- |
| `public_beta_ready` | `false` |
| Blocker catalog entries | `14` |
| Closed in repository | `7` |
| Still open | `7` |
| P0 open | `3` |
| P1 open | `4` |
| Remaining gate type | external evidence or future mainnet-hardening evidence |
| Final go-gate scope | controlled internal/public-observer rehearsal candidate only |
| Tx canon checkpoint | 236 tx types, version 1.25.0 |


## Evidence status legend

| Status label | Meaning |
| --- | --- |
| Generated artifact | Deterministic repository output from checked-in generator logic. |
| Local repository evidence | Source, docs, local tests, or local command output from the current checkout. |
| Template-only proof slot | Checked-in schema/runbook for future evidence capture; not completed external evidence and not blocker closure. |
| Completed limited proof | Bounded prior proof that may support only its exact documented scope. |
| External blocker-closing evidence | Fresh external/counsel/operator transcript package that can be considered for a specific blocker after validation and review. |

## Documentation classification table

| # | Documentation/evidence area | Current status | Issue found | Patch action | Remaining evidence/test need |
| ---: | --- | --- | --- | --- | --- |
| 1 | Root `README.md` | Accurate and reviewer-ready | Links and status boundaries are current. | Added regression coverage that the README keeps final go-gate and manifest links. | Keep synchronized with generated artifacts after future pass changes. |
| 2 | `Weall-Protocol/README.md` | Accurate and reviewer-ready | No readiness escalation found. | No text change. | Keep tx canon checkpoint synchronized. |
| 3 | `RELEASE_CHECKLIST.md` | Accurate and reviewer-ready | No blocker-count drift found. | No text change. | Rerun release hygiene after commit. |
| 4 | `CONTRIBUTING.md` / `SECURITY.md` | Accurate but general | Not a reviewer evidence index; no direct overclaim found. | No text change. | Consider future reviewer cross-link if contributors begin using these as launch docs. |
| 5 | Current reviewer docs | Accurate and reviewer-ready | Allowed claim and blocker counts are aligned with artifacts. | Added Pass 30 audit link and evidence-status legend to the current evidence index. | Keep all remaining blockers visible. |
| 6 | Legacy `docs/REVIEWER_EVIDENCE_INDEX.md` | Stale but useful historical checklist | It had an old review date and could be mistaken for the canonical current evidence index. | Added a prominent current-status notice directing reviewers to `docs/reviewer/EVIDENCE_INDEX.md`. | Future pass may archive or merge old checklist content. |
| 7 | Public observer quickstarts | Accurate but potentially confusing | There are two public observer quickstart locations; the detailed older guide did not explicitly defer to the current testnet runbook. | Added a canonical wrapper at `docs/testnet/PUBLIC_OBSERVER_TESTNET_QUICKSTART.md` and marked the root `docs/PUBLIC_OBSERVER_TESTNET_QUICKSTART.md` as a detailed supplement. | Keep one canonical rehearsal path: `docs/testnet/PUBLIC_OBSERVER_QUICKSTART.md`. |
| 8 | `docs/testnet/PUBLIC_OBSERVER_QUICKSTART.md` | Accurate but missing deterministic frontend install guidance | Frontend step used `npm install` instead of the deterministic lockfile path expected by reviewer runs. | Changed frontend command to `npm ci` and added expected-output guidance for status endpoints. | External observer transcript still required for `AUD-628-P1-001`. |
| 9 | Testnet launch checklist | Accurate and reviewer-ready | No missing blocker-count boundary found. | No text change. | Keep generated checks current after future artifact changes. |
| 10 | Final go-gate docs | Accurate and reviewer-ready | Go/No-Go boundaries agree with generated go-gate artifact. | Added regression coverage through Pass 30 doc test. | Regenerate final go-gate only if generator/source changes. |
| 11 | Public observer open-download proof template | Template-only but clearly labeled | Already clearly says not completed external evidence. | Added audit/report coverage. | Completed external transcript package needed. |
| 12 | External cross-machine replay proof template | Template-only but label could be stronger | It said template only and not blocker closure, but not the exact “not completed external evidence” phrase. | Added explicit not-completed-external-evidence language. | Two external/physical machine aggregate transcript still needed. |
| 13 | Independent validator/operator proof template | Template-only but label could be stronger | It did not use the exact not-completed-external-evidence phrase. | Added explicit not-completed-external-evidence language. | Independent operator transcript still needed. |
| 14 | Real storage/IPFS proof template | Template-only but label could be stronger | It did not use the exact not-completed-external-evidence phrase. | Added explicit not-completed-external-evidence language. | Real daemon/operator transcript still needed. |
| 15 | Legal/compliance proof template | Template-only but label could be stronger | It did not use the exact not-completed-external-evidence phrase. | Added explicit not-completed-external-evidence language. | Counsel or controlled external attestation still needed. |
| 16 | Upgrade execution proof slot | Template-only future hardening | It already preserves record-only posture. | Added audit/report coverage. | Future executable upgrade/migration/rollback proof still needed. |
| 17 | Production helper topology proof slot | Template-only future hardening | It already preserves disabled production-helper posture. | Added audit/report coverage. | Future helper topology proof still needed. |
| 18 | Generated artifacts | Accurate and fresh | Baseline checks passed; no generated drift found. | No generated artifacts changed. | Rerun `--check` generators before commit. |
| 19 | Protocol docs | Accurate and bounded for this pass | No private protocol-native content, frontend authority, mempool finality, or wall-clock truth regression found in touched docs. | Added regression tests around templates/runbooks/current evidence index. | Continue scanning broader docs before public-facing updates. |

## Closed in this pass

* documentation/evidence issue: legacy public observer quickstart ambiguity.
* evidence: `docs/PUBLIC_OBSERVER_TESTNET_QUICKSTART.md` and `docs/testnet/PUBLIC_OBSERVER_QUICKSTART.md` both existed as public-observer guidance, while `docs/testnet/PUBLIC_OBSERVER_TESTNET_QUICKSTART.md` was missing.
* tests: `tests/test_release_docs_truth_sync.py` now requires the canonical wrapper and explicit canonical-current/supplement distinction.

* documentation/evidence issue: deterministic frontend install guidance in the public observer quickstart.
* evidence: `docs/testnet/PUBLIC_OBSERVER_QUICKSTART.md` used `npm install` for reviewer frontend checks.
* tests: `tests/test_release_docs_truth_sync.py` now requires `npm ci`, working-directory guidance, and expected-output guidance in the quickstart.

## Reduced in this pass

* documentation/evidence issue: proof-template packages could be read inconsistently by reviewers.
* what improved: template README files now consistently say they are not completed external evidence, do not close blockers, and must not be cited as readiness escalation.
* what remains: the actual external transcript packages still need real operators, machines, commands, manifests, signatures or controlled attestations, hashes, and strict-release validation.

* documentation/evidence issue: current evidence index did not have a compact evidence-status legend.
* what improved: `docs/reviewer/EVIDENCE_INDEX.md` now separates generated artifact, local repository evidence, template-only proof slot, completed limited proof, and external blocker-closing evidence.
* what remains: reviewers still need to inspect the generated artifacts and completed transcripts before escalating claims.

## Still open

* documentation/evidence issue: `AUD-628-P1-001` external public observer evidence.
* why: repository docs and templates cannot prove an external clean-clone/open-download/state-sync/rendered journey.
* exact evidence or patch needed: completed public observer transcript package with branch/commit, dependency output, signed registry verification, chain identity, state sync or honest fail-closed result, frontend rendered journey, and manifest.

* documentation/evidence issue: `AUD-618-P1-003` external replay evidence.
* why: generated local artifacts do not prove replay consistency across external/physical machines.
* exact evidence or patch needed: aggregate external cross-machine replay transcript passing strict validation.

* documentation/evidence issue: `AUD-618-P1-004` real storage/IPFS evidence.
* why: docs and deterministic scaffolds are not real Kubo/IPFS operator proof.
* exact evidence or patch needed: real daemon/operator transcript with peer IDs, daemon versions, CIDs, pin/retrieval proofs, fresh-node retrieval, wrong-CID/corrupt-content rejection, signatures/attestation, and strict validation.

* documentation/evidence issue: `AUD-618-P0-001` independent validator/operator evidence.
* why: controlled repository proof does not establish public validator safety or public multi-validator BFT readiness.
* exact evidence or patch needed: independent controlled validator/operator transcript with authority boundaries, activation proof, partition/rejoin, equivocation rejection, catchup, restart replay, state-root equality, and strict validation.

* documentation/evidence issue: `AUD-618-P0-002` legal/compliance attestation.
* why: checked-in legal docs are non-lawyer drafts and templates only.
* exact evidence or patch needed: counsel or controlled external attestation bound to the exact commit and launch-disabled matrix.

* documentation/evidence issue: `AUD-618-P0-003` executable upgrade hardening.
* why: current protocol upgrade surfaces are record-only.
* exact evidence or patch needed: staged executable upgrade/migration/rollback proof with multi-node replay and rollback/repair semantics.

* documentation/evidence issue: `AUD-618-P1-005` production helper topology hardening.
* why: production helper execution remains disabled.
* exact evidence or patch needed: multi-node helper topology proof covering deterministic assignment, lanes, canonical ordering, receipt validation, merge, serial equivalence, Byzantine rejection, crash/restart, and operator policy.

## Reviewer verification commands

```bash
cd ~/WeAll-Protocol/Weall-Protocol
source .venv/bin/activate

PYTHONPATH=src:scripts python scripts/gen_public_beta_blocker_report_v1_5.py --check
PYTHONPATH=src python scripts/gen_release_evidence_manifest_v1_5.py --check
PYTHONPATH=src:scripts python scripts/gen_final_public_observer_controlled_testnet_go_gate_v1_5.py --check
PYTHONPATH=src:scripts python scripts/gen_external_operator_transcript_requirements_v1_5.py --check
PYTHONPATH=src:scripts python scripts/gen_protocol_upgrade_execution_hardening_plan_v1_5.py --check
PYTHONPATH=src:scripts python scripts/gen_production_helper_topology_hardening_plan_v1_5.py --check
PYTHONPATH=src python scripts/check_v15_public_readiness_artifacts.py
PYTHONPATH=src python scripts/check_reviewer_truth_boundaries.py
PYTHONPATH=src python -m pytest -q   tests/test_release_docs_truth_sync.py   tests/test_reviewer_language_cleanup.py   tests/prod/test_final_public_observer_controlled_testnet_go_gate.py   tests/prod/test_public_beta_evidence_gates.py   tests/prod/test_public_observer_testnet_readiness_docs.py   tests/prod/test_legal_compliance_evidence_pack.py   tests/prod/test_protocol_upgrade_execution_hardening_plan.py   tests/prod/test_production_helper_topology_hardening_plan.py   tests/prod/test_external_evidence_transcript_gates.py   tests/prod/test_external_transcript_strict_release.py   tests/test_public_readiness_artifacts_v15.py
```

## Safe reviewer conclusion

This documentation/evidence pass makes the current repository easier to verify and harder to overclaim. It does not change protocol readiness status. The allowed claim remains bounded to controlled internal/public-observer rehearsal candidate only, and public beta remains blocked by the seven open external/mainnet-hardening gates.
