# WeAll Protocol

WeAll is an experimental public-only civic protocol implementation. This repository contains the backend node/runtime, public API, frontend, operator scripts, generated evidence artifacts, and reviewer-facing documentation for the current local/devnet/public-observer-oriented hardening track.

Current allowed claim: **WeAll is a pre-public-testnet protocol implementation under active hardening, with local/devnet/public-observer-oriented evidence present and public beta readiness still blocked by explicit external observer, replay, validator/operator, storage, legal, upgrade-execution, and helper-topology gates.**

This repository should be reviewed as an implementation under active hardening. It is not a public beta, public mainnet, public validator, public multi-validator BFT, live-economics, automatic-upgrade, production-helper, legal-approval, or public storage-market readiness claim.

## Public-only civic protocol direction

WeAll is being narrowed and reviewed as public-only civic protocol infrastructure. Protocol-native social, civic, governance, moderation, dispute, group, reputation, validator/operator, and node activity is intended to be publicly inspectable. Group membership may gate posting, commenting, voting, moderation, invitation, and administration behavior, but membership must not gate read visibility for protocol-native group content.

Private, direct, encrypted, inbox/outbox, chat, or protocol-native messaging is not part of the NLnet/public-testnet claim. Earlier private/direct messaging concepts are legacy/out-of-scope artifacts only when they appear in historical docs. They are not active public-testnet functionality, not production encrypted messaging, and not a hidden launch feature.

## Current status

| Surface | Status | Reviewer meaning |
|---|---:|---|
| Local/devnet/public-observer-oriented evidence | GO for local review only | Repository artifacts and local gates support bounded local/devnet/public-observer-oriented rehearsal packaging. |
| Public beta readiness | NO-GO | `generated/public_beta_blocker_report_v1_5.json` keeps `public_beta_ready=false`. |
| Public observer launch claim | NO-GO | `AUD-628-P1-001` still requires an external clean-clone/open-download/state-sync/frontend rendered journey transcript. |
| Public mainnet readiness | NO-GO | Mainnet-hardening gates remain open. |
| Public validator / public multi-validator BFT readiness | NO-GO | Independent validator/operator evidence remains required. |
| Live economics | NO-GO | Fees, transfers, rewards, slashing, treasury spend, and production economics remain locked by default. |
| Automatic protocol upgrade execution | NO-GO | Upgrade records are deterministic public metadata only; software apply, migration execution, and rollback execution are not enabled. |
| Legal/compliance approval | NO-GO | Legal materials are non-lawyer drafts pending counsel or controlled external review. |
| Public storage-market readiness | NO-GO | Storage/IPFS proof is not yet a public storage-provider market claim. |

Current tx canon checkpoint: **236 tx types, version 1.25.0**.

Proof-of-Humanity checkpoint: **Tier 0 = account only**, **Tier 1 = native async verified human**, and **Tier 2 = native live verified human**. There is no required user-facing Tier 3. There is no required email, no required SMTP, no required DNS, and no required named hosting provider as PoH authority.

The checked-in public testnet seed registry is `configs/public_testnet_seed_registry.json`, the checked-in public testnet trust roots are `configs/public_testnet_trust_roots.json`, and the pinned testnet chain identity config is `configs/chains/weall-testnet-v1.json`. It is a repository-pinned discovery input for observer bootstrapping; it is not provider authority, validator authority, or proof of public beta readiness.

## Reviewer verification path

Run these checks from a fresh checkout before relying on reviewer-facing claims:

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

If README or reviewer docs changed in the commit being reviewed, also run:

```bash
PYTHONPATH=src python scripts/check_release_hygiene_v1_5.py
```

For the bounded public-observer boot rehearsal, the operator path remains:

```bash
git clone <repo-url> WeAll-Protocol
cd WeAll-Protocol/Weall-Protocol
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.lock
pip install -e .
WEALL_PUBLIC_TESTNET=1 bash scripts/boot_public_observer_testnet.sh
```

That boot path is a local/operator transcript path, not authority by itself. Public claims require the external evidence packages listed below.

Frontend state is not protocol authority. Local scripts are not public-readiness authority without the external evidence gates.

## Evidence package map

| Evidence area | Canonical location | Current meaning |
|---|---|---|
| Public beta blocker status | `Weall-Protocol/docs/reviewer/PUBLIC_BETA_BLOCKER_STATUS.md` and `Weall-Protocol/generated/public_beta_blocker_report_v1_5.json` | 14 blocker catalog entries remain visible; 7 are closed in repository; 7 remain open as external evidence or mainnet-hardening gates. |
| Final bounded go-gate | `Weall-Protocol/docs/testnet/FINAL_PUBLIC_OBSERVER_CONTROLLED_TESTNET_GO_GATE.md` and `Weall-Protocol/generated/final_public_observer_controlled_testnet_go_gate_v1_5.json` | GO only for controlled internal/public-observer rehearsal candidate. |
| Release evidence manifest | `Weall-Protocol/generated/release_evidence_manifest_v1_5.json` | Tracks generated artifacts and preserves release claim boundaries. |
| Reviewer evidence index | `Weall-Protocol/docs/reviewer/EVIDENCE_INDEX.md` | Maps implemented evidence, generated artifacts, and external transcript templates. |
| README-to-implementation traceability | `Weall-Protocol/docs/reviewer/README_TO_IMPLEMENTATION_TRACEABILITY.md` | Maps major README claims to implementation files, tests, generated artifacts, templates, disabled gates, and open blockers. |
| External proof templates | `Weall-Protocol/docs/proofs/` | Templates for evidence that cannot be self-certified by local scripts. |
| Testnet runbooks | `Weall-Protocol/docs/testnet/` | Operator instructions and transcript expectations for the next rehearsal. |
| Production posture | `Weall-Protocol/docs/PRODUCTION_POSTURE.md` | Fail-closed production constraints and disabled-readiness boundaries. |
| Versioning strategy | `Weall-Protocol/docs/PROTOCOL_VERSIONING_STRATEGY.md` | Tx canon, chain/profile pinning, and record-only upgrade posture. |

## Headline claim to evidence map

| Headline claim | Implementation path(s) | Tests / checks | Generated artifacts | Command(s) to verify | Current claim status | Explicit boundary |
|---|---|---|---|---|---|---|
| Deterministic transaction canon | `Weall-Protocol/specs/tx_canon/tx_canon.yaml`; `Weall-Protocol/scripts/gen_tx_index.py`; `Weall-Protocol/src/weall/runtime/tx_schema.py` | `tests/test_canon_coverage.py`; `tests/test_tx_schema_governance_dispute_receipts.py`; `tests/test_direct_message_transaction_quarantine.py` | `Weall-Protocol/generated/tx_index.json` | `PYTHONPATH=src python scripts/gen_tx_index.py --check`; `PYTHONPATH=src python -m pytest -q tests/test_canon_coverage.py tests/test_direct_message_transaction_quarantine.py` | Implemented repository canon | Canon includes public civic txs only; no active direct/private message tx claim. |
| State root / replay determinism | `Weall-Protocol/src/weall/runtime/domain_dispatch.py`; `Weall-Protocol/src/weall/ledger/`; replay/state-root scripts | `Weall-Protocol/tests/test_state_root_ephemeral_contract.py`; `Weall-Protocol/tests/test_protocol_upgrade_height_scheduled_lifecycle.py`; replay transcript gates | `Weall-Protocol/generated/state_root_vectors_v1_5.json` | `PYTHONPATH=src python scripts/gen_state_root_vectors_v1_5.py --check`; targeted replay tests | Local/devnet evidence | External cross-machine replay remains an open evidence gate. |
| Local block production | `Weall-Protocol/src/weall/runtime/block_builder.py`; `Weall-Protocol/src/weall/runtime/block_admission.py`; rehearsal scripts | `tests/test_block_schedule_survivability_harness.py`; block production proof tests | block schedule/rehearsal evidence artifacts where generated | `PYTHONPATH=src python -m pytest -q tests/test_block_schedule_survivability_harness.py` | Local harness evidence | Does not imply public mainnet throughput or public BFT readiness. |
| Controlled devnet rehearsal | `Weall-Protocol/scripts/run_controlled_testnet_go_gate_v1_5.py`; testnet docs | `tests/test_controlled_testnet_go_gate.py`; `tests/prod/test_final_public_observer_controlled_testnet_go_gate.py` | `Weall-Protocol/generated/final_public_observer_controlled_testnet_go_gate_v1_5.json` | `PYTHONPATH=src:scripts python scripts/gen_final_public_observer_controlled_testnet_go_gate_v1_5.py --check` | Controlled rehearsal candidate evidence | Public beta remains blocked. |
| Public observer bundle | `Weall-Protocol/scripts/boot_public_observer_testnet.sh`; node discovery routes; observer docs | `tests/prod/test_public_observer_boot_and_evidence_scripts.py`; `tests/prod/test_clean_observer_boot_from_checked_in_registry.py` | `Weall-Protocol/generated/public_observer_launch_evidence_requirements_v1_5.json` | `WEALL_PUBLIC_TESTNET=1 bash scripts/boot_public_observer_testnet.sh`; capture transcript into `audit-metadata/reviewer-evidence-YYYY-MM-DD/` | Runbook/local proof posture | First external observer readiness requires a fresh remote/signed observer run. |
| Observer non-authority / cannot sign as validator | observer authority gate code; node/operator surfaces | `tests/prod/test_observer_cannot_enable_validator_signing.py`; `tests/prod/test_observer_bundle_contains_no_authority_secrets.py` | release evidence manifest references observer gates | `PYTHONPATH=src python -m pytest -q tests/prod/test_observer_cannot_enable_validator_signing.py tests/prod/test_observer_bundle_contains_no_authority_secrets.py` | Implemented gate evidence | Observer paths do not grant validator signing authority. |
| PoH current posture | `Weall-Protocol/src/weall/poh/`; PoH API/frontend pages | async/live PoH targeted tests and frontend source checks | API contract/response vectors | `PYTHONPATH=src python -m pytest -q tests/test_async_poh_reviewability_truth.py tests/test_apply_poh_live_hardening_mvp.py`; `node web/scripts/test_reviewer_critical_flows_source.mjs` | Native PoH surfaces under review | Not a complete public identity infrastructure or legal identity proof. |
| Governance current posture | `Weall-Protocol/src/weall/api/routes_public_parts/gov.py`; governance apply/domain dispatch; frontend decisions pages | governance due-height, multi-option, rendered journey checks | tx/API contract maps | `PYTHONPATH=src python -m pytest -q tests/test_governance_due_height_trust_boundary.py tests/test_governance_multi_option_voting.py`; `node web/scripts/test_reviewer_critical_flows_source.mjs` | Bounded public governance implementation | Not production constitutional governance readiness. |
| Protocol upgrade scheduled activation posture | `Weall-Protocol/src/weall/runtime/apply/protocol.py`; upgrade docs | `tests/test_protocol_upgrade_height_scheduled_lifecycle.py`; `tests/test_protocol_upgrade_record_only_boundary.py`; `tests/prod/test_protocol_upgrade_execution_hardening_plan.py` | `Weall-Protocol/generated/protocol_upgrade_execution_hardening_plan_v1_5.json` | `PYTHONPATH=src python -m pytest -q tests/test_protocol_upgrade_height_scheduled_lifecycle.py tests/test_protocol_upgrade_record_only_boundary.py` | Scheduled activation records implemented | Records declaration/activation only; no arbitrary migration/apply/rollback execution. |
| Locked economics / wallet status | economics routes/runtime launch matrix; wallet status UI | economics locked tests; frontend source checks | tokenomics simulation and blocker report | `PYTHONPATH=src python -m pytest -q tests/test_wallet_treasury_governance_reputation_safety.py tests/test_civic_social_governance_fee_free_after_activation.py`; `node web/scripts/test_reviewer_critical_flows_source.mjs` | Locked/read-only status posture | Live economics, fees, rewards, transfers, and treasury spend remain false/unclaimed. |
| Helper execution safety posture | helper runtime modules; launch matrix; helper hardening plan | helper restart/replay/merge tests; production helper topology test | `Weall-Protocol/generated/production_helper_topology_hardening_plan_v1_5.json` | `PYTHONPATH=src python -m pytest -q tests/test_helper_restart_equivalence.py tests/test_helper_replay_merge_adversarial.py tests/prod/test_helper_production_safety_checklist.py` | Experimental/gated; production helper execution disabled | Helpers do not replace consensus; production helper topology remains open future hardening. |
| Frontend reviewer surfaces | `web/src/pages/*`; `web/src/components/*`; `web/scripts/*` | source checks and Playwright specs where backend is available | frontend evidence docs/source scripts | `cd web && npm run typecheck && npm run test:reviewer-critical-source && npm run test:accessibility-source` | Reviewer UI source coverage | Frontend state is not protocol authority; backend availability affects rendered E2E. |
| Accessibility current posture | `web/src/styles.css`; shell/forms/status components; accessibility checklist | `web/scripts/test_accessibility_source.mjs`; reviewer-critical source check | N/A | `cd web && npm run test:accessibility-source` | Basic source-level accessibility posture | Not a full WCAG compliance claim; manual and rendered audits remain needed. |

## Major protocol surfaces

| Surface | Current implemented/reviewer surface |
|---|---|
| Account/profile | Account creation, profile reads, public account surfaces, native PoH state, and public API redaction checks. |
| Public social | Public posts, public comments, media-backed content, activity notices, and transaction-status visibility. |
| Public groups | Publicly readable group content with membership-gated posting, commenting, voting, moderation, invitation, and administration. |
| Governance | Public proposal, voting, block-height lifecycle progression, tally/finalization records, and record-only protocol-upgrade metadata. |
| Disputes/reviews | Public report/review surfaces, block-height lifecycle progression, reviewer assignments, votes, receipts, outcomes, and restricted private identity evidence boundaries. |
| Transaction lifecycle | Canonical tx index, admission/status surfaces, mempool/block evidence, receipts, and current tx canon checkpoint of 236 tx types, version 1.25.0. |
| Node/operator surfaces | Readiness/status endpoints, signed seed/validator discovery evidence, validator authority gating, observer/operator status, secret guard, and release hygiene checks. |
| Observer boot | `WEALL_PUBLIC_TESTNET=1 bash scripts/boot_public_observer_testnet.sh` with signed/pinned registry and chain commitment checks. |
| External evidence packages | Clean-clone/open-download observer transcript, cross-machine replay transcript, independent validator/operator transcript, real storage/IPFS transcript, legal attestation, upgrade hardening proof, and helper-topology proof. |

## What is intentionally disabled

These are deliberately not claimed by the current repository state:

- **Live economics:** fees, transfers, rewards, treasury spend, and slashing remain locked or non-live for launch claims.
- **Public validator/BFT readiness:** public validator joining, public validator safety, and public multi-validator BFT readiness require independent operator evidence.
- **Automatic upgrades:** protocol upgrade records are public deterministic metadata only; automatic software apply is not enabled.
- **Executable migrations/rollbacks:** migration and rollback execution are not enabled by the current upgrade posture.
- **Production helper execution:** helper artifacts and hardening plans do not enable production helper execution.
- **Public storage-market readiness:** storage/IPFS surfaces and tests do not prove a public storage-provider market.
- **Legal approval:** legal/compliance documents are drafts pending counsel or controlled external review.
- **Private protocol-native content:** encrypted DMs, private groups, member-only-readable protocol-native group content, and opaque consensus-affecting social payloads are unsupported.

## Public-only truth boundary

Protocol-native social, civic, governance, moderation, dispute, group, reputation, validator/operator, and protocol-state activity is publicly inspectable. Group membership may gate participation or administration, but it must not gate read visibility for protocol-native group content.

Public-testnet discovery uses signed/pinned seed-registry and endpoint evidence, not hosting-provider trust. Endpoint advertisements are connection hints and freshness evidence; they do not grant validator status.

## Reviewer starting points

1. `Weall-Protocol/docs/reviewer/CURRENT_READINESS_STATEMENT.md`
2. `Weall-Protocol/docs/reviewer/EVIDENCE_INDEX.md`
3. `Weall-Protocol/docs/reviewer/README_TO_IMPLEMENTATION_TRACEABILITY.md`
4. `Weall-Protocol/docs/reviewer/PUBLIC_BETA_BLOCKER_STATUS.md`
5. `Weall-Protocol/docs/testnet/FINAL_PUBLIC_OBSERVER_CONTROLLED_TESTNET_GO_GATE.md`
6. `Weall-Protocol/docs/testnet/PUBLIC_OBSERVER_QUICKSTART.md`
7. `Weall-Protocol/docs/PRODUCTION_POSTURE.md`
8. `RELEASE_CHECKLIST.md`

## Product direction

WeAll is being built as a familiar public social application with deterministic protocol state underneath: public posting, groups, community decisions, reports/reviews, account verification, and trusted responsibilities. The frontend is intentionally moving toward plain human language rather than crypto-native dashboard language, while the backend remains responsible for deterministic state, evidence, and fail-closed protocol boundaries.

## License

This repository is licensed under the Mozilla Public License 2.0. See `LICENSE` for the full license text.
