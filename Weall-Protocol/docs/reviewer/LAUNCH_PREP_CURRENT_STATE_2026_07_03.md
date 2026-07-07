# WeAll launch-prep current state — 2026-07-03

This note bounds the current public observer / closed-testnet launch-prep slice.
It is reviewer-facing documentation, not a public beta, mainnet, production, or public multi-validator BFT readiness claim.

## Frontend civic loop

The frontend now emphasizes the average-user loop: account and verification state, public posting, public groups, decisions/governance, reports/disputes, reviews, activity/reputation, node/testnet status, and economics status.
Empty states and home-page copy keep the review posture explicit: economics remain locked by default and public observer / closed-testnet flows do not activate fees, rewards, transfers, or live economics.

## Block-height lifecycle model

Protocol-state truth must be derived from block height. UI estimates may help humans understand timing, but they must not mutate protocol truth from local wall-clock state. Governance scheduler follow-up transactions use `_due_height` only when emitted through the SYSTEM queue; user payloads cannot forge protocol lifecycle height.

## Protocol upgrade model

Protocol upgrade declarations and activations are governance-parent-bound SYSTEM records. Approved upgrades schedule a deterministic future `activation_height`, publish a public activation record, and remain record-only. They do not fetch artifacts, apply software, execute migrations, restart nodes, roll back state, or activate economics.

## Constitution upgrade model

Constitution upgrade declarations record public metadata: constitution version, document hash, traceability hash, optional rights-floor hash, governance parent, and future activation height once approved. The current implementation is record-only. It does not fetch documents, expose raw identity evidence, or allow rights-floor bypass fields.

## Multi-option proposal model

Multi-option proposals use canonical deterministic `option_id` values. Votes reference option IDs, not mutable labels. The current bounded model is public record-only plurality: abstain is deterministic, invalid option votes are rejected, duplicate votes replace the signer’s prior vote, and ties publish tied option IDs in lexicographic order with no automatic winner.

## Emissary election model

Group-scale emissary elections remain governed through the same governance mechanics scaled to the group. Existing STV and window tests cover deterministic candidate registration, multi-seat selection, tie handling, activation height, and term windows. A later frontend evidence pass should make election records easier for reviewers to inspect.

## Public-only boundary

All protocol-native social, civic, governance, moderation, dispute, group, reputation, validator/operator, protocol-upgrade, constitution-upgrade, and protocol-state activity remains publicly inspectable. Group membership may gate participation rights but not read visibility. Raw private identity evidence remains protected and must not be exposed in public protocol surfaces.

## Claims not made

This slice does not claim public beta readiness, public mainnet readiness, production safety, public multi-validator BFT completeness, live economics activation, or automatic protocol software upgrades.

## Targeted evidence commands

```bash
PYTHONPATH=src pytest -q \
  tests/test_governance_multi_option_voting.py \
  tests/test_protocol_upgrade_height_scheduled_lifecycle.py \
  tests/test_constitution_upgrade_height_scheduled_lifecycle.py \
  tests/test_group_emissary_election_windows.py \
  tests/test_group_emissary_elections_stv.py \
  tests/test_public_only_protocol_redesign.py \
  tests/test_governance_due_height_trust_boundary.py \
  tests/test_governance_system_queue_autoprogress.py \
  tests/test_tx_schema_governance_dispute_receipts.py

node ../web/scripts/test_launch_prep_governance_source.mjs
node ../web/scripts/test_rendered_civic_loop_source.mjs
node ../web/scripts/test_public_only_protocol_source.mjs
PYTHONPATH=src python3 scripts/check_tx_canon_artifacts.py
PYTHONPATH=src:scripts python3 scripts/check_v15_public_readiness_artifacts.py
PYTHONPATH=src:scripts python3 scripts/gen_public_only_protocol_audit_v1_5.py --check
PYTHONPATH=src:scripts python3 scripts/gen_failure_code_registry_v1_5.py --check
PYTHONPATH=src:scripts python3 scripts/gen_release_evidence_manifest_v1_5.py --check
PYTHONPATH=src:scripts python3 scripts/gen_public_beta_blocker_report_v1_5.py --check
bash scripts/secret_guard.sh
```

Run release hygiene only after committing or from a clean tree; the checker intentionally fails on a dirty worktree.
