# WeAll NLnet Milestone Reviewer Guide

Status: NLnet resubmission reviewer guide for a pre-public-testnet implementation.

This document is intentionally conservative. It does not claim public mainnet readiness, public multi-validator BFT readiness, live economics, or a fully self-bootstrapped public Proof-of-Humanity network.

For the authoritative truth boundary, see `docs/TRUTH_BOUNDARY.md`.

For command evidence and captured outputs, see `docs/NLNET_EVIDENCE_INDEX.md`.

## Current resubmission posture

WeAll should be reviewed as a serious open-source Layer 1 coordination protocol implementation seeking support to move from private/local and external-observer rehearsal readiness into public testnet readiness.

The repository currently exposes:

- generated transaction canon artifacts and contract-map coverage;
- release hygiene, secret scanning, and dependency-lock gates;
- account custody and recovery-file frontend flows;
- signed transaction/session wiring;
- Proof-of-Humanity async and live verification flows;
- content, media, group, dispute/review, appeal/procedure, and governance surfaces;
- local block-production proof with state-root and receipt-root evidence;
- observer-only authority posture with validator signing, BFT, helper authority, and block-loop authority disabled;
- visible/locked tokenomics, wallet, tips, transfers, treasury allocation, and reward accounting invariants.

The repository does **not** yet claim:

- public mainnet readiness;
- public multi-validator BFT readiness;
- public adversarial validator readiness;
- live economics;
- public user launch readiness;
- fully production-grade moderation/governance;
- first trusted external observer readiness unless the remote signed observer gate has been run and captured against a real genesis API.

## What is implemented enough to review

### Protocol/release evidence

- Transaction canon artifacts are checked by `scripts/check_tx_canon_artifacts.py`.
- Release hygiene is checked by `scripts/verify_release_tree.sh`.
- Release-relevant secret scanning is checked by `scripts/secret_guard.sh`.
- Dependency lock posture is checked by `scripts/verify_release_dependencies.sh`.
- The targeted reviewer suite is run by `scripts/reviewer_production_readiness_gate.sh`.

### External observer evidence

- Local observer readiness is checked by `scripts/local_observer_readiness_gate.sh`.
- Observer authority lock is checked by `scripts/external_observer_authority_lock_gate.sh`.
- The combined first-external-observer gate is `scripts/first_external_observer_reproducibility_gate.sh`.

Important boundary:

Passing the combined gate without remote/signed environment variables proves local preconditions only. Signed external observer onboarding is proven only when both of these are enabled against a real genesis API:

```bash
export WEALL_RUN_TWO_MACHINE_OBSERVER_PREFLIGHT=1
export WEALL_RUN_SIGNED_OBSERVER_ONBOARDING=1
```

### Frontend evidence

From the outer repository root:

```bash
cd web
npm ci
npm run typecheck
```

Frontend typecheck proves type safety. It does not replace browser E2E proof for account recovery, PoH, content, review, governance, or wallet flows.

### Local block-production evidence

From `Weall-Protocol/`:

```bash
PYTHONPATH=src python3 scripts/production_block_production_rehearsal_gate.py
```

This proves local block-production evidence only. It does not prove public multi-validator BFT.

The expected readiness object must preserve this boundary:

```text
'public_multi_validator_bft_ready': False
```

## Commands for an outside reviewer

From the backend root `Weall-Protocol/`:

```bash
python3 -B -S scripts/check_tx_canon_artifacts.py
bash scripts/secret_guard.sh
bash scripts/verify_release_dependencies.sh
bash scripts/verify_release_tree.sh
bash scripts/reviewer_production_readiness_gate.sh
```

From the outer repo root for frontend checks:

```bash
cd web
npm ci
npm run typecheck
```

After frontend checks, clean generated artifacts before release-tree verification:

```bash
rm -rf node_modules dist tsconfig.tsbuildinfo
```

From the backend root for observer local-precondition checks:

```bash
bash scripts/local_observer_readiness_gate.sh
bash scripts/external_observer_authority_lock_gate.sh
```

For the full first-external-observer proof, run against a real genesis API and public observer bundle:

```bash
export WEALL_NODE_OPERATOR_ONBOARDING_BUNDLE=/path/to/public-observer-bundle.json
export WEALL_CHAIN_MANIFEST_PATH=/path/to/weall-genesis.json
export WEALL_GENESIS_API_BASE=http://GENESIS_HOST:8000
export WEALL_ALLOW_PRIVATE_GENESIS_API=1
export WEALL_RUN_TWO_MACHINE_OBSERVER_PREFLIGHT=1
export WEALL_RUN_SIGNED_OBSERVER_ONBOARDING=1
bash scripts/first_external_observer_reproducibility_gate.sh "$WEALL_NODE_OPERATOR_ONBOARDING_BUNDLE"
```

Use `WEALL_ALLOW_PRIVATE_GENESIS_API=1` only for private LAN rehearsal. Public testnet deployment requires a public security posture that is not proven by this private LAN command.

## Required evidence to capture before NLnet submission

Save command transcripts for:

1. Git identity: branch, commit hash, status, recent log.
2. Tx canon sync.
3. Secret guard.
4. Release tree hygiene.
5. Dependency lock verification.
6. Targeted reviewer gate.
7. Frontend `npm ci` and `npm run typecheck`.
8. Local observer readiness.
9. Observer authority lock.
10. Local block-production proof with `public_multi_validator_bft_ready: False`.
11. First external observer remote/signed proof, if it has actually been run.

If item 11 has not been run yet, the correct claim is:

> Local observer preconditions and authority lock pass. Signed remote external observer onboarding remains the next proof before claiming first trusted external observer readiness.

## NLnet milestone plan

### Milestone 1: Clean clone and external observer onboarding hardening

Objective: make a new reviewer/tester able to clone, boot, and safely run an observer without validator authority.

Current evidence:

- Release hygiene gates exist.
- Dependency lock verification exists.
- Local observer readiness gate exists.
- Observer authority lock gate exists.
- Tester boot scripts and observer docs exist.

Work remaining:

- Run and capture real remote signed observer onboarding against a genesis API.
- Add a clean environment full-pytest dependency preflight.
- Split or stage reviewer evidence so reviewers can see exactly what passed.

Deliverables:

- Clean clone boot transcript.
- Signed observer onboarding transcript.
- Observer authority lock report.
- External observer runbook.

Acceptance criteria:

- A fresh machine can prepare an observer.
- Observer posture cannot produce blocks or sign as validator.
- Signed observer onboarding is submitted to genesis and confirmed.

Truth boundary: external observer readiness only; not public BFT or mainnet readiness.

### Milestone 2: Account custody, PoH verification, and onboarding UX

Objective: make account creation, recovery, async verification, and live verification reliable for outside testers.

Current evidence:

- Recovery file creation/verification exists.
- Restore flow exists.
- Signed transaction/session path exists.
- Async/live PoH txs, routes, and frontend surfaces exist.

Work remaining:

- Browser E2E proof for account creation, recovery verification, restore, and registration.
- Full PoH async/live external rehearsal.
- Media/live-room reliability proof.

Deliverables:

- Account custody E2E proof.
- PoH async E2E proof.
- PoH live E2E proof.
- Reviewer queue/runbook.

Acceptance criteria:

- Tester can create account, save recovery, restore after browser restart, submit verification, receive final tier update, and unlock gated actions.

Truth boundary: testnet PoH readiness, not final public identity infrastructure.

### Milestone 3: Content, groups, dispute/review, and governance testnet flows

Objective: prove the social/governance loop from verified user action through network review and governance.

Current evidence:

- Content, group, dispute, review, appeal/procedure, and governance txs/routes/surfaces exist.
- Targeted tests and frontend source checks exist.

Work remaining:

- Full integrated verified-user demo: post, group join, report, review, appeal, governance proposal, comment, vote, finalize.
- External reviewer UX hardening.

Deliverables:

- PoH-to-content/group proof.
- Report-to-dispute-to-appeal proof.
- Proposal-to-vote-to-finalization proof.
- Docs clarifying network review versus centralized deletion.

Acceptance criteria:

- Tier-gated user can post and join groups.
- Report creates a reviewable case.
- Vote/finalization creates traceable receipts.
- Governance voting respects PoH eligibility.

Truth boundary: public testnet social/governance flows, not finalized production constitutional governance.

### Milestone 4: Locked tokenomics, wallet, tips, treasury, and reward accounting testnet proof

Objective: keep economics locked while proving the accounting model is safe and testnet-activatable.

Current evidence:

- Economics activation gate exists.
- Transfers/tips/rewards are locked before activation.
- Reward mint/distribution, max supply, and tip-index invariants are tested.
- Wallet and tipping frontend source checks exist.

Work remaining:

- Ensure every public doc says visible/locked, not live.
- Add activated test-state accounting proof.
- Add treasury authority/spend boundary proof.
- Harden wallet UI status language.

Deliverables:

- Locked tokenomics audit doc.
- Activated test-state accounting proof.
- Wallet/tipping UX proof.
- Treasury authority tests.

Acceptance criteria:

- Transfers/tips/rewards fail before activation.
- Activated test state conserves supply.
- Duplicate mint/distribute cannot inflate supply.
- Civic/social/governance actions remain fee-free.

Truth boundary: locked testnet tokenomics only; not live economics.

### Milestone 5: Deterministic block progression, validator promotion, and multi-node/BFT testnet readiness

Objective: move from local block proof toward safe public multi-validator testnet readiness.

Current evidence:

- Local block-production proof exists.
- BFT/HotStuff modules and validator tx surfaces exist.
- Observer-to-validator scripts/tests exist in parts.

Work remaining:

- Multi-node deterministic block progression.
- Validator promotion E2E.
- HotStuff/BFT convergence proof.
- Equivocation, partition/rejoin, restart/replay, and state-root convergence tests.

Deliverables:

- Multi-validator local BFT script.
- Validator promotion runbook.
- BFT safety/liveness report.
- State convergence proof.

Acceptance criteria:

- Multiple validators finalize the same blocks.
- Malicious/equivocating behavior does not produce accepted divergence.
- Restarted nodes reproduce the same state.

Truth boundary: public multi-validator BFT readiness only after adversarial gates pass.

### Milestone 6: Documentation, reproducibility, security hardening, and external tester reporting

Objective: make the project reviewable by NLnet, external testers, and future contributors.

Current evidence:

- Release/check scripts exist.
- Known limitations and reviewer docs exist.
- Security/release gates exist.

Work remaining:

- Keep the truth boundary synchronized with implementation.
- Maintain evidence index with commit-bound transcripts.
- Add external tester reporting template.
- Add public deployment security checklist.

Deliverables:

- `docs/TRUTH_BOUNDARY.md`.
- `docs/NLNET_EVIDENCE_INDEX.md`.
- Public testnet prep checklist.
- External tester report template.
- CI-backed reviewer gate evidence.

Acceptance criteria:

- NLnet can see what is implemented, visible/locked, scaffolded, and unfinished.
- Testers can reproduce flows without private context.
- Docs match code/tests/scripts.

Truth boundary: documentation/reviewer readiness; not feature completion by itself.

## Authority boundaries

The backend/chain state is authoritative. The frontend explains and guides only. Helpers, relay, rendezvous, gossip, IPFS/media/content storage, and UI state are non-authoritative unless deterministic protocol state commits the relevant hash, receipt, role, badge, assignment, or transaction result.

## Work after resubmission

It is safe to continue development during NLnet review if the submitted commit and evidence are preserved.

Recommended practice:

1. Create a tag for the submitted state.
2. Save evidence transcripts under `audit-metadata/nlnet-resubmission-YYYY-MM-DD/`.
3. Continue development after submission.
4. If NLnet asks questions, distinguish submitted evidence from later improvements.
5. Do not retroactively imply later commits were part of the original submission.
