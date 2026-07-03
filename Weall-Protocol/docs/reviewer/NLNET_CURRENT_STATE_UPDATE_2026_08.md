# WeAll NLnet / reviewer current-state update

Status: late-stage pre-public-testnet / mainnet-readiness hardening path.

This update is intentionally conservative. It describes the strongest current repository state without claiming public mainnet readiness, live economics, or completed public multi-validator BFT readiness.


## Controlled-testnet go-gate status

The controlled-testnet go-gate manifest is now allowed to be **ready to run** without claiming public beta readiness. This is a deliberate claim split:

- `controlled_testnet_go_gate_ready_to_run=true` means the deterministic manifest, bounded proof artifacts, launch-disabled high-risk features, public-only audit, and release-evidence inventory are fresh enough to run the controlled rehearsal gate.
- `public_beta_ready=false` remains mandatory until external validator/operator transcripts, storage/IPFS operator transcripts, public observer open-download evidence, rendered frontend journey evidence, and legal/compliance review are attached.

The public beta blocker report classifies each blocker as closed artifact/docs, external evidence required, mainnet-readiness hardening, or UX/observability follow-up. Open blockers are not hidden; they are the funded hardening path.

## Current project status

WeAll is an open-source deterministic civic coordination protocol. The repository now contains implementation-stage code, tests, generated artifacts, and operator/reviewer runbooks for public civic activity, governance, disputes, reputation, observer/testnet tooling, tokenomics scaffolding, and protocol-safety boundaries.

The project has moved beyond an early prototype posture into late pre-public-testnet hardening. Remaining funded work should be framed as hardening, validation, independent reproducibility, operator readiness, security review preparation, public observer expansion, UX/accessibility completion, and mainnet-readiness work.

## Proposal history and public-only redesign note

Earlier proposal language may have referenced encrypted messaging, private communication, or private group surfaces. That language is stale for the current implementation direction.

The current protocol boundary is public-only:

> All protocol-native social, civic, governance, moderation, dispute, group, reputation, validator/operator, and protocol-state activity must be publicly inspectable. Group membership may gate posting, commenting, voting, moderation, invitation, administration, or participation rights, but it must not gate read visibility of protocol-native social or civic content.

This does not mean exposing raw Proof-of-Humanity identity documents, raw face/video evidence, government identifiers, sensitive liveness material, account recovery secrets, private keys, or private local UI preferences.

## Current implemented evidence

Reviewer evidence should be taken from the submitted commit, not from stale transcripts. The most relevant evidence areas are:

- public-only protocol audit and regression tests;
- public observer/testnet chain identity and seed-registry checks;
- observer authority boundary checks;
- governance and dispute lifecycle tests;
- protocol upgrade record-only and scheduled-activation tests;
- economics locked-by-default tests and docs;
- release hygiene, secret guard, generated artifact checks;
- local sustained-load harness evidence when captured for the submitted commit.

Recommended commands from `Weall-Protocol/`:

```bash
git rev-parse --abbrev-ref HEAD
git rev-parse HEAD
git status --short
git diff --check
PYTHONPATH=src python -m compileall -q src/weall
bash scripts/secret_guard.sh
PYTHONPATH=src python scripts/check_v15_public_readiness_artifacts.py
PYTHONPATH=src python scripts/check_release_hygiene_v1_5.py
python3 -B -S scripts/check_tx_canon_artifacts.py
pytest -q \
  tests/test_protocol_upgrade_record_only_boundary.py \
  tests/test_protocol_upgrade_height_scheduled_lifecycle.py \
  tests/test_governance_due_height_trust_boundary.py \
  tests/test_dispute_height_lifecycle_boundaries.py \
  tests/test_group_governance_contract.py \
  tests/test_public_only_protocol_redesign.py \
  tests/prod/test_public_observer_boot_and_evidence_scripts.py \
  tests/prod/test_observer_cannot_enable_validator_signing.py
```

Run the full backend and frontend suites where feasible and attach the full transcript when claiming those results.

## What has been de-risked pre-grant

- The implementation now has a strict public-only civic boundary.
- Protocol-native encrypted/private social surfaces are removed or fail closed.
- Group membership is constrained to participation gating, not read visibility gating.
- Economics remain locked/inactive unless a governed activation path satisfies its gates.
- Public observer/testnet bootstrap artifacts and runbooks exist.
- Protocol upgrade records are bounded: governance may schedule public upgrade metadata at a deterministic future block height, but automatic software apply/migration/rollback remains disabled.
- Governance and dispute flows use deterministic block-height procedure where protocol state is affected.
- Local performance harnessing has become part of the evidence path, with local-harness claims separated from public-network claims.

## Revised grant / rescope framing

Pre-grant development has reduced the original public-testnet readiness risk. If selected for further review, the funded work can be scoped toward mainnet-readiness hardening: deterministic upgrade safety, adversarial multi-node validation, public observer testnet expansion, operator runbooks, UX/accessibility completion, release/security hardening, and independent reproducibility.

## Mainnet-readiness hardening path

The next funded milestones should focus on:

1. deterministic upgrade artifact verification, compatibility windows, migration vectors, and rollback coordination runbooks;
2. adversarial multi-node validation and public observer expansion beyond local/same-machine rehearsal;
3. governance/dispute protocol procedure E2E evidence through API and UI;
4. operator runbooks for seed registry rotation, validator promotion, incidents, recovery, and evidence capture;
5. frontend UX coherence for the minimum civic loop;
6. accessibility and onboarding review;
7. independent security/release review;
8. performance evidence split into local harness, closed testnet, and public network categories.

## Known limitations

Do not claim these are complete unless fresh evidence from the submitted commit proves them:

- public mainnet readiness;
- public multi-validator BFT readiness;
- live economics activation;
- automatic protocol upgrade software delivery;
- deterministic migration/rollback execution;
- global 2350 TPS throughput;
- closed testnet equivalence to public mainnet;
- independent third-party reproducibility.

## Exact reviewer setup path

Primary path:

1. clone the repository;
2. create Python virtualenv;
3. install backend dependencies from lockfiles;
4. run release hygiene and generated artifact checks;
5. run targeted public-only, observer, governance/dispute, protocol-upgrade, and economics-lock tests;
6. run frontend install/typecheck/source contract checks where frontend is in scope;
7. capture all outputs with branch, commit, and `git status --short`.

Zip/export path:

- record that Git commit identity is unavailable in the export;
- request or attach the source checkout commit hash separately;
- still run the same checks against the exported tree and mark the evidence as zip-derived.

## Exact evidence files

Key reviewer files include:

- `docs/PUBLIC_ONLY_PROTOCOL.md`
- `docs/PROTOCOL_UPGRADE_RECORD_ONLY_BOUNDARY.md`
- `docs/audits/closed_testnet_rehearsal_readiness_v1_5.md`
- `docs/audits/late_stage_nlnet_public_testnet_gap_inventory_v1_5.md`
- `docs/REVIEWER_EVIDENCE_INDEX.md`
- `docs/KNOWN_LIMITATIONS.md`
- `generated/public_only_protocol_audit_v1_5.json`
- `generated/release_evidence_manifest_v1_5.json`
- `generated/public_beta_blocker_report_v1_5.json`
- sustained-load evidence files under `rehearsal-evidence/` if present for the submitted commit

## Performance wording boundary

Allowed when matching evidence exists:

> Local sustained-load testing reached approximately 2350 TPS under the documented test harness.

Not allowed:

> WeAll is globally ready for 2350 TPS.

Not allowed:

> WeAll is mainnet-scale.

## Current reviewer conclusion

The current repository should be presented as serious implementation-stage public civic infrastructure that still needs grant-funded hardening and independent validation. The strongest truthful claim is not “finished”; it is “the core direction has been de-risked enough that remaining work is bounded, auditable, and appropriate for mainnet-readiness hardening.”
