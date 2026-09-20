# Current Readiness Statement

Current allowed claim: **WeAll is a pre-public-testnet protocol implementation under active hardening, with local/devnet/public-observer-oriented evidence present and public beta readiness still blocked by explicit external observer, replay, validator/operator, storage, legal, upgrade-execution, and helper-topology gates. Independent cryptographic review remains a separate launch gate.**

This statement is tied to the current generated readiness artifacts rather than pass-number history. It is intentionally conservative and must not be read as public beta, public mainnet, public validator, public multi-validator BFT, live-economics, automatic-upgrade, production-helper, completed production cryptographic audit, production post-quantum security, legal-approval, or public storage-market readiness.

## Summary verdict

| Claim | Status | Evidence boundary |
|---|---:|---|
| Controlled-testnet mechanism completion | NO-GO | Production helper state-root/restart equivalence is not yet proven; local reviewer/observer rehearsal remains available. |
| Bounded public observer launch claim | NO-GO | `AUD-628-P1-001` external rendered observer transcript is still missing. |
| Public beta readiness | NO-GO | `public_beta_ready` must remain `false`. |
| Public mainnet readiness | NO-GO | Mainnet-hardening gates remain open. |
| Public multi-validator BFT/public validator safety | NO-GO | Independent validator/operator evidence remains missing. |
| Live economics readiness | NO-GO | Economics are locked; fees, transfers, rewards, slashing, and treasury spend are not live launch claims. |
| Automatic protocol upgrade readiness | NO-GO | Upgrade records are deterministic metadata only; automatic apply, executable migrations, and executable rollbacks are not enabled. |
| Production helper execution readiness | NO-GO | Helper topology remains a future hardening/evidence gate. |
| Production cryptographic audit / post-quantum security | NO-GO | Fresh profile-aware post-transition rehearsal evidence, browser/local signing-boundary review, helper/evidence-signing production gates, and external cryptographic review remain required. |
| Legal/compliance approval | NO-GO | Counsel or controlled legal/compliance attestation remains required. |
| Public storage-market readiness | NO-GO | Real storage/IPFS operator transcript remains required. |

Current tx-canon count/version: read directly from `generated/tx_index.json`; no duplicated mutable checkpoint is authoritative in this document.

## Blocker-count truth

Blocker counts are mutable generated facts. Reviewers must read them directly from
`generated/public_beta_blocker_report_v1_5.json` and
`generated/final_public_observer_controlled_testnet_go_gate_v1_5.json`. This document
intentionally does not duplicate the numeric totals, because duplicated prose counts
become stale when blockers open or close. `public_beta_ready` must remain `false` while
any still-open blocker remains.

## What is implemented repository evidence

Repository evidence currently includes generated artifacts, tests, scripts, and docs that make the bounded rehearsal package inspectable:

- public beta blocker inventory and count semantics;
- release evidence manifest and claim boundaries;
- final controlled/public-observer go-gate artifact;
- API contract maps and response vectors;
- transaction-canon artifacts whose current count/version are read from `generated/tx_index.json`;
- public-only protocol docs and tests;
- governance and dispute block-height lifecycle surfaces;
- protocol-upgrade record-only surfaces;
- observer boot scripts and public-testnet chain/registry checks;
- helper, storage, public validator, replay, and legal evidence templates/hardening plans.

Repository evidence supports bounded local/devnet/public-observer-oriented rehearsal and review. Controlled-testnet mechanism completion remains NO-GO until production helper state-root/restart equivalence is proven; local evidence cannot replace external operator transcripts, counsel/control attestations, or future execution hardening proof.

## What is generated artifact evidence

Canonical generated files include:

- `generated/public_beta_blocker_report_v1_5.json`;
- `generated/release_evidence_manifest_v1_5.json`;
- `generated/final_public_observer_controlled_testnet_go_gate_v1_5.json`;
- `generated/api_contract_map_v1_5.json`;
- `generated/api_response_vectors_v1_5.json`;
- `generated/failure_code_registry_v1_5.json`;
- `generated/tx_index.json`;
- `generated/tx_contract_map.json`.
- `docs/reviewer/README_TO_IMPLEMENTATION_TRACEABILITY.md` for README claim-to-implementation mapping.

Generated files are evidence of repository consistency. They are not substitutes for missing external proof.

## External evidence still required

| Blocker | Remaining evidence |
|---|---|
| `AUD-618-P0-001` | Independent controlled validator/operator transcript. |
| `AUD-618-P0-002` | Real counsel or controlled legal/compliance attestation. |
| `AUD-618-P0-003` | Future executable upgrade staging/rollback proof. |
| `AUD-633-P0-004` | Fresh profile-aware post-transition rehearsal evidence, browser/local signing-boundary review, helper/evidence-signing production gate, and external cryptographic review. |
| `AUD-618-P1-003` | External/two-machine replay transcript. |
| `AUD-618-P1-004` | Real storage/IPFS daemon/operator transcript. |
| `AUD-618-P1-005` | Future production helper topology proof. |
| `AUD-628-P1-001` | External clean-clone/open-download/state-sync/frontend rendered journey transcript. |

## Major protocol surfaces now reviewable

- **Account/profile:** account/profile state, public reads, public API redaction, and native PoH state.
- **Public social:** public posts, comments, content detail, media evidence, notices, and tx status surfaces.
- **Public groups:** public reads with member-gated participation and administration.
- **Governance:** public proposal/vote/finalization flow with block-height lifecycle progression.
- **Disputes/reviews:** public report/review surfaces, assignments, votes, receipts, outcomes, and restricted evidence boundaries.
- **Transaction lifecycle:** canonical tx index, admission/status, mempool/block/receipt evidence, with mutable canon counts read from `generated/tx_index.json`.
- **Node/operator surfaces:** readiness/status, signed discovery evidence, validator authority gating, observer status, release hygiene, and secret guard.
- **Observer boot:** `WEALL_PUBLIC_TESTNET=1 bash scripts/boot_public_observer_testnet.sh` runbook with signed/pinned registry checks.
- **External evidence packages:** proof templates under `docs/proofs/` and testnet runbooks under `docs/testnet/`.

## Verification path

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

If README or verification docs changed, run:

```bash
PYTHONPATH=src python scripts/check_release_hygiene_v1_5.py
```

## Final communication boundary

Do not claim public beta readiness, public mainnet readiness, public multi-validator BFT readiness, public validator safety, live economics readiness, automatic protocol upgrade readiness, executable migration readiness, rollback execution readiness, production helper execution readiness, completed production cryptographic audit, production post-quantum security, quantum-proof security, legal/compliance approval, public storage-market readiness, complete anti-Sybil/collusion detection, or complete public identity infrastructure.

## Reviewer trust posture files added for this boundary

- `docs/reviewer/DIRECT_MESSAGE_TRANSACTION_QUARANTINE.md` — verifies direct/private/encrypted messaging is not in the active public-testnet tx canon and remains out of scope.
- `docs/testnet/OBSERVER_PROOF_POSTURE_AND_CAPTURE.md` — separates local observer proof, same-machine dual-node proof, and remote signed observer proof.
- `docs/reviewer/HELPER_PRODUCTION_SAFETY_CHECKLIST.md` — makes helper execution safety topics and disabled production posture verification-visible.
- `docs/reviewer/ACCESSIBILITY_REVIEW_CHECKLIST.md` — states basic source-level accessibility coverage without claiming full WCAG compliance.

### Pass 33 signature-profile truth boundary

WeAll is a pre-public-testnet protocol implementation under active hardening. The controlled-testnet signing profile has transitioned to profile-aware `pq-mldsa-v1` ML-DSA signing for protocol authority surfaces covered by this pass; `legacy-ed25519-v1` is disabled for protocol authority and retained only as a fail-closed inventory/migration identifier. This does not claim completed production cryptographic audit, mainnet readiness, live economics, public multi-validator BFT readiness, production helper execution readiness, production constitutional governance readiness, or public beta readiness. Public-only protocol surfaces remain public.
