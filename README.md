# WeAll Protocol

WeAll is an experimental public civic protocol and social coordination application. This repository contains the backend node/runtime, public API, frontend, operator scripts, generated evidence artifacts, and reviewer-facing documentation for the current controlled rehearsal candidate.

Current allowed claim: **WeAll is ready for controlled internal/public-observer rehearsal candidate, with public beta readiness still blocked by explicit external evidence, counsel-review, upgrade-execution, storage, validator, replay, observer, and helper-topology gates.**

This repository should be reviewed as an implementation under active hardening. It is not a public beta, public mainnet, public validator, public multi-validator BFT, live-economics, automatic-upgrade, production-helper, legal-approval, or public storage-market readiness claim.

## Current status

| Surface | Status | Reviewer meaning |
|---|---:|---|
| Controlled internal/public-observer rehearsal candidate | GO | Repository artifacts and local gates support the next bounded two-node/public-observer rehearsal candidate. |
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
