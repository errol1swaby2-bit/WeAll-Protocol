# Fresh-genesis complete evidence regeneration — pre-testnet release gate

**Status: PLANNED / NOT SATISFIED.** This is a pre-testnet acceptance specification, not evidence that a clean run has already succeeded. The development chain's prior transaction history is deliberately **not** the testnet's canonical chain history.

## Development sequence before the clean-genesis gate

The fresh-genesis acceptance steps below are **future release steps**, not the immediate work queue. The development completion order is:

1. **Complete and connect all missing or incorrectly wired backend and protocol subsystems.** Preserve unresolved constitutional semantics and security gates rather than silently implementing speculative authority.
2. **Exercise canonical end-to-end integrations** across protocol domains, transaction admission, executor, consensus, networking, persistence and storage.
3. **Revise and connect the frontend**, including layout, navigation, accessibility, browser signing, backend integration and actual user/operator journeys.
4. **Reconcile and comprehensively update all documentation against the revised architecture, implemented behavior and explicit decisions** using [the architecture/documentation reconciliation gate](../reviewer/ARCHITECTURE_DOCUMENTATION_RECONCILIATION_GATE.md). This is a distinct required phase **after frontend completion and before full-system audit**, not a final cosmetic cleanup.
5. **Conduct a full protocol and constitutional audit** against the newly reconciled design, running system, tests and UX. Any audit repairs that change architecture or behavior reopen impacted documentation and verification.
6. **Freeze reviewed software and candidate genesis**, then perform the fresh clean-chain, complete evidence regeneration and independent replay/consensus checks defined below before launch.

Phases 4–6 are not completed; the documentation inventory and final audit must not be labeled complete simply because existing documentation or focused tests exist.

## Authoritative scope decision

The protocol implementation, not historical developmental test-ledger state, is what must be reproducible. Before testnet activation:

1. Freeze a reviewed **exact commit**, dependency locks, transaction canon, protocol parameters, constitutional version and enabled/disabled feature matrix.
2. Construct a **new, unambiguous genesis** with newly pinned chain/network identifiers, genesis digest/state root, bootstrap authority and key-policy commitments. The intended testnet genesis must never silently reuse earlier development-chain identity or old transaction IDs.
3. Initialize participating nodes from clean databases and independently provisioned keys/identities. **Do not import** old development chain ledgers, block/receipt rows, nonce/account snapshots or transaction-history roots. Keep old materials archived out-of-band solely for engineering traceability; their historical compatibility is not a prerequisite for this new genesis.
4. Execute a complete, controlled protocol run under the frozen software and genesis. Capture each acceptance proof as an immutable, hash-indexed package attributable to that exact run and its actual nodes.
5. Restart nodes and independently replay **the newly created chain** from its genesis through the final block. Require identical canonical transaction order, receipts, state roots, block IDs/hashes, identity commitments and finality decisions across participants.
6. Regenerate every *applicable* current evidence package and readiness artifact from the fresh checkout and new run; classify each evidence item as **reproduced**, **failed**, **not run**, **not applicable (with reviewed justification)**, or **requires independent/external attestation**. No silent omissions, empty placeholders presented as completed, or copied historical PASS claims.
7. Run adversarial and fail-closed cases (forged/duplicate signatures, nonce conflict, replay/splice/cross-chain signatures, incorrect block/state commitments, PoH identity/authority bypass, duplicate jurors, minority BFT finalization and partition recovery). Preserve the exact failure receipts/transcripts.
8. Finalize the evidence inventory and obtain review of all remaining gated semantics, cryptographic/consensus authority and release-critical external evidence before the corresponding testnet/public-beta claims are made.

## Testnet identity and rehearsal distinction

A preliminary **rehearsal** may use throwaway chain IDs and synthetic keys. Its evidence establishes only bounded integration behavior; it is **not** the finalized testnet chain.

The *new testnet* must use a separately declared, uniquely pinned genesis identity and must begin with no imported development history. Pre-launch evidence may validate the candidate genesis with clean nodes; if genesis parameters, executable transaction semantics, source commit, signature policy or consensus configuration change, invalidate impacted proof claims and rerun the corresponding gates. Never silently update an evidence package in place.

## Minimum evidence families to regenerate

Use `docs/reviewer/EVIDENCE_INDEX.md`, the current `generated/release_evidence_manifest_v1_5.json`, the complete generated public-beta blocker catalog, `docs/proofs/`, available launch/reviewer runbooks, and the actual repo workflow/test inventory as the **discovery source**. Inventory their contents at the frozen commit; names below denote required *families*, not an exhaustive fixed artifact list.

| Family | New clean-run evidence required | Limit |
|---|---|---|
| Software and genesis identity | Commit, clean-clone, file/lock hashes, chain/network ID, genesis root, genesis operator/validator bootstrap, PoH mode, protocol/tx-canon versions | A config declaration is not executed consensus evidence |
| Transactions and state | Signed actual transaction envelopes and receipts, all required transaction-family coverage/negative paths, determinism, journal/rollback comparison, old-key and nonce refusal | Test fixtures and historical old-chain TXs cannot substitute |
| PoH, reputation, civic and governance | Real onboarding/PoH verification, accountability/appeal/restore, scoped voting and execution, participant authority/reputation gates, cross-account invalid attempts | Synthetic genesis Tier-2 bootstrap alone is not independent humanity proof |
| Consensus, finality and replay | Distinct nodes, validator identities and trust domains, proposal/vote/QC source, matching roots, branch/partition/rejoin, restarts, fresh-node replay from newly created genesis | Two processes on one machine do not demonstrate independently operated multi-validator BFT |
| Storage and private data | Real Kubo/IPFS topology and CID retrieval/failure tests, confidentiality/key controls, evidence retention and data minimization | Fake IPFS or generated-only vectors are not operator evidence |
| Frontend and observer | Clean install, real browser-signed account/PoH/social/governance flows, public-only API and privacy gates, fresh observer discovery/catch-up | Source tests/typechecks alone are not rendered E2E evidence |
| Infrastructure and upgrades | Helper deterministic equivalence and failure, operator runbooks, executable upgrade/rollback only if activated, exact disabled-feature assertions | A declared disabled capability must never be counted as executed proof |
| Release and independent assessments | Public-beta blocker catalog, generated manifests, adversarial audit, external cross-machine/validator and legal/crypto evidence where required | No fabricated external/counsel attestations; NO-GO until prerequisite is actually obtained |

## Per-package identity contract

Each newly captured package must record: a stable evidence-family ID; status and claim boundary; exact repository commit and clean-tree assertion; source/tool versions and deterministic command; hashes of all input files and lockfiles; chain/network/genesis ID and initial root; participating independent identities/topology (redacted as appropriate); begin/end heights; canonical tx/receipt/block root sequence; generated output paths and SHA-256 digests; test counts; independently reproducible validation command; and named outstanding prerequisites.

A manifest must index **all** discovered packages, including failed/blocked/not-run packages. Hash the manifest after production; do not try to embed the commit that contains the manifest into a tracked generated artifact that hashes itself. Keep private keys, recovery secrets, video-biometric data and other personal evidence out of public packages; include opaque digests and controlled-location references where appropriate.

## Hard NO-GO rules

- No launch/production authority is granted by PR #77's review-only signed-opening or synthetic replay checks.
- No `ACCOUNT_BAN` or S4 enforcement without ratified, executable authority and independent decision provenance.
- No refresh or approval of the outstanding V2 semantic-review digests by merely regenerating files. They require separate adjudication.
- No transition from synthetic single-runner evidence to claims of independent finality, network PoH uniqueness, external operators or production-grade cryptography.
- No testnet-ready claim until the **new-chain** complete evidence inventory is reproduced and adjudicated under the specific launch tier being claimed. Historical development-ledger replay is optional forensic engineering work, not a required input to this replacement-chain plan.

## Executable current entry points (not a claim of completion)

Start with the current `docs/testnet/TESTNET_LAUNCH_CHECKLIST.md`, `docs/reviewer/EVIDENCE_INDEX.md`, `scripts/run_clean_clone_go_gate_v1_5.sh`, `scripts/gen_release_evidence_manifest_v1_5.py`, and relevant focused replay/PoH/consensus suites. These are components that must be rerun and extended as needed for the full clean genesis; no existing individual green CI job substitutes for this complete acceptance gate.

**Release decision at creation: NO-GO — requirements and evidence inventory remain to be satisfied.**
