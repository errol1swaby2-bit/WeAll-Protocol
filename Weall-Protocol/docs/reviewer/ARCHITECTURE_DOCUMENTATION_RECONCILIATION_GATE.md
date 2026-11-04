# Architecture and documentation reconciliation — mandatory pre-audit gate

**Status: PLANNED / NOT COMPLETED.** This document defines a future review-and-rewrite phase. Existing specifications, constitutions, diagrams, API descriptions, UX documents and evidence claims have changed over the development process; no legacy text is automatically considered current merely because it appears in the repository.

## Position in the completion roadmap

1. Finish missing and incorrectly integrated backend/protocol subsystems.
2. Exercise complete canonical cross-subsystem flows.
3. Finish frontend layout, interaction, accessibility and backend integration revisions.
4. **Reconcile, rewrite and validate all documentation (this gate).**
5. Run a comprehensive whole-protocol and constitutional audit against the reconciled documentation and actual integrated implementation.
6. Correct audit findings, repeat affected integration/documentation checks, then freeze candidate software and new genesis for clean-run evidence regeneration and launch gating.

Documentation reconciliation may begin as an inventory earlier, but its final acceptance depends on the completed architecture **and revised frontend**. The subsequent full audit must not be based on superseded draft architecture.

## What must be inventoried and updated

Cover **all** checked-in and release-distributed material, not only README or the current launch checklist:

- Constitution, normative protocol specification, architecture decisions, transaction canon, protocol invariants, chain identity/genesis and constitutional authority boundaries.
- Domain mechanics: account identity and key lifecycle; PoH; reputation; disputes, juries, appeals and sanctions; governance; groups; civic/social interfaces; economics; role/validator/operator enrollment.
- Consensus/finality/BFT, deterministic execution and replay; helper lanes; networking; p2p discovery; storage/IPFS; encryption, privacy, safety controls; reconfiguration and protocol upgrades.
- Frontend product architecture, information hierarchy, navigation, visual design, accessibility and end-to-end member/operator/observer flows, matched to actual APIs and transaction lifecycles.
- API and event schemas; public routes, CLI, configuration, key/signature interfaces, deployment instructions, security and threat model, operator/systems maintenance.
- All README, contribution/onboarding, developer/reviewer, testnet/public observer, legal/compliance, release-readiness, test/evidence runbook, proof statement, generated documentation and diagram surfaces.
- Supplied project reference artifacts and historical external PDFs/DOCX: inventory and compare them as potential *earlier-source versions*; do not quietly overwrite/ratify them as new constitutional authority.

## Per-decision reconciliation procedure

For every significant changed architectural decision record:

1. **Previous documented behavior** with original document, exact version/revision or commit.
2. **Current intended design**, identifying whether explicitly decided/ratified, still proposed, or unresolved; do not guess user intent from incomplete code.
3. **Present implementation and integration state**, with exact source functions, tests, reachable transaction/API paths and observed behavior.
4. **Differences, incompatibilities, migration/breaking-change implications**, especially signature domain, transaction shape, chain identity, state roots, PoH authority and public-facing UX.
5. **Resolution**: implement missing behavior, revise stale documentation, update the chosen design, or leave an explicit open decision requiring review. A mismatch must never be disguised as documentation-only.
6. **Affected destinations**: normative specs, code comments, diagrams, tx canon/API schemas, tests/fixtures, frontend copy, operator docs, proof claims and release runbooks.
7. **Verification**: direct links to diff/issue/decision, ownership, generated-artifact update and tests showing all references consistently describe the same implemented semantics.

Maintain a traceability matrix with status per item: `implemented_and_reconciled`, `documented_but_not_implemented`, `implemented_but_not_specified`, `conflicting_or_unratified`, `deprecated_historical` or `blocked`. Show unratified governance and constitutional decisions explicitly, rather than automatically promoting a newer design note over an approved constitutional rule.

## Treatment of older material

Keep prior versions identifiable and marked **historical/superseded** when they no longer describe the active design. Record what replaced them and when. Don't erase decisions or omit adverse historical findings. Draft language, outdated diagrams, legacy tx-history examples and preliminary performance measurements must not appear as current production claims. Conversely, do not rewrite true historical test transcripts and then present them as freshly reproduced evidence.

Reconcile both product-facing documentation and low-level consensus contracts: a clean frontend cannot compensate for backend claims that are architecturally wrong, and a correct backend cannot compensate for inaccurate participant-facing descriptions.

## Acceptance criteria before the full protocol audit

- An inventory covers all in-scope repository documentation, diagrams, API/canon descriptions and published launch-facing claims; external source documents are identified as references when applicable.
- Every architectural revision is linked to an explicit current decision, implemented contract and applicable code/test/UX evidence, or recorded as open and blocking.
- Newly agreed architecture is consistently described across normative documents, transaction/runtime/API contracts, generated artifacts, frontend workflows and deployment/operator guides.
- No legacy specification or historical evidence silently conflicts with active claims. The review records remaining disagreements and explicitly avoids claiming everything is implemented.
- Build/generated docs and doc-link/schema consistency checks pass on the exact reviewed commit; broken links, unrecognized old APIs/tx types, missing user journeys and contradictory numbers are resolved or marked blocked.
- A designated approval/review signs off the reconciliation packet and clearly separates ratified constitutional authority from aspirational product design. Re-run affected docs whenever subsequent full-audit repairs change semantics.

**Gate result at creation: NOT SATISFIED.** No comprehensive update or architecture ratification is claimed by the existence of this plan. Full protocol audit should begin only when this reconciliation has produced a coherent, reviewable baseline.
