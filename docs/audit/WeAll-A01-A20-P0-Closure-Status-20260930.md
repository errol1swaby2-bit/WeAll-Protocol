# WeAll A01–A20 P0 Closure Status

Date: 2026-09-30 (America/Los_Angeles)
Audit base: `cd7f10a8b62e9f5a3711f4263d04e3fd62f0d351`
Audit tree: `36a5868c72022f11a61bca8f48816852acccb1c9`
Canonical closure PR: #38

This document is deliberately stricter than a normal PR checklist. A runtime patch is not the same thing as audit closure. `PATCHED / EVIDENCE PENDING` means the branch contains a targeted remediation, but the finding remains open until the audit-required regression, replay/restart, adversarial, generated-artifact, and full-suite evidence is green on an exact commit.

## Status legend

- `PATCHED / EVIDENCE PENDING` — targeted code remediation exists; exact closure evidence is still required.
- `PARTIAL` — one or more findings in the track are closed or patched, but other findings remain open.
- `DESIGN BLOCKER` — the audit requires a protocol/normative decision before code can safely close the finding. The PR must not invent the missing rule.
- `IMPLEMENTATION BLOCKER` — invariant is sufficiently defined, but the production implementation/testing work remains substantial.
- `EVIDENCE GATE` — closes only after underlying runtime tracks are proven and evidence/claims are regenerated.

## Track status

| Track | Findings | Current status | Branch work / remaining gate |
| --- | --- | --- | --- |
| P0-01 Canonical transaction identity / replay | A02-F001, A16-F002 | CLOSED — PATCHED AND PROVEN | Failed canonical inclusion consumes nonce and immutable tx identity; resubmission is rejected on leader, follower, and restarted follower with equal state roots. Focused lifecycle evidence and exact-head full-suite/reviewer gates are green on the preserved closure lineage. |
| P0-02 Equal-root deterministic execution | A04-F001, A16-F003, A18-F001 | CLOSED — PATCHED AND PROVEN | Async/Tier-2/Live case maps and reviewer pools are canonically ordered. Equal-root permutations cover receipt-only, assignment, finalize/receipt, and leader-vs-replay scheduler-pipeline parity. Public/generated claims are refreshed only after the proof. Generalized same-tree audit-to-claim binding is separately enforced under P0-12. |
| P0-03 HotStuff highQC parent / validator transition certificates | A05-F001, A05-F002, A16-F004 | CLOSED — PATCHED AND PROVEN | The production-composition closure chain requires highQC-parent extension, preserves the authenticated validator-transition bridge across highQC advance/restart, reconstructs certified pending ancestry without admitting unauthenticated alternates, and proves delayed finality/replay behavior. The focused closure matrix and full backend/reviewer gates were green on the preserved exact closure lineage. |
| P0-04 Follower receipt canonicality | A06-F001, A16-F002 | CLOSED — PATCHED AND PROVEN | Follower apply rejects a tampered receipt body without state movement, accepts the canonical block, and restart/readback preserves the exact canonical block and state root. State-sync tamper/restart coverage remains as a second path. |
| P0-05 P2P mutual auth / frame sizing | A07-F001, A07-F002 | CLOSED — PATCHED AND PROVEN | Mutual authentication uses fresh receiver challenge material with signed acknowledgements, recipient/correlation binding, stale-proof rejection and replay rejection. A single finite production wire budget governs peer payloads/frames, BFT proposal block sizing and chunked state-sync transfer bounds. The dedicated closure run passed 17 focused regressions plus 4,685 backend tests (1 skipped), and the unchanged exact tree at `65329c71df7a2f029760d49fc57b21beffd650cc` passed Backend CI, Reviewer Readiness, Web CI and Secrets Guard. |
| P0-06 Human uniqueness / reviewer anti-grinding | A08-F001, A20-F001 | CLOSED — SCOPE-CLOSED AND PROVEN | The repository does **not** claim to have invented global human uniqueness or an unbiasable randomness beacon. Instead, the canonical production genesis commits `params.poh.human_authority_mode=scope_closed_pending_uniqueness_entropy`. At the canonical apply boundary all positive PoH authority creation/advancement families fail closed with `poh_human_authority_scope_closed`; async/Tier-2/Live schedulers independently enqueue nothing under that mode; direct award helpers fail closed; challenge/revocation remain available; and non-production compatibility remains testable. This removes both A08-F001 and A20-F001 from reachable production authority until a separately reviewed uniqueness/privacy/adjudication protocol and commit-before-unpredictable-entropy selection protocol are defined. The P0 assurance gate contains dedicated mutants for bypassing both the apply lock and async scheduler lock. |
| P0-07 Governance electorate / proposal binding / constitutional authority | A09-F001..F004, A16-F005 | CLOSED — PATCHED AND PROVEN | A09-F001 through A09-F003 are closed: production civic governance fails closed, executable proposals use the Tier-2 human electorate, and votes bind an immutable executable proposal version. A09-F004 is scope-closed rather than supplied with invented constitutional rules: strict civic profiles reject `CONSTITUTION_UPGRADE_DECLARE`/`ACTIVATE` at proposal authoring and independently reject direct SYSTEM protocol application; the record-only compatibility path remains outside production civic authority. A16-F005 is now supplied by the locked P0 assurance gate: production chain-mode and voting-stage proposal-freeze mutants are non-equivalent P0-07 operators and are killed by the exact-head gate. |
| P0-08 Economics activation / treasury governance binding | A10-F001, A10-F002, A10-F005 | CLOSED — PATCHED AND PROVEN | Locked economics cannot schedule value execution; production enablement runs readiness preconditions; group treasury requires governance approval bound to the immutable spend plan; approved queue-to-apply value movement is one-shot across restart/replay and mutation is rejected. |
| P0-09 PoH API authorization/privacy | A12-F001, A18-F002 | CLOSED — PATCHED AND PROVEN | All six scoped account/juror queues and Tier-2/Live full-case reads are session/principal or participant bound. Anonymous, wrong-principal, and authorized runtime matrices pass, and all protected surfaces are represented by current generated auth/privacy vectors executed against runtime truth. |
| P0-10 Bounded production state / state sync / permanent account state | A15-F001..F003 | CLOSED — PATCHED AND PROVEN | A15-F001 bounds root-visible live ancestry to a consensus-committed ceiling with a rolling checkpoint commitment; restart, proposer/follower equality, fork-choice/HotStuff finality and state-sync verification cross the compaction boundary. Synthetic steady-state evidence at 100k/1M/5M heights retains exactly 10,000 live ancestry records while measuring state size, deepcopy, state-root/replay-root, durable serialization/write, restart parse, RSS and per-block compaction. A15-F002 uses finite wire-derived response caps, cheap trusted-anchor/range preflight before state materialization, and a global/per-peer bounded off-loop worker with bounded result drain; 10/100/500 MiB synthetic state requests remain response-capped, concurrent accepted work is globally bounded, excess requests fail `sync_busy`, and BFT routing remains independently serviceable under saturated sync work. A15-F003 remains closed by finite nonzero identity-bound registration work without claiming human uniqueness or a lifetime account cap. |
| P0-11 Property/mutation gate | A16-F001 | CLOSED — PATCHED AND PROVEN | A deterministic P0 assurance framework is locked into Backend CI with fixed reviewable property seeds, lifecycle-focused property tests, explicit P0 mutation operators, a survivor artifact, and a fail-closed gate. The exact-head P0 assurance gate kills all 15 non-equivalent P0 mutants, with zero survivors and zero invalid mutations; the normal Backend CI independently passes this gate before the full pytest suite. |
| P0-12 Claim/evidence truth binding | A18-F001, A18-F002 | CLOSED — PATCHED AND PROVEN | Current claim generation consumes the canonical same-tree A01–A20 P0 closure ledger, enumerates open HIGH/P0 tracks and findings, hashes the ledger as a required generation input, and fails closed if any release claim boundary is enabled while a P0 track remains open. Dedicated malformed/missing-track and claim-promotion regressions pass. |


## P0-10 A15-F001/F002 dedicated closure evidence

Dedicated closure workflow run: `37258212437`.

A15-F001 synthetic steady-state heights were exercised at 100,000 / 1,000,000 / 5,000,000 while retaining the protocol ceiling of 10,000 live ancestry records plus a constant-size rolling checkpoint. The run measured candidate deepcopy, state-root and replay-root equality, canonical serialization/write, restart parse, RSS, and one-block compaction at each height. The largest measured state-root time was `26.724 ms`; the largest encoded bounded state was `820,364` bytes. These are CI-host synthetic measurements, not validator-hardware throughput claims.

A15-F002 exercised synthetic 10 / 100 / 500 MiB state snapshots. Every oversized request was rejected as `snapshot_too_large` under the finite wire-derived response cap; the 500 MiB case completed in `8444.363 ms` with peak process RSS `1,587,508 KiB` on the CI host. A saturated worker admitted `4` requests at the global work cap, rejected `2` excess requests as `sync_busy`, drained at one result per tick, and routed `500` BFT vote messages with measured max callback latency `0.003627 ms`. These are bounded stress measurements, not network throughput claims.

The workflow artifact contains the machine-readable JSON/CSV evidence and the long-height SVG plot. That workflow-free exact-tree contingency was subsequently satisfied on the reconciled PR head recorded in PR #38 metadata. Any later follow-up commit must re-establish the same exact-head gates before reviewer handoff.

## Additional CI blockers discovered during closure

The first P0 branch backend run reached the dependency audit and found that `requirements-dev.lock` pinned `urllib3==2.7.0`, which the current advisory feed reports vulnerable. The runtime lock audited clean. A temporary branch-only workflow regenerated the dev lock with `urllib3==2.8.0`, ran `pip-audit`, committed only the regenerated lock, and was then deleted. This is a CI/readiness repair discovered while preparing closure; it is not being retroactively counted as one of the A01–A20 findings.

After the A09/A10 authority patch, Backend CI and Reviewer Readiness reached generated-artifact validation and found the legacy v1.5 failure registry stale because new fail-closed reasons had been introduced. The deterministic dependency chain was regenerated twice: `failure_code_registry_v1_5.json`, `api_response_vectors_v1_5.json` where applicable, `public_beta_blocker_report_v1_5.json`, and `release_evidence_manifest_v1_5.json`. This repaired evidence freshness only; it did not close any P0 finding by itself.

The A15-F003 closure changed permanent-account admission and public-testnet chain identity. The checked-in public seed registry remains intentionally fail-closed pending the operator-held ML-DSA re-signing ceremony; no signature was fabricated as part of audit remediation. The source closure was followed by v1.5/V2 regeneration, focused scarcity tests, cardinality-scaling evidence, and exact-head normal CI.

The initial P0-11 mutation run killed 12 of 13 non-equivalent mutants and correctly blocked closure on `P0-08-ECON-ACTIVATION-PRECONDITIONS`. The runtime already had a negative activation-precondition regression; the mutant's selected test set omitted it. The gate was strengthened to include that existing regression. The helper-free exact tree then killed 13/13 non-equivalent mutants, and normal Backend CI independently passed the same assurance gate before the full pytest suite.

## Reference exact-head evidence and final-head binding

The last workflow-free runtime/evidence candidate before this audit-ledger reconciliation was commit `cf9d36cb101f8211dd1bcac1a0975dbcc724a01f`, Git tree `beb93ce2f78ad60e03ead35383dd17be3a839e5a`.

On that candidate:

- Backend CI was green, including Ruff, dependency audit, canon lint, generated-artifact checks, historical-evidence restoration, the P0 property/mutation assurance gate, full pytest, and transaction-coverage report generation/upload;
- Reviewer Readiness Gate was green;
- Web CI was green;
- Secrets Guard was green;
- the normal Backend CI P0 assurance gate killed **15/15** non-equivalent mutants with zero survivors and zero invalid mutations;
- the normal Backend CI full suite completed with **4,743 passed, 1 skipped**;
- the workflow-free pre-push finalizer independently ran the exact candidate through generated/public-claim checks and a full backend suite with **4,744 passed** before push;
- all temporary PR38 remediation workflows were absent from the candidate tree.

This reference candidate proves the runtime and generated-evidence closure used by the final P0 audit reconciliation, including the P0-06 production human-authority scope lock. The reconciliation itself changes audit truth text and regenerated claim/spec derivatives, not the closed runtime invariants.

A tracked Git object cannot stably embed the commit SHA or Git tree hash of the commit that contains that same object: changing the embedded identifier changes the object and therefore changes the identifier. For that reason, this ledger intentionally does **not** label an embedded SHA as its own final head. The final exact PR commit SHA and Git tree are recorded in PR #38 metadata after the workflow-free reconciled tree passes the normal Backend CI, Reviewer Readiness, Web CI, and Secrets Guard gates. This ledger remains a required hashed input to current claim generation, so final same-tree claim/spec validation still fails closed if the ledger and generated evidence diverge.

## Merge / closure prohibition

PR #38 remains the single canonical closure PR and MUST NOT be represented as fully P0-closed or merge-ready while any of the following is true:

1. Any P0 track above is `DESIGN BLOCKER`, `IMPLEMENTATION BLOCKER`, `PARTIAL`, or `EVIDENCE GATE`.
2. Any targeted remediation lacks the regression evidence required by its source audit finding.
3. Full backend, reviewer-readiness, web, and secrets checks are not green on the exact proposed head.
4. Generated/canon/spec artifacts are stale relative to the proposed source tree.
5. P0 property/mutation survivors remain unadjudicated.
6. Public claim/evidence artifacts still assert capabilities contradicted by an open same-tree finding.
7. Final closure evidence does not record the exact final commit SHA and Git tree.

## Post-closure implementation boundary

1. Keep production positive PoH human-authority creation/advancement scope-closed while the uniqueness/privacy/adjudication and post-commit unpredictable reviewer-entropy protocols remain undefined or unproven.
2. Treat any future re-enablement of production PoH human authority as a new protocol feature requiring separate reviewed design, adversarial/restart/state-sync evidence, generated-artifact refresh, and exact-head normal CI before activation.
3. Preserve the final exact reconciled commit SHA and Git tree in PR #38 metadata after all normal gates pass; do not weaken public-beta/mainnet/launch claim boundaries merely because the P0 repository closure is complete.
