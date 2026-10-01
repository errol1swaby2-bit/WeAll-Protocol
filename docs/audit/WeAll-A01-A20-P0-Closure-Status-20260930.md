# WeAll A01–A20 P0 Closure Status

Date: 2026-09-30 (America/Los_Angeles)
Audit base: `cd7f10a8b62e9f5a3711f4263d04e3fd62f0d351`
Audit tree: `36a5868c72022f11a61bca8f48816852acccb1c9`
Umbrella PR: #33

This document is deliberately stricter than a normal PR checklist. A runtime patch is not the same thing as audit closure. `PATCHED / EVIDENCE PENDING` means the branch contains a targeted remediation, but the finding remains open until the audit-required regression, replay/restart, adversarial, generated-artifact, and full-suite evidence is green on an exact commit.

## Status legend

- `PATCHED / EVIDENCE PENDING` — targeted code remediation exists; exact closure evidence is still required.
- `PARTIAL` — one or more findings in the track have targeted remediation, but other findings remain unpatched.
- `DESIGN BLOCKER` — the audit requires a protocol/normative decision before code can safely close the finding. The PR must not invent the missing rule.
- `IMPLEMENTATION BLOCKER` — invariant is sufficiently defined, but the production implementation/testing work remains substantial.
- `EVIDENCE GATE` — closes only after underlying runtime tracks are proven and evidence/claims are regenerated.

## Track status

| Track | Findings | Current status | Branch work / remaining gate |
| --- | --- | --- | --- |
| P0-01 Canonical transaction identity / replay | A02-F001, A16-F002 | PATCHED / EVIDENCE PENDING | Canonically included failed user txs consume nonce; durable `tx_index` identity is immutable and duplicate commit fails. Needs end-to-end failed-tx resubmit, restart, proposer/follower, and full-suite proof. |
| P0-02 Equal-root deterministic execution | A04-F001, A16-F003, A18-F001 | PATCHED / EVIDENCE PENDING | Async/Tier-2/Live PoH case maps are iterated in canonical key order; equal-root insertion-order regressions added. Needs full scheduler/root permutation evidence and claim regeneration. |
| P0-03 HotStuff highQC parent / validator transition certificates | A05-F001, A05-F002, A16-F004 | IMPLEMENTATION BLOCKER | Requires chained-HotStuff leader parent rule and authenticated transition-certificate bridge across activation/validator generations plus adversarial multinode mutation evidence. No cosmetic patch applied. |
| P0-04 Follower receipt canonicality | A06-F001, A16-F002 | PATCHED / EVIDENCE PENDING | Durable commit now revalidates complete block commitments before persistence. Needs follower tamper, restart/readback, proposal/replay parity, and full-suite proof. |
| P0-05 P2P mutual auth / frame sizing | A07-F001, A07-F002 | IMPLEMENTATION BLOCKER | Requires fresh session-bound mutual peer authentication and a single protocol-valid wire-size contract/chunking strategy. Audit explicitly rejects a boolean-only or limit-only cosmetic fix. |
| P0-06 Human uniqueness / reviewer anti-grinding | A08-F001, A20-F001 | DESIGN BLOCKER | Must define protocol-level global uniqueness authority and commit-before-unpredictable-entropy reviewer selection. Applicant-controlled case ID cannot remain selection entropy. |
| P0-07 Governance electorate / proposal binding / constitutional authority | A09-F001..F004, A16-F005 | PARTIAL | A09-F001 patched: `weall-prod` is strict production civic governance. A09-F002 patched/evidence-pending: strict executable governance uses a snapshotted Tier-2 human electorate, with a regression proving a Tier-0 validator is excluded while a non-validator Tier-2 human is included. A09-F003 patched/evidence-pending: voting-stage mutation is rejected on strict chains and `GOV_EXECUTE` must execute the exact proposal action snapshot rather than substituted SYSTEM payload actions. A09-F004 remains open, but the normative ambiguity is narrower than previously recorded: Genesis Constitution Article XIII explicitly requires a public amendment proposal, exact diff, deliberation, constitutional review, eligible verified-user participation, quorum, supermajority, activation delay, public receipt, challenge window, and at least 75% approval for ordinary amendments; it also defines an explicit unamendable anti-domination floor. The stricter protected-right process is not numerically specified, so production code must fail closed rather than inventing its threshold/process. Broader mutation/property/restart evidence remains required for A16-F005. |
| P0-08 Economics activation / treasury governance binding | A10-F001, A10-F002, A10-F005 | PATCHED / EVIDENCE PENDING | A10-F001: strict/configured economic states do not schedule group-treasury value execution while economics is locked/disabled. A10-F002: enabling economics on `weall-prod` unconditionally runs the existing readiness-precondition report. A10-F005: strict group-treasury execution now requires both execution multisig and a governance approval bound to the immutable spend plan; scheduler and apply paths verify proposal/plan bindings. Focused authority regressions reached 25/25. Remaining closure evidence includes a positive governance-approved queued execution/value-transfer path, restart/replay, broader group cases, generated exact-head proof, and full suite. |
| P0-09 PoH API authorization/privacy | A12-F001, A18-F002 | PATCHED / EVIDENCE PENDING | Scoped account/juror queues are session/principal bound; Tier-2/Live full-case internal projections are participant-only. Needs runtime API matrix, generated contract/vector regeneration, and same-tree contract truth proof. |
| P0-10 Bounded production state / state sync / permanent account state | A15-F001..F003 | DESIGN + IMPLEMENTATION BLOCKER | Requires bounded ancestry commitment/history architecture, finite authenticated state-sync work/response envelope, and protocol-level permanent-state scarcity/identity bootstrap policy. |
| P0-11 Property/mutation gate | A16-F001 | IMPLEMENTATION BLOCKER | Add locked property/mutation framework, deterministic seeds, P0 mutation operators, survivor artifact, and CI gate. Must exercise lifecycle boundaries rather than only local functions. |
| P0-12 Claim/evidence truth binding | A18-F001, A18-F002 | EVIDENCE GATE | Regenerate only after runtime closure. Claim generation must consume open same-tree audit findings so unresolved HIGH findings automatically block/downgrade broader claims. |

## Additional CI blockers discovered during closure

The first P0 branch backend run reached the dependency audit and found that `requirements-dev.lock` pinned `urllib3==2.7.0`, which the current advisory feed reports vulnerable. The runtime lock audited clean. A temporary branch-only workflow regenerated the dev lock with `urllib3==2.8.0`, ran `pip-audit`, committed only the regenerated lock, and was then deleted. This is a CI/readiness repair discovered while preparing closure; it is not being retroactively counted as one of the A01–A20 findings.

After the A09/A10 authority patch, Backend CI and Reviewer Readiness reached generated-artifact validation and found the legacy v1.5 failure registry stale because new fail-closed reasons had been introduced. The deterministic dependency chain was regenerated twice: `failure_code_registry_v1_5.json`, `api_response_vectors_v1_5.json` where applicable, `public_beta_blocker_report_v1_5.json`, and `release_evidence_manifest_v1_5.json`. The v1.5 public-readiness checker passed, the artifacts were committed locally, clean-tree release hygiene passed, and the derivative-only commit was pushed as `11d050e479e4857e5ef888afcb431334f07a0248`. This repairs evidence freshness only; it does not close any P0 finding by itself.

## Current focused evidence

The governance/economics/treasury authority closure batch has passed 25 focused regressions covering:

- production executable-governance Tier-2 electorate selection;
- production voting-stage proposal immutability;
- unconditional production economics readiness checks;
- strict multisig threshold without governance approval does not schedule execution;
- strict treasury execution without governance approval is rejected;
- governance approval binds the exact group/spend/treasury/recipient/amount plan;
- mutation of approved spend terms is rejected;
- strict `GOV_EXECUTE` rejects executable actions that differ from the proposal action snapshot;
- existing fail-closed group-treasury, system-queue lifecycle, and four-gate safety regressions.

The 42 V2 derivatives were current and reproducible on the pre-v1.5-refresh head. Because exact-tree freshness is mandatory, the current head must still pass the normal generated-artifact gates after the v1.5 derivative-only commit and this ledger update. These focused passes are not equivalent to full P0 closure.

## Merge / closure prohibition

PR #33 remains a draft and MUST NOT be converted to merge-ready while any of the following is true:

1. Any P0 track above is `DESIGN BLOCKER`, `IMPLEMENTATION BLOCKER`, `PARTIAL`, or `EVIDENCE GATE`.
2. Any targeted remediation lacks the regression evidence required by its source audit finding.
3. Full backend, reviewer-readiness, web, and secrets checks are not green on the exact proposed head.
4. Generated/canon/spec artifacts are stale relative to the proposed source tree.
5. P0 property/mutation survivors remain unadjudicated.
6. Public claim/evidence artifacts still assert capabilities contradicted by an open same-tree finding.
7. Final closure evidence does not record the exact final commit SHA and Git tree.

## Next implementation order

1. Run Backend CI and Reviewer Readiness on the current maintainer-authored head so the suites can proceed past the repaired v1.5 freshness gate; refresh only the derivatives that the exact-tree checks prove stale.
2. Add the positive A10-F005 governance-approved queue-to-apply value-transfer regression, then add restart/replay and broader adversarial closure evidence for the already-patched A02/A04/A06/A09/A10/A12 findings.
3. Implement the mechanically specified ordinary portion of A09-F004 from Genesis Constitution Article XIII; keep protected-right amendments fail-closed until a stricter numeric/process rule is normatively defined, and do not claim semantic rights-floor validation from document hashing alone.
4. Implement A05/A07/A15 architecture tracks only from explicit designs, with dedicated adversarial/multinode/stress evidence.
5. Adjudicate A08/A20 human-uniqueness and anti-grinding design together so reviewer selection and uniqueness have one coherent trust model.
6. Install the A16 property/mutation gate and kill the P0 mutation classes.
7. Regenerate A18 claim/evidence truth artifacts and capture final exact-commit closure evidence.
