# PR77 CASE receipt source-bound adjudication — 2026-11-03

**Disposition: REVIEW HOLD / NO SEMANTIC SIGN-OFF / NOT PUBLIC-TESTNET EVIDENCE.** This is a technical inspection of the exact current draft implementation and V2 extraction, not a normative amendment, semantic-review acceptance, or independent replay attestation.

## Correct source attribution

The canonical transaction applier registry (`specs/v2/source/tx_appliers.json`) binds `CASE_TYPE_REGISTER` (TX-2400), `CASE_BIND_TO_DISPUTE` (TX-2401), and `CASE_OUTCOME_RECEIPT` (TX-2402) to `src/weall/runtime/apply/dispute.py::_apply_case_receipt`. The public `apply_dispute` dispatcher delegates to that handler.

The 2026-11-03 extractor change that selected the single branch-local call without requiring a dispatch-return or `apply_` prefix could select `_as_str` when inspecting an internal CASE branch. This wrongly replaced the canonical handler with a string utility, creating additional stale V2 contract deltas for CASE_TYPE_REGISTER and CASE_BIND_TO_DISPUTE. **The follow-up correction removes that fallback** and adds tests using the actual registered `dispatch_function` rather than only the outer dispatcher.

This narrower correction changes only the **compiler static-analysis source selection**, not the runtime CASE handler. It does not bless or alter a `review_digest`. The static scanner still scans the shared `_apply_case_receipt` function containing three CASE branches, so its sets of failure reasons and state keys should not be claimed path-exact without further branch-aware analysis.

## Actual runtime contract and unresolved safety conditions

1. **SYSTEM flag versus actual authority.** `_require_system_env(env)` enforces `env.system` and raises `forbidden:system_only` if false. This direct helper does not independently authenticate the block scheduler, parent transaction, or governance executor. Such authority must be verified at the canonical admission/queue/executor boundary, not inferred from the boolean in an isolated test.
2. **Registration.** `CASE_TYPE_REGISTER` accepts the first nonempty `case_type` (or alternate `type`/`name`), inserts `cases.types[case_type]` on first use, and returns a receipt. Subsequent registrations for the same case type currently return a successful receipt even when their payload differs; first-write-wins and conflict expectations need normative adjudication.
3. **Binding.** `CASE_BIND_TO_DISPUTE` uses `case_id`, `id`, or `case:<nonce>`; it checks that the supplied `dispute_id` is nonempty, but the inspected direct helper does not require the dispute to exist. The first `cases.bindings[case_id]` record is retained. **For a duplicate case ID with a different dispute ID, the helper returns a successful receipt containing the *new requested* dispute ID while leaving the *previous stored* binding unchanged.** This is a potential receipt/state contradiction; investigate the block executor's rejection/receipt policy and constitutionally intended duplicate semantics. Do not assert that a conflicting SYSTEM envelope is authentic simply because `env.system` is true.
4. **Rejected-message mutation.** `_ensure_cases(state)` is called **before** validation of required `case_type`/`dispute_id` fields. Consequently, a direct call on previously uninitialized state can create `state.cases` before raising `invalid_payload:missing_case_type` or `invalid_payload:missing_dispute_id`. Verify that the canonical executor always rolls this back, including in bounded rollback and replay. Do not count a unit-test exception alone as atomic rejection.
5. **Outcome receipt.** `CASE_OUTCOME_RECEIPT` appends to `cases.outcomes` and returns a receipt, but independent finality/authorization is not established by an isolated call.

## Required proof before reviewing these semantics

- Execute **real canonical schema admission and SYSTEM-parent authorization** against wrong signer, missing scheduler parent, malformed payload, and unauthorized governance executor.
- Compare direct handler, dispatcher and canonical bounded-rollback executor outcomes on success and rejection; assert receipts **agree** with persisted bindings, no mutation after failure, and identical deterministic roots after restart/replay.
- Explicitly test duplicate identical versus conflicting case registration and binding, missing dispute targets, and conflicting nonce/parent; adjudicate whether they must reject, dedupe or return the original receipt.
- Determine historical compatibility and any **versioned activation boundary** before modifying the runtime CASE applier's consensus semantics. A prevalidation/duplicate-conflict repair must not silently reinterpret existing canonical history.
- Keep semantic digests unmodified until precise current material, test evidence, and explicit maintainer acceptance are available. Independent review and testnet authorization remain disabled.

## Source and checks

- `src/weall/runtime/apply/dispute.py`: `_require_system_env`, `_ensure_cases`, `_apply_case_receipt`, `apply_dispute`
- `specs/v2/source/tx_appliers.json`: CASE applier bindings
- `scripts/compile_v2_spec.py`: `_tx_function_analysis` branch-local handler choice
- `tests/test_pr77_v2_dispute_open_dispatch_extraction.py`: canonical CASE attribution and utility-call regression
- `.github/workflows/pr77-case-handler-extraction-no-approval.yml`: source regression and unapproved drift report

**Boundary:** read-only technical adjudication and compiler analysis precision. No consensus activation, approval, historical compatibility, live PoH, HTTPS, or two-node finality is established here.


## Executed exact-head diagnostic — 2026-11-03

- [GitHub Actions run 41734002434](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/41734002434) **PASS**, 10/10 focused tests, Ruff lint and format checks passed, and the read-only compiler diagnostic reports **18 stale review contracts**, with neither `CASE_TYPE_REGISTER` nor `CASE_BIND_TO_DISPUTE` included.
- `tests/test_pr77_case_receipt_adversarial_diagnostic.py` reproduces both direct-handler **HOLDs**: conflicting duplicate CASE binding can return a receipt inconsistent with stored binding, and invalid/missing payload can mutate previously uninitialized `cases` state before throwing. It also tests valid registration and verifies a non-SYSTEM envelope fails before mutation.
- These tests use synthetic `TxEnvelope` instances calling `apply_dispute` directly. They **do not establish** that canonical schema, authentication, journal rollback, historical block replay or BFT finality accepts those invalid envelopes or persists their effects. The next gate is proving or repairing these invariants at the canonical executor and versioned activation boundary.
- The workflow prints explicit `HOLD` and `NO-GO` conclusions. No accepted `semantic_reviews.json` digest changed.
