# PR77 phase-1 content report → dispute pipeline integration

**Status: EXPERIMENTAL / CI VALIDATION REQUIRED.** Not final protocol, user-facing
E2E, global PoH, independent BFT, S4 case classification, or testnet evidence.

## Why this check exists

The frontend's public content/feed reporting action submits `CONTENT_FLAG`;
the content domain enqueues `CONTENT_ESCALATE_TO_DISPUTE`; the escalation
invokes dispute opening, assigns only conflict-eligible opt-in reviewers, and
enqueues a receipt. Direct applier/emitter tests did not alone prove this chain
survives signed external submission, canonical block admission, system queue,
durable state, and independent fresh-executor replay within one code revision.

This bounded regression exercises two separately signed accounts: the genesis
author and a registered, controlled-*local-bootstrap* reporter. It submits
`ACCOUNT_REGISTER`, explicit local `POH_BOOTSTRAP_TIER2_GRANT`,
`CONTENT_POST_CREATE`, and `CONTENT_FLAG` through `WeAllExecutor.submit_tx`,
builds blocks with `produce_block`, and requires the system escalation's
**successful block receipt**, resulting dispute, correct target and reporter
attribution, exclusion of parties from juror assignments, absence of account
bans, and exact source/fresh-replay manifest equivalence.

## Exact limitations

- `WEALL_POH_BOOTSTRAP_OPEN=1` under local developer mode is a controlled
  fixture shortcut and **not** proof of unique human identity or real PoH
  issuance. This mode must never be silently used to claim real testnet PoH.
- A second executor on the same runner is not a separate operator, BFT finality
  authority, third-party node or full network topology.
- Direct account-target signed `DISPUTE_OPEN` has a separate synthetic
  end-to-end regression. The current frontend's ordinary public report action
  exposes `CONTENT_FLAG`; whether to expose other dispute targets in the
  participant UI is a product/constitutional scope decision, not something
  this test guesses or activates.
- Generated/severe-sanction and semantic-review gates remain unchanged. No
  `ACCOUNT_BAN` authority, no constitutional S4 classification or appeal is
  implied.
- Phase 1 requires a full subsystem inventory and additional integrated flows.
  This is just one representative path, not a completeness certification.

**Outcome:** Await pinned CI. If failed, preserve the exact failing boundary
and correct only with focused evidence; do not change production gating merely
to turn the check green.
