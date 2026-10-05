# Human Uniqueness, Registration Friction, and Tier-0 Lifecycle

Status: normative design target for PR #38 remediation; implementation/evidence incomplete.

This document separates three protocol problems that must not be collapsed into one mechanism:

1. registration abuse/friction;
2. one-human authority / duplicate identity adjudication;
3. permanent Tier-0 state growth.

The mechanisms below are deliberately layered. No single layer is allowed to claim properties owned by another layer.

## 1. Account registration proof-of-work

Account-registration work is retained as a passive first-line friction mechanism.

It MAY:

- raise the marginal computational cost of automated bulk account creation;
- slow simple registration floods;
- make fresh-key state spam less free at the admission boundary.

It MUST NOT:

- establish personhood;
- establish one-human-one-account uniqueness;
- grant PoH authority;
- grant reputation, voting, governance, reviewer, validator, or civic authority;
- be consumed by protocol logic as evidence that two accounts belong to different humans;
- be described as a hard lifetime account-count bound.

A high-resource actor can perform proportionally more work. Registration PoW is therefore defense in depth, not the authoritative Sybil decision mechanism.

## 2. Tier 0 is an account, not a human

Successful `ACCOUNT_REGISTER` creates a Tier-0 account only.

Tier 0 carries no implication that the account represents a unique human. Human/governance authority begins only after a valid PoH award under the human-uniqueness rules below.

## 3. Primary human-uniqueness mechanism

Human uniqueness is enforced through adjudicable duplicate-identity challenges.

An eligible challenger may identify:

- a challenged account; and
- a reference account alleged to represent the same human.

Opening a challenge MUST NOT by itself revoke either account.

The canonical challenge record must distinguish allegation from adjudicated fact.

Protocol analytics MAY surface or prioritize suspected duplicates using bounded signals such as duplicated evidence commitments, reviewer overlap, coordinated verification windows, or other documented correlation indicators.

Analytics MUST NOT autonomously revoke PoH authority or create a canonical duplicate relation without adjudication.

## 4. Independent adjudication

A duplicate-identity challenge is decided by a separately selected human reviewer/adjudication panel.

Reviewer selection MUST satisfy A20-F001 before production human-authority creation is enabled:

- the request/challenge context is committed before selection entropy becomes knowable;
- applicant-controlled labels such as `case_id` are not entropy;
- retry/replacement counters are not new entropy sources;
- applicant and proposer skip/retry grinding is bounded or impossible by protocol rule;
- withholding/minority-bias behavior is explicitly modeled;
- restart and state-sync reproduce the same committed selection outcome;
- replacement selection cannot create an unbounded second panel-search surface.

Until these properties are implemented and proven, production positive PoH authority remains fail-closed.

## 5. Duplicate decision semantics

If a duplicate challenge is upheld:

- the challenged duplicate loses active PoH authority;
- a canonical duplicate relation is recorded;
- only the retained/reference identity may continue to hold verified-human authority for that adjudicated relation;
- the duplicate account is blocked from reacquiring PoH authority through an ordinary fresh verification attempt while the relation remains confirmed.

The canonical relation must preserve at least:

- challenge identifier;
- challenged/duplicate account identifier;
- retained/reference account identifier;
- decision status;
- decision height/context;
- authority effect;
- appeal/overturn history sufficient for deterministic replay.

The relation is an authority binding, not an instruction to destroy the underlying account or unrelated non-human account state.

## 6. False positives, dismissal, and appeal

If a duplicate challenge is dismissed before an upheld decision, no confirmed duplicate relation is created.

If an upheld decision is later overturned on appeal:

- the duplicate-authority block is removed canonically;
- the accused account is not permanently poisoned;
- previously revoked PoH authority is not silently resurrected;
- ordinary reverification is required before human authority is re-awarded;
- the original decision and overturn remain in deterministic history.

## 7. Tier-0 lifecycle for A15-F003

Registration PoW does not by itself bound permanent state. A15-F003 therefore requires a separate deterministic Tier-0 lifecycle.

The production target is:

1. a newly registered Tier-0 account is **provisional**;
2. a provisional Tier-0 record has a consensus-committed lifecycle deadline or equivalent finite retention rule;
3. an account becomes retention-relevant when it enters PoH or another explicitly enumerated protocol state that requires the full account record;
4. a provisional account that never becomes retention-relevant may be compacted after the deterministic lifecycle condition is met;
5. compaction preserves a minimal canonical tombstone/commitment sufficient to prevent replay, identity resurrection ambiguity, challenge-history corruption, and restart/state-sync disagreement.

The lifecycle MUST NOT depend on local wall-clock time, local database size, node-specific garbage collection, or nondeterministic memory pressure.

## 8. Tombstone / commitment safety requirements

A compacted Tier-0 account representation must preserve enough consensus-visible information to ensure that every honest node agrees on whether a later transaction is:

- a replay of an already-consumed registration identity;
- a prohibited attempt to resurrect a retired account identifier without the defined recovery/re-registration semantics;
- a valid protocol-defined re-registration/recovery action, if such an action is explicitly allowed;
- linked to an existing duplicate-identity or challenge history that still has authority consequences.

The exact tombstone schema is an implementation decision and must be covered by state-root, restart, replay, and state-sync equality tests before A15-F003 is closed.

## 9. Required evidence before closure

### A08-F001 / P0-06

Closure requires evidence for:

- eligible-user duplicate challenge opening;
- distinct registered target/reference validation;
- no punishment on challenge open;
- independently selected adjudication panel;
- upheld duplicate relation and authority revocation;
- re-award blocking while confirmation is active;
- dismissal without poisoning;
- appeal/overturn with reverification requirement;
- conflicting/recursive duplicate relation handling;
- analytics that suggest rather than autonomously revoke;
- restart/state-sync equality for challenge, decision, appeal, and authority effects.

### A20-F001 / P0-06

Closure additionally requires:

- commit-before-unpredictable-entropy selection;
- explicit bias/withholding security model;
- proposer/applicant retry and skip-grinding regressions;
- replacement-panel grinding regressions;
- multi-validator tests;
- restart/state-sync tests;
- deterministic property/Monte-Carlo evidence where appropriate.

### A15-F003 / P0-10

Closure requires evidence for:

- registration PoW remains identity/payload bound and non-reusable;
- provisional Tier-0 lifecycle is deterministic;
- inactive Tier-0 accounts compact at the protocol-defined boundary;
- retention-relevant accounts do not compact incorrectly;
- compacted accounts cannot replay registration or evade duplicate/challenge consequences;
- proposer/follower, restart, replay, and state-sync roots remain equal across compaction;
- long-run state growth is bounded by the live provisional window plus constant/minimally bounded tombstone representation rather than by ever-growing full account records.

## 10. Claim boundary

Until the above implementation and evidence are present on one exact commit/tree:

- registration PoW may be described only as passive computational friction / abuse throttling;
- P0-06 must remain open;
- A15-F003 must not be represented as closed solely because registration PoW is enabled;
- stronger public/release claims remain fail-closed.
