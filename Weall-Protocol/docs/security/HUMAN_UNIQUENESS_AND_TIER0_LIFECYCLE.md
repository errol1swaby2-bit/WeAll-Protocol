# Human Uniqueness, Registration Friction, and Optional Tier-0 Lifecycle

Status: normative P0-06 design target for PR #38. A15-F003 remains closed by the separately documented account-registration scarcity invariant.

This document separates three protocol concerns that must not be collapsed into one mechanism:

1. permanent account-state admission scarcity;
2. one-human authority / duplicate identity adjudication;
3. optional future Tier-0 compaction and storage hardening.

The mechanisms are deliberately layered. A mechanism may contribute defense in depth outside its primary security role, but it must not be credited with properties it does not establish.

## 1. Account registration proof-of-work

Account-registration work is retained.

For A15-F003, registration PoW is the protocol-level scarcity mechanism that closes free fresh-key permanent-state creation. The proof is consensus-enforced, finite, nonzero in the production/public-testnet policy, and bound to the registration identity and payload as specified in `ACCOUNT_REGISTRATION_SCARCITY.md`.

For A08/P0-06, the same mechanism is only passive anti-Sybil friction. It MAY:

- raise the marginal computational cost of automated bulk account creation;
- slow simple registration floods;
- make large fresh-key farms more expensive to create.

It MUST NOT:

- establish personhood;
- establish one-human-one-account uniqueness;
- grant PoH authority;
- grant reputation, voting, governance, reviewer, validator, or civic authority;
- be consumed by protocol logic as evidence that two accounts belong to different humans;
- be described as a hard lifetime account-count bound.

A high-resource actor can perform proportionally more work. Registration PoW is therefore valid permanent-state scarcity and useful Sybil defense in depth, but it is not the authoritative human-uniqueness decision mechanism.

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

Reviewer selection MUST satisfy A20-F001 before production positive human-authority creation is enabled:

- the request/challenge context is irreversibly committed before selection entropy becomes knowable;
- applicant-controlled labels such as `case_id` are not entropy;
- retry/replacement counters are not new entropy sources;
- applicant and proposer skip/retry grinding is bounded or impossible by protocol rule;
- withholding/minority-bias behavior is explicitly modeled;
- restart and state-sync reproduce the same committed selection outcome;
- replacement selection cannot create an unbounded second panel-search surface.

The deterministic ML-DSA-signed beacon currently used by WeAll is authenticated and reproducible but is not an unpredictability primitive. It must not be represented as satisfying A20-F001 by itself.

Until the required uniqueness and entropy properties are implemented and proven, production positive PoH authority remains fail-closed through the consensus-visible `scope_closed_pending_uniqueness_entropy` mode. Existing challenge/revocation safety paths remain available.

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

## 7. Optional Tier-0 lifecycle hardening

A deterministic provisional-account lifecycle or compact tombstone scheme may still be valuable as future storage hardening, but it is not required to reinterpret A15-F003 after the registration-PoW closure already proved on PR #38's preserved closure lineage.

If future protocol work adds Tier-0 compaction, it must preserve replay, identity, duplicate-challenge, recovery, restart, and state-sync safety. In particular, it must not depend on local wall-clock time, local database size, node-specific garbage collection, or nondeterministic memory pressure.

Any future compaction design must be reviewed as a consensus-state migration in its own right rather than smuggled into P0-06 as an unrelated merge blocker.

## 8. Required evidence before P0-06 closure

### A08-F001 — human uniqueness

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

### A20-F001 — reviewer anti-grinding

Closure additionally requires:

- commit-before-unpredictable-entropy selection;
- explicit bias/withholding security model;
- proposer/applicant retry and skip-grinding regressions;
- replacement-panel grinding regressions;
- multi-validator tests;
- restart/state-sync tests;
- deterministic property/Monte-Carlo evidence where appropriate.

## 9. A15-F003 closure boundary

A15-F003 remains owned by `ACCOUNT_REGISTRATION_SCARCITY.md` and the preserved exact-head P0-10 evidence. Its claim is intentionally narrow:

- free fresh-key permanent-state creation is no longer unbounded because every production/public-testnet registration pays finite identity-bound computation;
- the work cannot be reused across signer/nonce/chain/payload identities;
- the mechanism does not establish one-human uniqueness;
- it does not claim a hard lifetime maximum on legitimate accounts.

Human uniqueness remains A08. Reviewer anti-grinding remains A20.

## 10. Claim boundary

Until P0-06 implementation and evidence are present on one exact commit/tree:

- registration PoW may be described as the A15 permanent-state scarcity mechanism and as passive anti-Sybil friction;
- registration PoW must not be described as human-uniqueness proof;
- P0-06 remains open;
- production positive PoH authority remains scope-closed pending uniqueness + entropy closure;
- stronger release claims remain fail-closed until the same-tree ledger, generated artifacts, full suite, reviewer-readiness and normal CI all agree.
