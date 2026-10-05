# Human Uniqueness, Registration Friction, and Optional Tier-0 Lifecycle

Status: PR #38 P0-06 is **CLOSED — SCOPE-CLOSED AND PROVEN** by making new production PoH human-authority creation unreachable until separately reviewed uniqueness and reviewer-entropy protocols exist. A15-F003 remains closed by the separately documented account-registration scarcity invariant.

This document separates three protocol concerns that must not be collapsed into one mechanism:

1. permanent account-state admission scarcity;
2. one-human authority / duplicate-identity adjudication;
3. optional future Tier-0 compaction and storage hardening.

The mechanisms are deliberately layered. A mechanism may contribute defense in depth outside its primary security role, but it must not be credited with properties it does not establish.

## 1. Account registration proof-of-work

Account-registration work is retained.

For A15-F003, registration PoW is the protocol-level scarcity mechanism that closes free fresh-key permanent-state creation. The proof is consensus-enforced, finite, nonzero in the production/public-testnet policy, and bound to registration identity and payload as specified in `ACCOUNT_REGISTRATION_SCARCITY.md`.

For human uniqueness, the same mechanism is only passive anti-Sybil friction. It MAY:

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

A high-resource actor can perform proportionally more work. Registration PoW is therefore valid permanent-state scarcity and useful Sybil defense in depth, but it is not proof of human uniqueness.

## 2. Tier 0 is an account, not a human

Successful `ACCOUNT_REGISTER` creates a Tier-0 account only.

Tier 0 carries no implication that the account represents a unique human. Any future production human/governance authority must cross a separately reviewed PoH authority boundary.

## 3. Current P0-06 production closure

PR #38 does **not** claim to have solved global human uniqueness or constructed an unbiasable randomness beacon.

Instead, production genesis commits:

`params.poh.human_authority_mode = scope_closed_pending_uniqueness_entropy`

Under that consensus-visible mode:

- positive PoH authority creation and advancement paths fail closed;
- async, Tier-2, and Live schedulers do not create new positive human-authority work;
- direct award helpers fail closed;
- challenge, revocation, and evidence-safety paths remain available;
- non-production compatibility paths remain testable without being represented as production authority.

This removes A08-F001 and A20-F001 from the reachable production authority surface. The P0-06 closure claim is therefore a **scope closure**, not an assertion that the missing uniqueness or unpredictability primitives were invented inside PR #38.

## 4. Existing duplicate-identity safety primitives

The repository retains adjudicable duplicate-identity challenge primitives as defense in depth and as groundwork for a future human-authority protocol.

An eligible verified-human challenger may identify:

- a challenged account; and
- a reference account alleged to represent the same human.

Opening a challenge does not itself revoke either account. The canonical record distinguishes allegation from adjudicated fact, reserves an unordered account pair against parallel/reversed challenge grinding, and records that reviewer selection is deferred pending a separately reviewed entropy mechanism.

If a duplicate decision is upheld through the authorized system path:

- the challenged duplicate loses active PoH authority;
- a canonical duplicate relation is recorded;
- ordinary PoH re-award is blocked while that confirmed relation remains active.

If an upheld decision is later dismissed/overturned:

- the duplicate-authority block is removed canonically;
- prior PoH authority is not silently resurrected;
- ordinary reverification is required before authority can be re-awarded in a profile where positive authority creation is enabled.

These primitives do not change the production scope closure: production positive human-authority creation remains unreachable.

## 5. Future re-enablement requirements — uniqueness and adjudication

Re-enabling production positive PoH authority is a new protocol feature, outside the P0 closure implemented by PR #38.

Before re-enablement, the protocol requires a separately reviewed human-uniqueness/privacy/adjudication design with evidence for at least:

- who may initiate duplicate-identity challenges and under what anti-abuse rules;
- independent adjudication authority and conflict exclusions;
- no automatic punishment merely because analytics or a challenger flags a pair;
- upheld duplicate relation and authority consequences;
- dismissal and false-positive recovery;
- appeal/overturn with reverification rather than silent authority restoration;
- conflicting or recursive duplicate relations;
- restart, replay, state-sync, and multi-validator equality for all authority effects;
- privacy boundaries for evidence and human-review data.

Analytics may surface or prioritize suspected duplicates, but they must not autonomously create canonical duplicate identity or revoke human authority.

## 6. Future re-enablement requirements — reviewer entropy

Reviewer selection for future production human-authority creation must satisfy A20-F001 before the scope-closed mode may be lifted.

At minimum:

- the request/challenge context is irreversibly committed before selection entropy becomes knowable;
- applicant-controlled labels such as `case_id` are not entropy;
- retry/replacement counters do not create fresh panel-search dimensions;
- applicant/proposer skip, retry, replacement, and withholding behavior is explicitly modeled;
- restart and state sync reproduce the same committed selection outcome;
- replacement selection cannot create an unbounded second panel-search surface;
- multi-validator/adversarial evidence supports the claimed bias resistance.

The deterministic ML-DSA-signed beacon currently used by WeAll is authenticated and reproducible but is not an unpredictability primitive. It must not be represented as satisfying A20-F001 by itself.

PR #38 intentionally leaves this future feature unimplemented and keeps production positive human authority fail-closed instead.

## 7. Optional Tier-0 lifecycle hardening

A deterministic provisional-account lifecycle or compact tombstone scheme may still be valuable as future storage hardening, but it is not required to reinterpret A15-F003 after the registration-PoW closure proved on PR #38's preserved closure lineage.

If future protocol work adds Tier-0 compaction, it must preserve replay, identity, duplicate-challenge, recovery, restart, and state-sync safety. It must not depend on local wall-clock time, local database size, node-specific garbage collection, or nondeterministic memory pressure.

Any future compaction design must be reviewed as a consensus-state migration in its own right rather than treated as part of P0-06 closure.

## 8. A15-F003 closure boundary

A15-F003 remains owned by `ACCOUNT_REGISTRATION_SCARCITY.md` and the preserved P0-10 exact-head evidence. Its claim is intentionally narrow:

- free fresh-key permanent-state creation is no longer unbounded because each production/public-testnet registration pays finite identity-bound computation;
- the work cannot be reused across signer/nonce/chain/payload identities;
- the mechanism does not establish one-human uniqueness;
- it does not claim a hard lifetime maximum on legitimate accounts.

Human uniqueness and reviewer unpredictability are not inferred from PoW.

## 9. Claim boundary

For PR #38 and its production profile:

- A15-F003 may be described as closed by account-registration scarcity;
- P0-06 may be described as **CLOSED — SCOPE-CLOSED AND PROVEN** only because new production positive human-authority creation is consensus-disabled;
- the repository must not claim that global human uniqueness or unbiasable reviewer entropy is implemented;
- the deterministic ML-DSA beacon must not be described as unpredictable randomness;
- any future re-enablement of production positive human authority requires separate protocol review, implementation, adversarial evidence, and activation gating;
- any follow-up commit after an exact-head closure invalidates the prior exact-SHA/tree binding until generated artifacts, claim/evidence bindings, the P0 assurance gate, the full backend suite, Reviewer Readiness, Web CI, and Secrets Guard are green on the new head; the final exact SHA/tree belongs in PR #38 metadata.
