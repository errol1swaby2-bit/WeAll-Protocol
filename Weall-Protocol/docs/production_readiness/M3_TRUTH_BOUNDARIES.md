# Milestone 3 truth boundaries

Milestone 3 (Reviewer Track R-M3) covers the controlled-testnet civic loop from a verified human action through public content, public-group participation, network review, appeal, governance voting, deterministic finalization, and public receipts.

M3 is complete only when its implementation-freeze commit and evidence-only direct child pass the canonical closure suite. Repository source tests or page-render checks alone are necessary but not sufficient.

## In-scope mechanism boundary

M3 closes the controlled-testnet portions of:

- `M-039`: posts, comments, reactions, shares, and media;
- `M-040`: moderation flags, public receipts, and dispute escalation;
- `M-041`: public-only read visibility and local-only controls;
- `M-042`: groups, memberships, roles, moderators, and signers;
- `M-043`: group-scoped posting and participation;
- `M-049`: proposal creation, editing, comment, withdrawal, and stage progression;
- `M-050`: ballot admission, voting close, tally, finalization, and receipts;
- `M-051`: human and group electorate snapshots;
- `M-054`: dispute opening, evidence, assignment, vote, and resolution;
- `M-055`: appeal, juror withdrawal/timeout, replacement, and enforcement;
- `M-056`: contextual reputation and eligibility outcomes without vote weighting.

## Blocking protocol corrections

M3 cannot close while either of these conditions remains:

1. Governance uses configured validators as political principals instead of the correct frozen Tier-2 or group electorate.
2. A voter can revoke or replace a ballot after the first ballot is admitted where the controlling specification requires first admitted final ballot finality.

Validators are not political principals. Threshold and quorum calculations must use a frozen denominator and exact integer arithmetic. Public receipts may prove ballot inclusion and aggregate outcomes, but they must not publish an identity-to-choice mapping where the controlling ballot contract forbids it.

## Supported claims after closure

After valid closure, the repository may claim that:

- independently controlled Tier-2 accounts can create and inspect public content;
- public group reads remain available to nonmembers while charter rules gate participation;
- a signed report becomes a public, reviewable dispute record;
- selected reviewers accept, attend, vote, withdraw or time out through canonical signed transactions;
- appeals use fresh eligible reviewers where required and produce append-only public correction/finalization receipts;
- proposal creation, discussion, frozen electorate capture, ballot admission, close, tally, and finalization are block-height controlled;
- ineligible voters are rejected and eligible voters have equal political weight;
- the complete scoped journey reproduces across restart/replay, two nodes, and observer catch-up;
- every closure artifact is hash-bound to the implementation freeze.

## Unsupported claims

M3 does not establish:

- public beta or Mainnet readiness;
- finalized production constitutional governance;
- executable protocol-upgrade, treasury, or economic action safety;
- emergency-governance completion;
- public validator admission or public multi-validator BFT readiness;
- live economics, treasury spending, rewards, or slashing;
- complete global anti-Sybil or anti-collusion protection;
- independent external security, legal, or governance review;
- completion of separate Reviewer Track R-M1.

## Explicit exclusions

The following mechanism targets remain outside this controlled-testnet M3 closure:

- `M-045`: group treasury signer and spend flow;
- `M-052`: executable governance-action hold, due execution, and deterministic remedy;
- `M-053`: emergency governance;
- `M-058`: production sanctions, account exclusion, and economic slashing;
- all R-M4 and R-M5 economic/validator launch claims.

A no-action civic proposal may be used for M3 finalization evidence. The UI and evidence must clearly distinguish that result from executing protocol software, economics, treasury, constitutional amendments, or node operations.

## Evidence boundary

A valid closure requires:

1. a clean implementation-freeze commit containing source, tests, runbooks, traceability, and closure tooling;
2. a non-skippable real-stack multi-actor browser journey;
3. backend, frontend, replay, two-node, observer, privacy, and receipt-integrity gates;
4. an evidence-only direct child containing only `artifacts/m3-closure/**`;
5. an independently verified manifest bound to the freeze commit and tree.

No source, configuration, test, specification, generated canon, or closure-relevant documentation may change in the evidence-only commit.
