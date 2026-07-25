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

## Implemented protocol corrections and remaining evidence boundary

The M3 freeze candidate implements the previously blocking protocol corrections:

1. Protocol-wide rounds snapshot eligible Tier-2 humans, and group rounds snapshot eligible group members. Configured validators are not political principals unless independently present in that human electorate.
2. The first admitted final ballot is immutable; duplicate, replacement, and revoke attempts fail deterministically in the controlled-testnet ballot profile.
3. Each round freezes its denominator. A deterministic SYSTEM transition closes an unmet round without decision, opens a new versioned electorate round when permitted, and eventually expires with an explicit no-decision receipt.
4. Governance, dispute, appeal, and group-election choice state is aggregate-only under the strict profile; participation nullifiers remain separate from choices.
5. Review assignment uses deterministic severity-sized panels, substitutes, conflict exclusions, and a fresh appeal panel disjoint from the original panel.
6. Accepted reports receive either a canonical dispute enqueue or a deterministic pending-escalation repair record, and public-content mutation appends an immutable receipt chain.

These source-level corrections do not close M3 by themselves. The active round denominator never drifts in place, but the complete behavior must still be demonstrated through the non-skippable real stack, frontend build, restart/replay, two-node equality, observer catch-up, privacy scan, and evidence-only direct-child gates.

The real-stack node must be created with the strict controlled-testnet ballot
profile recorded in genesis state: `m3_civic_governance_strict=true`,
`ballot_profile_id=controlled-testnet-aggregate-v1`, and
`ballot_profile_active=true`. Closure tooling must reject legacy/local ballot
behavior even when all later state reads appear correct.

The real-stack proof must bind every positive transition to a confirmed canonical transaction ID and must submit the required negative attempts from independent browser custody states. Read-only inspection of a pre-seeded final state is not closure evidence. The strict low-severity review/appeal proof requires at least 18 independent reviewer candidates so both panels and both substitute sets can remain disjoint.

## Supported claims after closure

After valid closure, the repository may claim that:

- independently controlled Tier-2 accounts can create and inspect public content;
- public group reads remain available to nonmembers while charter rules gate participation;
- a signed report becomes a public, reviewable dispute record;
- selected reviewers accept, attend, vote, withdraw or time out through canonical signed transactions;
- appeals use fresh eligible reviewers where required and produce append-only public correction/finalization receipts;
- proposal creation, discussion, versioned electorate-round capture, bounded quorum refresh, ballot admission, close, tally, and finalization are block-height controlled;
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
