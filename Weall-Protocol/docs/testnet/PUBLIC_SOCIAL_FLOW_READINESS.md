# Public social flow readiness

This checklist covers the bounded public observer / controlled testnet social surfaces: Feed, Create Post, Content Detail, Thread, public activity, and group-scoped social posts.

The goal is not public beta, mainnet, public multi-validator BFT, live economics, automatic protocol upgrades, production helper execution, legal approval, public validator safety, public storage-market readiness, or complete identity/Sybil infrastructure. The goal is to make public social actions understandable and honest for testers.

## Public-only boundary

Protocol-native social activity is public-readable:

- posts;
- comments and replies;
- reactions;
- reports/flags;
- group-scoped posts and comments;
- public activity records derived from those actions.

Group membership may gate participation, not read visibility. A group can require membership or governance status before posting, commenting, voting, moderating, inviting, or administering, but group content remains public-readable protocol state.

The frontend must not introduce private protocol-native messaging, private group read visibility, encrypted private social payload claims, or member-only read access.

## Transaction lifecycle wording

Social surfaces must keep these states separate:

1. draft exists in local browser form state;
2. signed envelope is being prepared;
3. backend accepted or recorded the submitted transaction;
4. the affected read model is refreshing;
5. backend transaction status reports confirmation/finality or rejection;
6. the feed/thread/content view shows the reconciled state.

A button click, local form state, local validation, upload success, mempool acceptance, or browser toast is not final confirmation. Social actions should use language like `submitted`, `recorded`, `updating`, `pending`, `rejected`, or `confirmed by backend tx status` rather than implying immediate finality.

## Required page behavior

### Feed

Feed should show:

- the active feed scope: public, group, or account;
- the endpoint/source that returned the visible items;
- backend ranking mode without claiming personalized production recommendations unless the backend reports it;
- read-only state for unsigned viewers;
- clear action gates for reacting and reporting;
- public social boundary copy;
- helpful empty states;
- reaction/report buttons that submit signed transactions and point testers to transaction status rather than implying final confirmation.

### Create Post

Create Post should show:

- account/session/signing readiness;
- posting eligibility without claiming real-world identity certainty;
- whether the audience is public or group-scoped public-readable content;
- upload, media declaration, signed post submission, and transaction status as separate steps;
- a path to Thread, Content Detail, and Transactions after submission;
- copy that says submission is not the same as visibility or finality.

### Content Detail

Content Detail should show:

- author, content id, visibility, group scope, and deleted/active state;
- whether the viewer is read-only, action-ready, or gated;
- author-only edit/delete boundaries;
- report behavior as community review input, not an immediate moderation outcome;
- transaction-status language for edits, deletes, and reports.

### Thread

Thread should show:

- the public post and public replies;
- viewer state and action gate;
- reply/reaction/report actions wired through the transaction queue;
- public social boundary copy;
- report links to community review when visible;
- no claim that a reply, reaction, or report is final just because the local page refreshed.

## Tester evidence to capture

For a social-flow transcript, capture:

- Feed empty state or visible feed item state;
- Create Post readiness cards;
- a post submission result with the Transactions link visible;
- the matching Transactions record showing recorded/pending/confirmed/rejected status;
- Thread view with public boundary copy;
- a reaction or reply submission showing transaction-status language;
- a report/flag submission showing community review status or honest delayed visibility.

## Stop conditions

Stop and file a bug if any social page:

- says a post, reply, reaction, or report is confirmed before backend transaction status or visible reconciliation supports it;
- treats mempool/local acceptance as final confirmation;
- hides public read visibility behind group membership;
- shows private protocol-native messaging or member-only group read access;
- says public beta, mainnet, public BFT, live economics, automatic upgrade, production helper, legal approval, public validator, public storage-market, complete anti-Sybil, or complete identity readiness is achieved.

## Allowed readiness statement

The strongest allowed claim after this flow works locally is:

```text
Ready for controlled internal/public-observer rehearsal candidate, with public beta readiness still blocked by explicit external evidence gates.
```
