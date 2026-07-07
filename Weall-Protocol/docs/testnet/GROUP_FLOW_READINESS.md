# Group Flow Readiness

Status: bounded public observer / controlled testnet readiness support. This document does not claim public beta, public mainnet, public multi-validator BFT, live economics, automatic upgrades, legal approval, or production helper execution.

## Purpose

A first-run tester should understand that WeAll groups are public civic coordination spaces. Group membership may gate participation, but it must not gate read visibility for protocol-native group content or group governance records.

## Tester-visible contract

A tester opening the group flow should be able to confirm all of the following without founder explanation:

1. The group directory is a public read surface.
2. Group detail pages are public read surfaces.
3. Joining or leaving a group is a signed transaction and must be tracked through transaction lifecycle status.
4. Creating a group submits a public charter; it does not create a private room.
5. Membership may gate posting, commenting, voting, moderation, invitation, and administration.
6. Membership must not gate reading protocol-native group content.
7. Group admins, moderators, signers, and emissaries are not unilateral owners.
8. Group authority follows the same governance mechanics that run the protocol, scaled to the size and scope of the group.
9. Emissary candidate lists, ballots/vote counts, winners, activation heights, and expiration/finalization state are public group-governance records when present in chain state.
10. Frontend cache state never grants protocol authority.

## Expected UI surfaces

### Groups directory

The directory should show:

- page purpose;
- number of visible groups;
- public read visibility;
- whether group creation is gated by account/Tier/session requirements;
- a safe next step for read-only testers.

### Group detail

A group detail page should show:

- group id;
- public read visibility;
- current membership state;
- signer threshold/count when available;
- active emissary election count when available;
- membership action state;
- recent public group activity;
- transaction-status guidance after membership/report actions.

### Group creation

The group creation page should show:

- public charter language;
- deterministic group id preview;
- account/session/Tier requirements;
- action lifecycle language that distinguishes submitted/recorded/visible/failed states;
- a reminder that group creation is not a private-space primitive.

## External transcript evidence to capture

For `AUD-628-P1-001`, the external observer transcript should capture:

```text
1. Open Groups while logged out/read-only.
2. Confirm group directory reads are public.
3. Open a group detail route.
4. Confirm group content/governance copy says public reads and member-gated participation.
5. Sign in or restore a tester account.
6. Submit a join/leave action if a safe test group exists.
7. Open Transactions and capture the tx lifecycle status.
8. Open the group detail route again and capture the visible membership/feed result or honest pending/fail-closed state.
9. Open the governance/emissary record section and capture active election/count information if present.
```

## Non-claims

This checklist does not claim:

- public beta readiness;
- public validator safety;
- public storage-market readiness;
- live token economics;
- automatic protocol upgrades;
- legal/compliance approval;
- complete Sybil/collusion resistance;
- private group support.
