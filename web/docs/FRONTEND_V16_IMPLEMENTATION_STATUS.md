# Frontend v1.6 — stacked implementation status

**Baseline**: PR #81 at `c5f66b9c602630384da944e93fcdfec45126c8d8`. This is a **draft increment** for the v1.6 product specification, NOT a completed implementation or release authorization.

## Implemented in this first increment

- A fixed, five-destination main navigation (Home, Feed, Groups, Decisions, Account), with account/session gating unchanged.
- A group-first, URL-addressable public profile with focused Posts, About, Members, Governance, and Emissaries tabs.
- Existing group data reads, signed membership actions, moderator membership decisions, post reporting and public emissary election views retained on their applicable panels.
- Mobile bottom navigation, keyboard focus visibility and scrollable group section tabs.

## Pending before calling the full v1.6 frontend implemented

- Identity, backup/restore, and verification journeys separated into task-focused routes and validated on the live controlled-devnet.
- Separate public profile presentation and *authorized* public profile backgrounds/media publication.
- Group-specific decisions, role desks, treasury public transparency and emissary workspaces (where authoritative backend contracts actually support actions).
- Dedicated review lane workspaces, canonical receipt/failure states, social/content moderation lifecycle, node operator workspaces, settings and theme import/export.
- All existing route aliases, all remaining v1.6 journey contracts, browser history, accessibility, desktop/mobile visual regression and independent process backend/frontend tests.
- Unresolved source validation issues in the PR #81 integration base must remain open. No production activation, fund transfers, validator authorization or new consensus semantics.

**Do not merge** until the full intended frontend behavior is implemented, independently tested and reviewed. P2P private messaging, private profile wallpaper and arbitrary executable themes remain **out of scope**.
