# Frontend v1.6 — stacked implementation status

**Baseline**: PR #81 at `c5f66b9c602630384da944e93fcdfec45126c8d8`. This is a **draft increment** for the v1.6 product specification, NOT a completed implementation or release authorization.

## Implemented in this first increment

- A fixed, five-destination main navigation (Home, Feed, Groups, Decisions, Account), with account/session gating unchanged.
- A group-first, URL-addressable public profile with focused Posts, About, Members, Governance, and Emissaries tabs.
- Existing group data reads, signed membership actions, moderator membership decisions, post reporting and public emissary election views retained on their applicable panels.
- Mobile bottom navigation, keyboard focus visibility and scrollable group section tabs.
- Eleven compatibility aliases for proposed URLs, all resolving to existing backend-gated screens, without claiming new task implementation.
- The complete v1.6 design target is checked in as `FRONTEND_V16_PRODUCT_SPEC.md`; this status page identifies the implemented subset.
- Account Verification has URL-aware focus views for Overview, Record Evidence, Live Verification, Responsibilities, Case History and Technical Records. The signed PoH actions, public status and error banner remain in their existing component. Switching away from an actively recording async video is blocked by the local section navigation.
- Public Account has a canonical profile identity and public posts as the default view, plus separate Overview, Trust/Reputation, Eligibility, and owner-only Responsibilities/Node sections. This changes presentation, not canonical authority.
- Groups now show proposals explicitly scoped to their canonical group ID from a bounded public index. The treasury section accurately reports that no verified ledger or authorized payment workflow is available here; group duties link to existing signed-action surfaces only.
- V1.6 navigation/verification/account/group source-contract tests were extended with fail-closed scope and recording checks.
- Reviewer Center now exposes dedicated URL-addressable views for Overview, Content review, Dispute juror work, Async PoH, Live PoH and My Reports. The four reviewer queues preserve their original backend authority and signed actions; the reporter's own report-tracking list remains read-only and distinct.
- The previous `/reviews?lane=...` links remain supported. New `/tasks/content`, `/tasks/disputes`, `/tasks/poh-async`, `/tasks/poh-live` routes are focused view aliases, **not** separately implemented review engines or permission grants. The latest reviewer change is pending exact-head CI.
- Settings now has a category overview and focused Connection, Themes, Layout, Accessibility and Advanced panels. Eight bundled light/dark theme previews apply the existing safe client color controls and persist locally; there are no uploaded wallpapers, arbitrary CSS imports or public theme writes.
- Public profiles now display the backend's committed `banner_media.fetch_path` where supplied, with a visitor-side decorative hide control. The owner's `/me/profile-appearance` alias opens a focused public profile editor that can preview a public image CID and submit/replace `banner_cid` through the **existing signed `PROFILE_UPDATE`** skeleton. This is protocol-native public profile metadata, not a personal wallpaper; the image must already exist and be readable via the public proxy. No media upload workflow was added. **Removing a previously committed banner is not supported by the current canonical `PROFILE_UPDATE` schema**; blanking a preexisting CID is explicitly blocked rather than treated as a successful deletion.
- On-chain inclusion, media durability, authorization, legacy CID behavior and browser appearance acceptance require separate validation; the editor's submission toast is not definitive confirmation.
- Reviewer and appearance changes are both queued for exact-head Web CI. Actual browser accessibility and devnet PoH regressions are not proven by static assertions alone.

## Pending before calling the full v1.6 frontend implemented

- Finish identity key backup/restore and full independent verification journey splitting into route-level task modules; the current Verification stage tabs are an incremental UI improvement, not end-to-end delivery.
- Implement *authorized* public profile backgrounds/media publication with real backend contracts and durable receipts. The new public profile tabs do not publish media.
- Extend the initial group-scoped decisions index and honest treasury/role boundaries into complete paginated group proposal, emissary mandate and treasury read models once the backend exposes authoritative contracts. No spend or unsupported appointment controls.
- Complete each reviewer lane's independent task workspace, conflict/recusal evidence and acceptance flow; the new review queues are one frontend-only separation step. Canonical receipt/failure states, social/content moderation lifecycle and node operator workspaces remain unfinished.
- Add fully specified custom-theme editing, safe import/export validation, high contrast modes and follow-device handling; the current gallery only applies preset light/dark accent combinations.
- Add an authorized media-upload/crop flow for public profile banners; the current implementation intentionally accepts only already-published public media CIDs and does not claim an integrated upload flow.
- Complete the remaining v1.6 route aliases, all remaining journey contracts, browser history tests, accessibility, desktop/mobile visual regression and independent-process backend/frontend tests.
- Unresolved source validation issues in the PR #81 integration base must remain open. No production activation, fund transfers, validator authorization or new consensus semantics.

## Validation boundary
- Web CI and the rendered governance frontend regression passed on the preceding layout commits through `47241970cda4b559326758666d2454d14e903858`.
- Backend, focused P1 and reviewer readiness remain failing from the integration baseline; do not relabel them as passed.
- Latest exact-head CI, local browser acceptance, two-node PoH, real public profile publication, and cross-machine independence are **not yet proven** by this status note.

**Do not merge** until the full intended frontend behavior is implemented, independently tested and reviewed. P2P private messaging, private profile wallpaper and arbitrary executable themes remain **out of scope**.
