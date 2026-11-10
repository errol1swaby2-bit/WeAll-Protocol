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

## Group responsibility / membership-moderation increment (2026-11-10, pending CI)

- Added exact-group deep links `/groups/:id/responsibilities` and `/groups/:id/manage/members` resolving to the same canonical group object rather than treating a task suffix as part of the group ID.
- Group responsibilities are now a signed-in contextual dashboard. Member participation, moderator membership reviews, and unsupported emissary/treasury action desks are explicitly distinguished. This presentation does **not** grant any role.
- The public Members tab no longer houses moderator approval controls. The separate membership desk reveals pending applicant identifiers and approve/reject actions only when an authenticated local signer is present, the account is listed as a moderator in the returned group state, and the group's membership mode requires approval. An unassigned or anonymous visitor sees no pending applicant list in this UI.
- Before submitting the existing signed `GROUP_MEMBERSHIP_DECIDE`, the client fetches fresh group state and fails closed unless the moderator is still listed and the exact request remains pending. Backend authorization and inclusion are still independently required. There are no new transaction types or administrative shortcuts.
- Added fail-closed source checks to `test:v16-navigation-source`. **Build, browser acceptance, and exact-head CI results are not yet verified for this new increment.** A canonical read model may omit restricted membership requests; that condition blocks actions here rather than assuming permission. PR #88 stays **DRAFT / NO-GO**, and existing backend/reviewer/focused-P1 failures remain unresolved.

## Public group report matching and role desk boundary (2026-11-10, exact-head CI pending)

- Public `/groups/:id/reports` matches disputes to a group **only** from canonical target snapshot `group_id` or a post ID returned by that group's public feed. Both inputs are capped; no exhaustive case count, hidden-post visibility, or unsupported `group_id` dispute filter is claimed. Unavailable or mismatched sources fail closed.
- `/groups/:id/manage/moderation` is a role-context routing desk, not a new content-removal or juror voting authority. Group moderators can follow group public reports and navigate to the existing independent dispute reviewer queue, which retains its own opt-in, assignment, and signature gates.
- `/groups/:id/emissaries/work` states that executable elected mandate/term/timelock/receipt data is not available, rather than creating unsupported work controls.
- Canonical moderator role representations may be arrays **or** object maps. Both the UI listing and the fresh pre-sign check now normalize these representations. A map/list is still only preflight; backend `GROUP_MEMBERSHIP_DECIDE` authorization remains authoritative.
- The v1.6 test now exercises the actual scope classifier and role-list normalization using transpiled pure TypeScript, in addition to source checks.
- No new consensus transactions, private evidence reads, treasury spending, or emissary execution. PR #88 remains **DRAFT / NO-GO**.
## Group-bound decisions and emissary election read-only detail (2026-11-10; exact-head CI pending)
- A dedicated `/groups/:id/decisions/new` action route now opens the existing signed `GOV_PROPOSAL_CREATE` composer in a canonical group context. The action route is resolved before the group-ID catch-all; the group ID and `group_members` electorate are fixed and checked by the client before signing. A fresh `/v1/groups/:id/governance-contract` read must confirm exact group identity immediately before submission. The backend remains authoritative over member/proposer eligibility, inclusion and execution.
- Group-context creation intentionally disables advanced JSON/action payloads and shows a record-only decision. A nonmatching group, stale group contract, or conflicting `scope_id` fails closed instead of falling back to protocol-wide creation. This is a UI safety boundary, not proof of protocol-level protection.
- New public emissary election index/detail deep links consume only current active election summaries returned by the group governance contract. Candidates, voter snapshots, election clock boundaries, closed history and ballot/finalization read models are **not** supplied; thus **no ranked ballot, election creation, forced finalization or term activation UI** was enabled. No winner claims on absent data.
- Added route-resolution, group-scope, fresh-contract and election safety checks to the v1.6 frontend gate. Full cross-account browser acceptance and exact-head CI must be assessed separately. No protocol rules changed.

## Backend canonical group-election read API and frontend inspection (2026-11-10; exact-head CI pending)

- `GET /v1/groups/:id/elections` returns a bounded, paginated current-state index of **open, finalized, and no_decision** group election records. `GET /v1/groups/:id/elections/:electionId` returns one exact-scope record or 404.
- The response allowlists candidate accounts, seats, chain-height windows, observed height, status and finalized winners. Internal payloads, full voter snapshots, ballot maps and nullifiers are not serialized. `viewer_in_voter_snapshot` is null unless a valid backend account session authenticates the requester; no URL/query account is trusted for that check.
- Frontend election index/detail now call these new canonical read routes and reject mismatched scope and source. Current-state counts do not prove completeness of chain-history archives; index rendering is limited to the first 100 records and exposes a clear pagination warning.
- Neither route creates a ballot, grants an emissary or authorizes group treasury execution. These are **read-only projection contracts** requiring separate signed ballot and runtime authorization work. Backend focused tests and v1.6 source checks cover these boundaries. **DRAFT / NO-GO.**

- An independent scoped `Group election read-model focused evidence` workflow runs Ruff and targeted backend public-read plus canonical election-window/STV tests on the PR exact revision. It does not bypass or mark green the independent failing Backend CI generated-artifact gate. Test results must be checked before any acceptance claim.

## Local ranked-ballot preparation only — signed-envelope privacy blocker (2026-11-10, exact-head validation pending)

- Audited canonical `GROUP_EMISSARY_BALLOT_CAST` schema, browser signer, HTTP ingress and runtime apply path. The signed envelope includes the identifiable `signer` and **plaintext `ranking`**. Strict ballot mode aggregates local apply-state ballots but **cannot undo exposure through signed transactions, propagation, logs, or chain history**. A secret ballot is NOT established merely by `ballot_profile_active` or anonymous apply-state tables.
- Public election reads explicitly advertise `ballot_transport_disclosure=signed_envelope_contains_signer_and_plaintext_ranking`, `ballot_transport_privacy_verified=false`, `secret_ballot_supported=false`, and `ballot_submission_authorized=false`.
- Group election detail includes a **browser-memory-only local ranking rehearsal**: add candidates, move them higher/lower, remove or clear. The component has NO network, persistent storage, signing, transaction dispatch, or export action. It resets on election/record changes and unmount; an observer of the screen can still see the draft. Preparation checks exact group, status, candidate integrity, safe observed height window, and explicit privacy-readiness fields.
- These actions deliberately **do not cast a ballot**. Separate protocol work is required for confidentiality of a real transaction, cryptographically enforced eligibility/nullifiers, safe anonymity and replay, plus live multi-account/multi-node finality evidence before enabling signed UI. No consensus behavior changed. **DRAFT / NO-GO.**
