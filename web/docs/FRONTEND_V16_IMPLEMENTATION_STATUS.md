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

## Confidential ballot design review and proof-of-current-risk (2026-11-10; exact-head CI pending)

- `Weall-Protocol/docs/production_readiness/GROUP_EMISSARY_CONFIDENTIAL_BALLOT_DESIGN_V0_1.md` characterizes today's signer-plus-plaintext-ranking disclosure in the schema, ordinary browser signing, tx admission/propagation and block history. It distinguishes current strict aggregate apply-state protection from **unproven voter-choice confidentiality**.
- The document is an explicit **non-normative design input**. It sketches research questions around anonymous snapshot eligibility proofs, election-scoped nullifiers, encrypted ranked ballots, publicly verifiable mixing/decryption and deterministic STV transcript proofs; no cryptographic suite or protocol change is selected/activated.
- `tests/test_group_emissary_ballot_transport_boundary.py` is a focused current-risk regression: it proves the signed-envelope contains the signer and ranking, even with an active strict testnet profile, while the public election flags remain no-secret/no-submit. This demonstrates the present blocker; it does **not** prove anonymity, secure encryption or cryptographic soundness.
- The existing group-election focused CI records the new test and document hashes, and carries the explicit `secret_ballot_transport=NOT_VERIFIED` scope. No consensus implementation, fee path, ballot signer, ballot submission UI, generated V2 registry or constitutional approval was changed. **DRAFT / NO-GO.**

## Group emissary confidential-ballot ADR and machine-readable review gate (2026-11-10; exact-head CI pending)

- Added `GROUP_EMISSARY_CRYPTO_ARCHITECTURE_ADR_V0_2.md`: select classical verifiable shuffle + threshold-decryption solely as a **feasibility baseline** for full-ranked STV, explicitly not a deployable or PQ-approved scheme. Compare PQ anonymous-proof + verifiable ranked decryption, private-ZK STV, homomorphic first-choice totals (rejected for STV), and ML-KEM-only encryption (rejected as a complete voting protocol). Sources include NIST FIPS 203/204, ElectionGuard's ranked-choice limitation and Verificatum's classical reference.
- New `specs/research/group_emissary_ballot_architecture_v0_1.json` machine-readable matrix and `scripts/validate_group_emissary_architecture_review.py` enforce **NO_GO, no selected production primitive suite, no alleged PQ security, no ballot submission or new tx types, and no invented benchmarks**. Validator checks full-election context binding, research options, release gates, and low-end 4 GB RAM laptop measurement target.
- Added negative-mutation tests to prevent accidentally marking approval, privacy, resource evidence, or unsupported shortcuts true. Group-election focused CI now hashes these artifacts, checks Ruff and manifest, and runs all focused tests. This review infrastructure does **not** implement cryptography or replace consensus authorization/approval.
- No changes to tx schema, runtime apply, signing, genesis, treasury, reviewer eligibility, or frontend ballot submission. PR #88 **DRAFT / NO-GO**; exact-head CI pending.

## T0 WeAll sequential preference redistribution vectors (2026-11-10; design clarification)

- Added ten behavioral fixtures (including a five-seat full-weight redistribution sequence), an independently coded no-Fraction current-behavior tally reference, and focused tests for canonical helper equality, ordering stability, ties, partial/exhausted preferences, duplicate/unknown ranking normalization, minimum-seat fill, and no-decision/treasury preservation.
- **Corrected understanding from protocol architect:** After each seat is awarded, a voter's full ballot weight follows their next highest still-eligible ranked candidate. This is WeAll's INTENDED sequential redistribution behavior, even though it is not conventional surplus-retaining STV. The prior classification of that behavior as a defect is **withdrawn**. No quota-retaining consensus correction or historical replay migration is indicated by this behavior alone. The current helper docstring should not be treated as an exact normative STV specification.
- In one-ballot five-seat scenarios, current finalization can seat five emissaries and update group treasury signer authority. With zero valid ballots, finalization must instead return no_decision with no authority transfer. The focused runtime apply tests characterize both without changing consensus.
- All vectors and the reference oracle remain **research/evidence only**; no confidential ballot submission, protocol rule, or elected authority activation was added. Exact-head focused and release-gate results pending. **DRAFT / NO-GO.**

- **Correction evidence:** The design-author clarification supersedes the prior “surplus-transfer defect” and “must fix STV” framing. The research corpus now explicitly records the intended transfer rule, renames the two-seat vector, and adds a canonical five-seat A→B→C→D→E sequence. Other election, quorum, privacy and CI limitations remain open. Exact-head validation pending.

## Versioned group emissary quorum v1 — explicit governance activation only (2026-11-10; CI pending)

- Architect policy: emissary voting requires a participation quorum like regular governance. Exact default is `ceil(2 × eligible_members / 3)` against a frozen group voter snapshot; 20 eligible members require 14 valid unique ballots. Successful ballots are counted from canonical legacy or strict-profile aggregate ballot state; rank count never substitutes for voter turnout.
- Implemented a **default-unset** governance-whitelisted activation-height parameter and immutable per-election `quorum_policy_version=1` metadata. Elections created before activation retain historical behavior; new activated elections produce committed `no_decision` without changing group/treasury authority when turnout is below quorum. Read API exposes only aggregate status, threshold and tally.
- Added exact quorum math, pre/post activation, strict/legacy, one-ballot legacy compatibility, no-ballot and tampered snapshot negative regressions. **No parameter is set or election is activated in this PR**, and no constitutional authorization or confidential ballot is claimed. DRAFT / NO-GO.

- **Activation blocker:** regular group governance filters group members by active account standing and PoH Tier 2; current group emissary snapshots are membership-only. The new quorum mirrors governance's default arithmetic, **not yet the eligible-electorate predicate**. A regression demonstrates this distinction. Do not activate until eligibility parity or deliberate differentiation is reviewed.

## Quorum v1 electorate alignment (2026-11-10; exact-head validation pending)

- Newly versioned **activated** emissary elections now reuse canonical group-governance `_active_group_member_ids` for their frozen voter snapshot, including active membership, an existing eligible account record, PoH Tier 2 by default, and account standing. No eligible voters causes fail-closed rejection. The persisted electorate source and normalized count are verified again at finalization before any signer transfer.
- Historical/pre-activation elections remain unchanged, including raw member snapshots. The review tests distinguish frozen-snapshot eligibility from later status changes and verify ineligible accounts cannot cast against a newly created active election.
- This aligns the **default group electorate predicate and quorum arithmetic** without introducing new governance overrides or a ballot privacy scheme. No activation parameter is set. Constitutional review, independent process replay/finality, and release gates remain unresolved. **DRAFT / NO-GO.**
