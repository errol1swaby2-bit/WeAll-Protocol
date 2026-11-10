# WeAll — complete product layout and navigation specification · v1.6

> **Implementation tracking note (2026-11-10):** This is the v1.6 DESIGN TARGET adopted for draft frontend PR #88. The source snapshot below was prepared before development began; see [the implementation status](FRONTEND_V16_IMPLEMENTATION_STATUS.md) for what the new branch has actually implemented. Do not interpret proposed routes or screen behavior as working code, and do not merge while blockers remain.

**Design baseline:** PR #81 (`integration/all-review-prs-70-80-20261104`), exact source `c5f66b9c602630384da944e93fcdfec45126c8d8`; **draft / unmerged**. As-is rows reflect source routes; every target route is a proposal until separately implemented. **No code changes made.**

**Design refinement v1.6 — messaging out of scope; public profile appearance only:** The proposed messaging module and per-conversation wallpapers/themes introduced in v1.5 are **withdrawn**. P2P/direct/private messaging remains **out of scope**, with no messaging routes, chat UI, theme settings or implied transport/encryption promises. Profile-specific customization is **public only**: its owner may deliberately publish a bounded background and appearance metadata, visible to other accounts and public visitors where profile reads are permitted. No private/owner-only profile wallpaper, visitor-specific profile theme, or private application image-wallpaper editor is part of this baseline. Visitors may suppress public decorative backgrounds for accessibility or reduced data use, but that is a viewing safety preference, not separate private profile styling.

**Retained from v1.4:** Public personal-profile background publication, preview as an outside visitor, replacement/removal with truthful canonical status, cross-account read behavior and visitor accessibility suppression.

**Retained from v1.3:** Device/browser-local **application color themes**, typography, spacing, contrast, motion and safe theme import/export, plus authorized group public visual identity. These are ordinary app-presentation preferences; they do not create private image wallpapers on public profiles or publish a theme to other users.

**Retained from v1.2:** Group-centered governance and responsibility dashboards, scoped treasury/elections and the public group profile with posts.

**Previous refinement v1.2:** WeAll uses a complete group-centric information architecture. Every group has a public community profile and its own posts, membership, charter, decisions, treasury transparency, emissary elections and scoped responsibilities. Role dashboards are entered from the group itself; global indexes cross-link canonical records but do not replace the group as their context. This document specifies **product behavior and navigation only**; it authorizes no code, protocol, economic activation or merge.

**Purpose:** establish a reviewable, cross-product information architecture and functional screen specification *before any implementation work*. The completed local observer PoH journey is user-observed usability evidence, not independent multi-machine validation. A previous `check_v15_artifacts` README check failed in the clean clone and remains unresolved.

## 1. North star and navigation decisions

**Default top-level navigation (five fixed positions):** **Home | Feed | Groups | Decisions | Account**. Global review assignments enter through a header task affordance and account responsibilities, not a permanent sixth social tab. Group-specific roles and mandates enter through the respective group profile, with only a contextual shortcut in the global task center. The Activity bell owns notices. Public Reports, Personal Node, Protocol Explorer, Settings and Help are in a labeled secondary menu. The normal navigation positions never jump according to tier.

**Page contract:** Hubs browse and route; detail pages explain one record; task screens do exactly one action; multi-stage review and PoH flows expose stage progress rather than stacking forms. Account self-management is distinct from the public profile of another person. **Group public profiles are distinct from group management, with scoped role-only duties reachable inside the group.** Page data are not protocol authority.

| Placement | Destination | Function |
|---|---|---|
| primary | `/home` — Home | Next action and personal overview |
| primary | `/feed` — Feed | Public social participation |
| primary | `/groups` — Groups | Community membership and public work |
| primary | `/decisions` — Decisions | Civic deliberation and ballots |
| primary | `/me` — Account | Identity, verification, and responsibilities |
| header | `/activity` — Activity bell | Notifications and public event notices |
| header-or-account | `/tasks` — My work | Assigned reviewer duties; not a global permanent nav item |
| menu | `/reports` — Reports | Public oversight is accessible regardless of reviewer status |
| menu | `/node` — Personal node | Operator and observer tools without crowding social use |
| menu | `/protocol` — Protocol | Public verification and locked-economics reference |
| account-menu | `/settings` — Settings | Preferences and node connection |
| account-menu | `/help` — Help | Task-specific guidance |

### Desktop shell (proposed)
```text
┌─ WeAll ───── Menu / nav ────────────── [Activity] [My work] [Account] ┐
│ Page title · one short explanation                   [help when needed] │
├───────────────────────────────────────────────────────────────────────┤
│ ONE PRIMARY TASK / ONE PRIMARY OBJECT                                │
│ summary / context → relevant content / form → status / next action    │
│                                                                        │
│ [local tab navigation within one object]     [Context drawer optional]│
└───────────────────────────────────────────────────────────────────────┘
```
**Mobile shell:** compact top bar (brand, notifications, account), content, stable five-destination bottom nav. Use in-page scrolled tabs or compact segmented control for object subviews; do not hide key safety text in a drawer. Live media stays the main viewport area.

## 2. Current information architecture — 28 implemented routes

**Global current shell:** compact menu + brand + Activity bell + Context & Status drawer toggle; then title, description, breadcrumbs, mode pill and contract note, plus a route-summary strip and the page itself. The same contextual data can reappear across shell, drawer, and screen.

| Area | Route | Screen source | Mode / current gate | Evidence of stacking |
|---|---|---|---|---|
| Entry | `/login` | `LoginPage.tsx` | utility / public | Sign-in, creation, key recovery, backup and connection settings in one component. |
| Home & attention | `/home` | `Home.tsx` | hub / session | Welcome, tester journey, launch walk-through, role guidance, pending work. |
| Home & attention | `/activity` | `Activity.tsx` | hub / session | Notices and notification preferences share page. |
| Social | `/feed` | `Feed.tsx` | hub / session | Feed browsing and entry points. |
| Social | `/create` | `CreatePostPage.tsx` | action / session | Composer, media, durability, checklist and payload diagnostics. |
| Social | `/post/:id` | `Content.tsx` | detail / public | Post content, account gates, management and raw payload. |
| Social | `/content/:id` | `Content.tsx` | detail / public | Second URL for shared content-detail component. |
| Social | `/thread/:id` | `Thread.tsx` | detail / public | Replies, composer and raw thread JSON. |
| Groups | `/groups` | `Groups.tsx` | hub / public | Discovery and available groups. |
| Groups | `/groups/create` | `GroupCreate.tsx` | action / session + T2 metadata | Charter composer and public-only boundary explanations. |
| Groups | `/groups/:id` | `Group.tsx` | detail / public | About, membership, posts, governance records, reports all stacked. |
| Decisions | `/decisions` | `Proposals.tsx` | hub / public | Open/closed decisions, lifecycle explanations, eligibility. |
| Decisions | `/decisions/create` | `ProposalCreate.tsx` | action / session + T2 metadata | Proposal form, execution caveats, raw submission metadata. |
| Decisions | `/decisions/:id` | `Proposal.tsx` | detail / public | Description, discussion, voting, lifecycle, editing and record history stacked. |
| Reports & reviews | `/reports` | `Disputes.tsx` | hub / public | Report directory and public dispute status. |
| Reports & reviews | `/reports/:id` | `DisputeDetail.tsx` | detail / public | Appeals, public timeline, evidence references, status. |
| Reports & reviews | `/reviews` | `JurorDashboard.tsx` | hub / session + T2 metadata | Four duty lanes, assignment queues, action buttons and advanced detail on one page. |
| Reports & reviews | `/reviews/:id` | `DisputeReview.tsx` | action / session + T2 metadata | Evidence/reviewer readiness and signed decision. |
| Verification | `/verification` | `AccountVerificationPage.tsx` | utility / session | Account readiness, local setup, async recording, live requests, case history, duties, diagnostics. |
| Verification | `/verification/live/:caseId` | `LiveVerificationRoom.tsx` | action / session/participant | Video, participant list, attendance/vote, connection troubleshooting, results. |
| Account | `/profile` | `Account.tsx` | utility / session | Identity/edit, reputation, eligibility, reviewer duties, node key onboarding and storage/validator/helper opt-ins. |
| Account | `/account/:account` | `Account.tsx` | detail / public | Same large component used for public account and own profile. |
| Account | `/session` | `SessionDevicesPage.tsx` | utility / session | Current browser, signed session records, passkey-style readiness and device history. |
| Account | `/settings` | `Settings.tsx` | utility / public | Node connection, display/accessibility, environment and technical settings stacked. |
| Protocol & node | `/node` | `NodeDashboard.tsx` | utility / public | Node health, identity, roles, sync, incidents, IPFS/storage, raw diagnostics all stacked. |
| Protocol & node | `/economics` | `Economics.tsx` | utility / session | Locked wallet/economics and network activation posture. |
| Protocol & node | `/advanced` | `Tools.tsx` | advanced / session + advanced | Status, readyz, diagnostics, flags, media, network surfaces. |
| Protocol & node | `/transactions` | `TransactionsPage.tsx` | advanced / session + advanced | Submission history, statuses and raw transaction records. |

**Source fidelity notes:** `/home` is a wrapper around `Home.tsx`; `/verification` wraps `AccountVerificationPage.tsx`; `/settings` wraps `Settings.tsx`. `Content.tsx` is used by `/post/:id` and `/content/:id`. Authorization labels here refer to client route metadata; actual API/consensus permissions require a separate backend audit.

## 3. Intended sitemap — every screen and subworkspace

The following **103 destination patterns** form the full target map. This is **not 103 top-level menu entries**: many are deep links, single-action steps, or tabbed views of a shared page template. No user-facing route from this section is asserted implemented just because it is listed.

### A. Welcome & account access · Entry

| Intended route | Screen / purpose | Access posture | Single primary action | Migration status |
|---|---|---|---|---|
| `/start` | **Welcome / choose path** (hub) — Create or restore account; read-only discovery and existing-network constraints. | everyone | Choose account path | new |
| `/auth/create` | **Create account** (task) — Key generation and explicit custody prerequisites; never assume network authority. | not signed in | Create account | new |
| `/auth/backup` | **Save recovery** (task) — Verify recovery file was saved; explain irreversible loss and local custody. | new account | Confirm saved | new |
| `/auth/restore` | **Restore account** (task) — Restore from key, verify against selected node, handle unsynced session. | not signed in | Restore session | new |
| `/auth/status` | **Account setup result** (detail) — Submitted versus confirmed account registration and recoverable errors. | session | Continue to Home | new |

### B. Home & personal attention · Home

| Intended route | Screen / purpose | Access posture | Single primary action | Migration status |
|---|---|---|---|---|
| `/home` | **Home** (hub) — One current next step, compact personal activity, 2–3 useful shortcuts. | session | Continue next step | retained |
| `/activity` | **Activity** (hub) — List of public-protocol-derived notices; unread is a client display state. | session | Open relevant item | retained |
| `/activity/preferences` | **Notice preferences** (utility) — Control display/attention only; does not alter protocol event truth. | session | Save preferences | new |

### C. Social feed & content · Feed

| Intended route | Screen / purpose | Access posture | Single primary action | Migration status |
|---|---|---|---|---|
| `/feed` | **Feed** (hub) — Public discussion feed. Browse, filter and open content; do not embed a full composer. | session (current) | Create post | retained |
| `/feed/new` | **Create post** (task) — Text, media, audience/public posting, signing and durable receipt. | eligible account | Publish signed post | new-alias |
| `/post/:id` | **Post** (detail) — Post body/media, reactions, visible moderation state, response entry. | public | Reply | retained |
| `/post/:id/report` | **Report post** (task) — One report reason, evidence preview, signed submission and result. | eligible account | Submit report | new |
| `/thread/:id` | **Discussion thread** (detail) — Reply sequence, composer if eligible; context stays visible. | public | Add reply | retained |
| `/people/:account` | **Public profile** (detail) — Public name/avatar, owner-published background, bio, public posts/groups and publicly verifiable roles; visitor accessibility determines decorative suppression. Never display private theme, device files or recovery data. | public | Browse posts | new-alias |

### D. Groups & communities · Groups — public community profiles and scoped responsibilities

**Product decision:** The group itself is the persistent container, comparable to an account's public profile. The public `/groups/:id` landing page includes identity (name/visual/description), exact scope, membership status, charter preview and **public posts first**. Everything below is reached through group-local navigation; only one content/workspace panel displays at a time. This supersedes the older idea of a general group workspace with governance sections stacked below the posts.

**Public group sections:** Posts, About / Charter, Members, Decisions, Treasury, Emissaries, Reports, Public Records. **Signed-in, responsibility-specific section:** My Group Responsibilities → role-specific desks (membership approval, moderation, emissary work), shown only when the canonical group role permits it. This does **not** imply group governance is private: public treasury decisions, election outcomes, accountability and related records remain readable wherever the protocol makes them public.

| Intended route | Screen / purpose | Access posture | Single primary action | Migration status |
|---|---|---|---|---|
| `/groups` | **Discover groups** (hub) — Search/filter public groups, membership previews, clear join status. | public | Explore group | retained |
| `/groups/new` | **Create group** (task) — Charter/scope/rules/publicity; signed create and canonical result. | eligible account | Create group | new-alias |
| `/groups/:id` | **Public group profile** (detail) — Group identity (name/visual, description, charter and geographic or organizational scope), membership status and public post stream; one-page overview like a public account profile. Treasury, elections, decisions and workspaces are links/tabs, not stacked administration. | public read; participation backend-gated | Read group posts / Join group | retained |
| `/groups/:id/join` | **Membership action** (task) — Request/join/leave with explicit pending/accepted/denied state. | eligible account | Request membership | new |
| `/groups/:id/manage` | **Group role workspace** (workspace) — Authorized group moderation and membership actions only; no independent treasury, election or protocol authority. Enter from the group profile and only after backend role verification. | canonical group-role holders only | Review pending work | new |
| `/groups/:id/posts/new` | **Group post** (task) — Create a post for this group while keeping group identity and scope visible. Signed posting eligibility is checked by the backend. | eligible group participant | Publish to group | new |
| `/groups/:id/posts` | **Group posts** (detail) — Full paginated stream of posts belonging to this group, with public replies and report entry. The group profile shows only a preview. | public read | Read group discussion | new |
| `/groups/:id/about` | **Group charter and scope** (detail) — Description, group charter, scope identity, rules, public membership policy and transparent links to scope-governance rules. | public read | Read charter | new |
| `/groups/:id/members` | **Members and membership** (detail) — Public membership and membership-state presentation limited to protocol-public data; requests and approval decisions have separate signed actions. | public read; member-only writes | View members / Request membership | new |
| `/groups/:id/decisions` | **Group decisions** (hub) — All canonical proposals filtered to this exact group scope, including stages, participation, outcomes, and group context. Global Decisions still indexes the same canonical proposals. | public read | Open group proposal | new |
| `/groups/:id/decisions/new` | **Propose within this group** (task) — Focused signed proposal creation prebound to group identity and exact governance scope; backend refuses mismatched scope, unauthorized votes or actions. | eligible group member under backend scope rules | Submit group proposal | new |
| `/groups/:id/treasury` | **Group treasury** (workspace) — Group-scoped public treasury balance/allocations, incoming/outgoing canonical records when available, constraints, pending decisions and approved results; no direct send control. Empty/unavailable states must be honest. | public record; sensitive operations gated | Inspect treasury / Propose allocation | new |
| `/groups/:id/treasury/propose` | **Propose treasury action** (task) — Create a group-scoped funding/allocation proposal, not an immediate transfer; explicit approval, timelocks and execution eligibility remain canonical. | eligible proposer under group governance policy | Submit funding proposal | new |
| `/groups/:id/emissaries` | **Emissaries and elections** (detail) — Current elected emissary seats/terms and public election history when protocol data exists, including unresolved or no-decision outcomes; no manual appointment control. | public read | Inspect representative roles | new |
| `/groups/:id/emissaries/elections` | **Group emissary elections** (hub) — Active/completed elections scoped to this group, ballot eligibility and tally/term evidence without invented winners; vote via canonical signed decision flow. | public read; eligible voting gated | Open election | new |
| `/groups/:id/emissaries/work` | **Emissary responsibility desk** (workspace) — Only assigned, explicitly approved, group-scoped execution/representation tasks, evidence of the authorizing proposal, expiry/mandate, and action receipts. No unilateral treasury or protocol powers. | currently authorized elected emissary for this exact group | Open authorized mandate | new |
| `/groups/:id/responsibilities` | **My group responsibilities** (workspace) — Private routing dashboard for member, moderator, reviewer (where applicable), and emissary duties in this one group. Missing role means no work controls. | signed-in account; data filtered to actual group roles | Open assigned group task | new |
| `/groups/:id/reports` | **Group reports and moderation record** (hub) — Group-filtered public reports, moderation outcomes, appeals and review states. Protected reviewer identity/evidence must not appear publicly. | public read; protected evidence restricted | Inspect report | new |
| `/groups/:id/records` | **Group public records** (detail) — Canonical group-scoped proposal, election, membership, execution and treasury audit receipts, with signed status and source provenance; only records actually exposed by protocol. | public read | Inspect official group record | new |
| `/groups/:id/manage/members` | **Membership approval desk** (task) — Dedicated queue for approval-required member requests, explicit eligibility/conflict checks and signed accept/reject receipts, separate from the public profile. | backend-authorized group membership moderators | Decide on one request | new |
| `/groups/:id/manage/moderation` | **Scoped moderation desk** (workspace) — Assigned group moderation tasks, reasons, action limits, appeal links and receipts; no protocol-wide report/juror shortcut. | specifically authorized group moderation actor | Inspect assigned moderation case | new |
| `/groups/:id/responsibilities/treasury` | **Treasury mandate desk** (workspace) — View approved funding mandates, expiry, required approvals and execution/record status; expose no execution control unless separately supported and authorized in canonical rules. | current group-specific mandate holder when one exists | Inspect authorized treasury mandate | new |
| `/groups/:id/emissaries/elections/:electionId` | **Emissary election detail** (detail) — Inspect one actual canonical election including scope, candidates, voting rules, deadline or no-decision outcome, and receipts; link to existing canonical ballot flow where implemented. | public read; eligible ballot gated | View election result / Cast eligible ballot | new |

**Public group profile wireframe:**

```text
← Groups     [Group banner/avatar]  Community name · scope · membership status
             One-paragraph purpose / charter summary     [Join / Request]

  Posts (default)   About   Members   Decisions   Treasury   Emissaries   Records
┌────────────────────────────────────────────────────────────────────────────┐
│  PUBLIC GROUP POST STREAM: posts, media, replies, engagement and reporting │
│  [View all posts]    [Create group post — when eligible]                    │
└────────────────────────────────────────────────────────────────────────────┘
  [Your group responsibilities] ← shown only to signed-in eligible members
```

**Treasury ownership:** `/groups/:id/treasury` is the **group's** public financial-accountability view, not the protocol economics page and not an ungoverned wallet. A funding proposal is authored at `/groups/:id/treasury/propose` and becomes a *canonical group-scoped governance proposal* (e.g. `/decisions/:id`); its submission, approval, authorization, executed effect and recorded ledger result remain distinct states. If group-treasury reads are not yet supported by the runtime, display **not available**, not an invented zero balance or fabricated transfer history.

**Emissary ownership:** `/groups/:id/emissaries` shows actual elected seats, terms, election process and public mandate records. `/groups/:id/emissaries/work` is an **authorized assignment desk for the currently elected emissary**, never a direct path to unilateral treasury transfer, system-wide protocol changes or privileged key possession. No-decision elections stay no-decision; no winner is inferred.

**Global vs local decision discovery:** `/decisions` indexes relevant proposals across communities, while `/groups/:id/decisions` filters the very **same canonical proposals** by exact group scope. One proposal ID, one set of receipts, and one source of truth. Back navigation and breadcrumbs return to the originating community without duplicating mutable state.

**Scope and identity:** Group scope is the protocol's canonical group identity (including territorial scope where defined), not an editable client label. A parent group must not gain authority over a subgroup, nor a subgroup over the whole protocol, merely through the shared UI. Verify any cross-scope delegation strictly against protocol rules.

### D.1 Group product model — normative screen and ownership specification

**Design rule G-001 — Group as a first-class public profile.** A group is a persistent public-facing civic/social object, like a person's public profile. Its canonical group ID and scope remain visible as users move between posts, governance, treasury, elections and tasks. A group is not a collection of unrelated global screens, and the group homepage is not its administration dashboard.

**Group object relationships (one authoritative record per object):**

| Belongs to group context | Shown primarily in | Cross-reference and truth rule |
|---|---|---|
| Identity, scope, charter, rules, membership policy | Group header and About | Identity/scope come from authoritative group state, never locally editable labels of authority. |
| Group-targeted public posts and replies | Group profile preview and Posts | Identical post IDs may also appear in Feed; there is no copied second post or independent reaction state. |
| Member and membership-request status | Members and Join; assigned requests in membership desk | Public records and pending applicant detail have different disclosure boundaries. |
| Group-scoped proposals, ballots and outcomes | Group Decisions | Identical proposal IDs, stages and tallies appear in global Decisions, subject to exact-scope filters. |
| Treasury availability, public balances/commitments, approved disbursements | Group Treasury | No manufactured balances, spend permission, or transactions. Link every available figure to canonical supporting records. |
| Emissary seats, elections, terms, assigned mandates | Emissaries; mandate desk for holder | A seat, approved mandate and execution capability are separate states. No valid outcome means no authority. |
| Reported group posts, public moderation and appeals | Group Reports | Reports are the same canonical objects in global Reports; private reviewer material stays protected. |
| Approved group actions and audit history | Group Public Records | A receipt exists only when supported by state/history; never infer applied/final from UI submission. |

#### G-002 · Public group profile — `/groups/:id`

**Default visual hierarchy:** (a) group name and optional public avatar/banner, (b) canonical group scope/type and succinct description, (c) contextual membership status and one eligible action, (d) public posts, with the newest visible items first unless a user explicitly changes sort. A short charter preview and an unobtrusive link to About are allowed. Do not render treasury balances, election ballots, administrative queues and technical state as successive cards below the feed.

**Primary call-to-action selection:** visitors see `Join` or `Request membership` only when permitted, otherwise `Sign in` or a truthful eligibility explanation. Members see `Create group post` if eligible, otherwise `View membership status` or the next allowed action. Pending applicants see `Request pending` without duplicate submissions. When no members/post data are available, show honest unknown/empty states, not fabricated counts.

**Group navigation:** `Posts | About | Members | Decisions | Treasury | Emissaries | Reports | Records` are public destinations. On narrow screens, render them as scrollable local navigation or an explicit `Sections` selector, never as eight permanently stacked panels. The private `My responsibilities` entry is separately identified and appears only for a signed-in user with current attributable group responsibilities or a truthful read-only duties overview. It does not appear as a public tab.

**Essential group page states:** loading; loaded with posts; loaded with no posts; not found; unavailable/stale node; member; pending approval; eligible nonmember; ineligible/locked; signer/session unavailable. A locally cached state cannot be shown as confirmed after a chain/identity mismatch.

#### G-003 · Group posts and membership

**Posts:** `/groups/:id/posts` is a paginated group-filtered public feed with sorting/filtering that never changes object ownership. `/groups/:id/posts/new` is a focused composer with group identity fixed and visible; a signed post may appear in global Feed too, but must retain its canonical group association and public report path. Author actions and moderation results must remain distinct from platform-level authority.

**Members:** `/groups/:id/members` displays only membership details intended to be public. The join/leave/request flow at `/groups/:id/join` exposes `not a member`, `pending`, `member`, `denied/withdrawn` only when the corresponding canonical state exists. Approval-required membership cannot be presented as accepted before the signed group decision is applied. Private reasons or requests, if the protocol protects them, belong only to authorized duty desks.

**Moderators:** approval of membership, scoped moderation and any other group administration occur via `/groups/:id/responsibilities` and the dedicated role desk, not via controls mixed into the public Members or Posts pages. An individual can have different roles in different groups; the current group's ID is mandatory in every role decision.

#### G-004 · Group-scoped proposals — `/groups/:id/decisions`

The group Decisions page is a **filtered view of canonical governance**, not a separate voting engine. It shows scope, author, proposal type, procedural stage, next deadline by authoritative chain height, participation eligibility and the result if final. A proposal created from `/groups/:id/decisions/new` starts with the exact group scope fixed and clearly stated; the action must be refused if the requested electorate/authority differs from canonical scope. For group-related votes opened through global `/decisions/:id`, the group breadcrumb persists and the proposal cannot silently switch to protocol-wide electorate or another group.

**Separate proposal types:** ordinary group deliberation, group procedural matters, emissary elections where modeled as governance, and treasury/funding proposals remain explicitly labeled. Their approval thresholds, eligible electorates, execution rules and record visibility come from the protocol—not an assumed universal group-majority rule. Users may discuss and observe a proposal without being able to cast a ballot.

**Decision states:** draft/created, open for deliberation, voting or paused, tally/result, eligible for execution, executed, rejected, withdrawn, expired or otherwise unavailable **only where those states actually exist canonically**. A UI tab selection is not a stage change. Public election secrecy, where applicable, is preserved.

#### G-005 · Group treasury — `/groups/:id/treasury`

**The treasury is a public accountability destination, not a wallet with a `Send` button.** It belongs beneath the specific group, not under a person's account and not as the protocol-wide Economics page. The read surface must distinguish: (1) **no treasury supported for this group**, (2) **feature/economics locked**, (3) **state temporarily unavailable or unverified**, (4) **supported but no recorded activity**, and (5) **canonical activity present**. An unsupported or unreachable balance is **not zero**. Never imply that WeCoin transfers or group-treasury execution are currently enabled.

Where available, show the public financial summary, asset/unit, proposed or committed amounts, decision links, encumbrances/reservations, executed transfers and audit receipts. For each line item disclose only protocol-public recipient details; provide its originating group proposal, approval status, authorized mandate, execution outcome and chain receipt when present. Totals must distinguish available, committed and spent amounts; no sum is authoritative without an identified canonical source.

A `Propose allocation` entry leads to `/groups/:id/treasury/propose`. It initiates a **group-scoped governance proposal**, never a direct payment. Approved treasury work, if supported, appears under `/groups/:id/responsibilities/treasury` for the exact authorized actor and exact active mandate, with purpose, upper bound, expiration, prerequisite approvals and final execution receipt. A user-facing action is unavailable if the protocol does not yet provide the required execution path. Treasury proposals can be publicly inspected even when signing/execution is locked.

**Treasury state chain:** proposed → canonically accepted into governance (if applicable) → approved or rejected → authorized/pending execution → executed or failed/rejected → final record. Do not skip or conflate stages; use actual runtime status names when mapped. Expiration, revocation, partial execution and double-spend protections are backend matters to expose accurately, not client-invented capabilities.

#### G-006 · Group emissaries — `/groups/:id/emissaries`

Public view: seats and offices defined by the actual group rules, current elected holders, term/expiry, active elections, completed or `no_decision` outcomes, and the public **mandate register**. Do not display a placeholder person as elected or assume the group has emissaries before canonical election/activation. If voting is available, election details show ballot eligibility and the actual voting method without exposing protected choices.

Emissary responsibility belongs under `/groups/:id/emissaries/work`, reachable through `/groups/:id/responsibilities`. It lists individual **authorized mandates**, not an unrestricted emissary control panel. A mandate must be traced to the sponsoring group, a specific passed/activated proposal or other protocol-authorized basis, its scope, allowable effect, limits, expiry/revocation, required signers and the receipt trail. Election alone does not confer independent fund custody, arbitrary group rulemaking, or protocol-global authority. A failed or zero-ballot/no-decision election grants no position or duties.

**Cross-group restriction:** holding an emissary seat in one group gives no authority in another group or at protocol scope merely because the user can navigate between them. If the elected person loses role eligibility or the mandate expires, signing controls become unavailable while public records stay readable.

#### G-007 · Group responsibility desks — `/groups/:id/responsibilities`

This signed-in work hub displays only that user's current duties **for the displayed group**: approved membership requests to review, specifically assigned moderation items, active emissary mandates, and approved treasury mandates if the protocol supports them. Each row includes group identity, duty type, underlying object, current authority/status, next permitted step, deadline, conflict/recusal marker if applicable, and authoritative receipt reference. The default is an actionable compact queue, not a summary of all governance infrastructure.

If the user has no assigned group duties, present `No current responsibilities in this group` and links to publicly view governance/elections—not disabled fake admin buttons. If a user has roles in multiple groups, `/me/groups` can show a count and link directly to each group's desk, but it does not become an alternative global source of authority.

**Duty-specific contracts:** `/groups/:id/manage/members` handles one applicant decision at a time with group-specific signed result; `/groups/:id/manage/moderation` handles only actually delegated group moderation; `/groups/:id/emissaries/work` handles elected and mandated tasks; `/groups/:id/responsibilities/treasury` displays approved treasury mandate status and any separately supported action. The backend must remain the gate for every write; showing or hiding a button is not authorization.

#### G-008 · Public records, oversight and scope boundaries

`/groups/:id/reports` filters public disputes/reports to this group; `/groups/:id/records` is the public accountability ledger of group identity, charter changes, membership decisions where public, proposals, elections, treasury decisions, mandates and canonical execution records. Sensitive applicant information, protected PoH evidence, private reviewer credentials and confidential vote content are never exposed through a public group route. Privacy redaction and public record completeness are separate requirements; redaction must not invent a clean history.

The group retains its canonical identity when users navigate to the global post, decision or report details. Parent/child territory names, city/country displays, and nested group labels are **navigation context only**; no group inherits voting power or admin rights in its parent, descendants or the entire protocol from a common URL structure. Related records carry explicit authoritative scope metadata. This design does not create a new scope hierarchy, electorate or override mechanism.

#### G-009 · Group empty, locked and failure states

| Condition | Required wording / behavior |
|---|---|
| Group exists; no posts | `No public posts in this group yet` with action only if posting is currently eligible. |
| Public group data not returned | `Group information unavailable` or `Could not verify the current group state`; do not show zero members or an empty ledger as fact. |
| Not a member | Public reading remains available; eligible join/request action shown separately. |
| Membership approval pending | `Request pending`; provide status and prevent duplicate signed submission. |
| Treasury not supported | `Treasury records are not available for this group`; avoid transfer controls and fake balance. |
| Treasury supported but locked | `Treasury actions are not enabled`; public rules and recorded proposals remain inspectable. |
| Emissary seat vacant or election no-decision | `No elected emissary for this position` / `No decision reached`; no duty controls or inferred appointment. |
| Role or mandate expired | Public mandate history remains, action desk becomes read-only; prompt a safe authorized next step. |
| Signed group action submitted, not applied | `Submitted — awaiting canonical result`; show transaction/case reference and avoid blind resubmission. |
| Canonical rejection or stale node | Distinguish rejected apply from node/connectivity problems; do not substitute optimistic cached success. |

#### G-010 · Responsive density, accessibility and explicit acceptance

At desktop width, keep group identity and scope anchored in the header while only **one chosen section** occupies the primary content area. On mobile, the identity banner may compress but never hide the group name, scope or current membership status. Section navigation must be keyboard accessible, show active focus and retain deep links/back navigation. No group treasury ledger, emissary election table or member queue may require horizontal whole-page scrolling. Disable no public read route merely because the visitor has no signing key.

**Group acceptance scenarios (specification, not implementation):**

| Scenario | Product acceptance condition |
|---|---|
| Visitor opens public group link | Sees group profile, scope, post preview and links to public sections without signer; no private role data. |
| Member publishes a group post | Composer remains group-scoped; signed status truthful; same canonical post appears in group posts and appropriate global index. |
| Applicant requests approval-required membership | Shows pending state, not joined; authorized approver sees separate request in the right group's desk. |
| Ordinary member inspects treasury | Sees public supported records or an explicit locked/unavailable state; no spend button. |
| Eligible member proposes group funding | Creates a scoped proposal, not transfer; global and group decisions reference one ID. |
| No valid emissary election outcome | Public election remains `no decision`; no new role, mandate or treasury authority is implied. |
| Elected emissary opens group duties | Only current mandate for that group is displayed, with approvals and expiry; unrelated group/protocol actions inaccessible. |
| Moderator reviews a report | Exact role, group and case checked; public report shows outcome without leaking protected evidence. |
| A proposal or receipt changes on a different node | Stale/mismatched state is identified, signing closes safely, and canonical chain identity is visible. |
| User moves between group and global decision detail | Group breadcrumb and proposal scope persist; history/back returns to the same group section. |

**Exclusions:** This product map does not activate any locked economics, write new treasury execution rules, establish new emissary powers, define a new member electorate, grant moderator/admin shortcuts, or assert these new group screens are implemented. Any such capability needs its own independently reviewed protocol decision and evidence.

### E. Decisions & deliberation · Decisions

| Intended route | Screen / purpose | Access posture | Single primary action | Migration status |
|---|---|---|---|---|
| `/decisions` | **Discover decisions** (hub) — Active proposals, scope, phase, eligibility and result previews. | public | Open decision | retained |
| `/decisions/new` | **Create decision** (task) — Choose scope and proposal type; draft vs executable is explicit. | eligible account | Submit proposal | new-alias |
| `/decisions/:id` | **Decision workspace** (detail) — Tabs: summary, discussion, vote, result, canonical history. | public read | Discuss / vote if open | retained |
| `/decisions/:id/edit` | **Edit draft** (task) — Only edits that protocol rules permit at current stage. | authorized author | Save signed revision | new |
| `/decisions/:id/vote` | **Cast ballot** (task) — Dedicated ballot form with scope/phase/receipt safeguards. | eligible voter | Submit signed ballot | new |

### F. Reports, appeals & public oversight · Oversight

| Intended route | Screen / purpose | Access posture | Single primary action | Migration status |
|---|---|---|---|---|
| `/reports` | **Public reports** (hub) — Browse public reports by status and scope; no privileged voting controls. | public | Open report | retained |
| `/reports/new` | **Create report** (task) — Report target/reason with evidence minimization and signer feedback. | eligible reporter | Submit signed report | new |
| `/reports/:id` | **Report workspace** (detail) — Tabs: summary, timeline, appeal status, public record; protected evidence inaccessible. | public read | View timeline | retained |
| `/reports/:id/appeal` | **File appeal** (task) — Time/standing check, reason, signed appeal, canonical receipt. | authorized appellant | File signed appeal | new |

### G. Assigned responsibilities & review · Work

| Intended route | Screen / purpose | Access posture | Single primary action | Migration status |
|---|---|---|---|---|
| `/tasks` | **My assigned work** (hub) — Simple review queue with type and urgency filters; show locked duties explicitly. | assigned roles | Open assignment | new-alias |
| `/tasks/content` | **Content review queue** (hub) — Only assigned flagged-content work; separate reporter-tracking. | eligible reviewer | Open content case | new |
| `/tasks/disputes` | **Dispute juror queue** (hub) — Assignment, conflict checks, recusal and deliberation stages. | eligible juror | Open dispute case | new |
| `/tasks/poh-async` | **Async PoH queue** (hub) — Assigned encrypted evidence; accept before protected viewing. | eligible reviewer | Review assignment | new |
| `/tasks/poh-live` | **Live PoH queue** (hub) — Assigned live sessions, join availability, current status. | eligible reviewer | Join assigned room | new |
| `/tasks/:lane/:id` | **Review case workspace** (workspace) — Four focus steps: assignment → evidence → decision → signed receipt. | authorized assignee | Continue required step | new-alias |

### H. Proof of Humanity · Verification

| Intended route | Screen / purpose | Access posture | Single primary action | Migration status |
|---|---|---|---|---|
| `/verification` | **Verification overview** (hub) — Current canonical tier, next available action, pending cases, eligibility blockers. | session | Continue verification | retained |
| `/verification/async` | **Record evidence** (task) — Preparation, camera/consent, record, review, encrypt, submit; one stage visible at a time. | T0 eligible | Record evidence | new |
| `/verification/async/:caseId` | **Async case status** (detail) — Assignment, evidence status, reviewer outcome and chain finality separated. | applicant/authorized | Check status | new |
| `/verification/live/request` | **Request live verification** (task) — Availability, consent, signed case request and waiting posture. | T1 eligible | Request live review | new |
| `/verification/live/:caseId` | **Live verification room** (task) — Video first, participant identity, actual connection, attendance, vote controls where authorized. | case subject / assigned juror | Join / complete review | retained |
| `/verification/cases/:caseId` | **Verification case result** (detail) — Authoritative status with explicit submitted, included, final, rejected and terminal states. | authorized case participant | Back to verification | new |
| `/verification/history` | **Verification history** (hub) — Past async/live cases, timestamps, public receipts and protected-evidence boundaries. | account owner | Open a case | new |

### I. My account, reputation & roles · Account

| Intended route | Screen / purpose | Access posture | Single primary action | Migration status |
|---|---|---|---|---|
| `/me` | **My account overview** (hub) — Public identity preview, level, next action; no full role/operator workbench. | session | Edit profile / continue | new-alias |
| `/me/edit` | **Edit profile** (task) — Single-purpose profile fields and signed submission; contains a prominent link to public profile appearance rather than a second media editor. | account owner | Save profile | new |
| `/me/profile-appearance` | **Public profile appearance** (task) — Upload/choose, crop, preview as an external visitor, explicitly publish, replace or remove a **public-facing profile background**, with optional cover placement and safe overlays; preserve signed/publication state. | account owner only | Publish profile appearance | new |
| `/me/posts` | **My public posts** (hub) — Public posting history and content actions. | session | Open post | new |
| `/me/groups` | **My groups** (hub) — Membership/request history with links to public group pages. | session | Open group | new |
| `/me/reputation` | **Reputation and trust** (detail) — Canonical dimensions, provenance and restrictions; no misleading composite score. | session + public facts | Read dimension details | new |
| `/me/eligibility` | **What I can do** (detail) — Action eligibility and missing requirements, derived from authoritative state. | session | Open next eligible action | new |
| `/me/responsibilities` | **Choose responsibilities** (hub) — Separate optional duties: reviewer, node operator, validator, storage and helper. | T2/eligibility shown | Open a duty | new |
| `/me/responsibilities/reviewer` | **Reviewer participation** (task) — Per-lane opt-in, pause, resume; not an assigned-review decision page. | T2/eligible | Manage reviewer opt-in | new |
| `/me/responsibilities/operator` | **Node-operator enrollment** (task) — Distinct node key, registration, enrollment and pending-activation state. | T2/eligible | Enroll when eligible | new |
| `/me/security` | **Account security** (hub) — Recovery safety, device/session status and key separation. | session | Review sessions | new |
| `/me/security/sessions` | **Sessions and devices** (utility) — Active/revoked session-key records, this device, explicit recovery path. | session | Manage session | new-alias |
| `/me/transactions` | **My transaction history** (hub) — Timeline of signed submissions with machine-verified receipts. | session + advanced details | Inspect receipt | new-alias |

### J. Personal node & optional services · Node

| Intended route | Screen / purpose | Access posture | Single primary action | Migration status |
|---|---|---|---|---|
| `/node` | **Personal node overview** (hub) — Connection, readiness, current mode and one next operational step. | public status | View health | retained |
| `/node/connection` | **Node connection** (utility) — API selection, chain identity, trust anchors, compatibility and explicit fail-closed switching. | local operator | Check connection | new |
| `/node/sync` | **Synchronization** (detail) — Tip/height/state root, peer reconciliation, lag and restart evidence. | operator + public status | Check sync | new |
| `/node/responsibilities` | **Service roles** (hub) — Operator, validator, storage and helper responsibilities kept separate. | eligible operator | Open service role | new |
| `/node/validator` | **Validator readiness** (workspace) — Readiness evidence, opt-in, validator key/receipt, no implied authority. | eligible operator | Check eligibility | new |
| `/node/storage` | **Storage service** (workspace) — Capacity declaration/proof, opt-in, IPFS status, allocation readiness. | eligible operator | Run capacity check | new |
| `/node/helper` | **Helper service** (workspace) — Experimental/disabled topology and evidence, not production controls. | eligible operator | View readiness | new |
| `/node/incidents` | **Node incidents** (hub) — Health problems, sync alerts and bounded recovery runbooks. | operator | Inspect incident | new |
| `/node/diagnostics` | **Node diagnostics** (detail) — Logs, manifests, state identity, raw response explorer, safe redaction. | advanced operator | Export redacted evidence | new |

### K. Public protocol explorer · Protocol

| Intended route | Screen / purpose | Access posture | Single primary action | Migration status |
|---|---|---|---|---|
| `/protocol` | **Protocol explorer** (hub) — Public index for chain, governance, trust, economics, storage and records. | public | Explore network state | new |
| `/protocol/chain` | **Chain and finality** (detail) — Current chain identity, block/tip data, validator claims and limitations. | public | Inspect state | new |
| `/protocol/governance` | **Governance rules** (detail) — Public civic procedure, scope, stage, receipts, transparent references. | public | Browse decisions | new |
| `/protocol/reputation` | **Reputation model** (detail) — Public model/dimensions and consequences; avoid exposing private PoH evidence. | public | Inspect trust record | new |
| `/protocol/economics` | **Economics status** (detail) — Locked WeCoin, reward, transfer, fee and treasury posture. | public info; may require session initially | Read activation gates | new-alias |
| `/protocol/storage` | **Storage model** (detail) — Storage/IPFS evidence boundaries; no market readiness claim. | public | Read requirements | new |
| `/protocol/transactions/:txId` | **Transaction receipt** (detail) — Submitted vs included vs applied/rejected; canonical receipt and chain height. | public record subject to API | Copy receipt reference | new |
| `/protocol/tools` | **Technical diagnostics** (advanced) — Low-level API/status/media checks; not central navigation. | advanced enabled | Run read-only check | new-alias |

### L. Preferences, support & accessibility · Settings

| Intended route | Screen / purpose | Access posture | Single primary action | Migration status |
|---|---|---|---|---|
| `/settings` | **Settings overview** (hub) — Appearance, accessibility, notices, node connection, security entry points. | public / session | Open a setting | retained |
| `/settings/appearance` | **Appearance overview** (hub) — Preview application color themes, typography, layout and accessibility; public profile backgrounds are edited only from `/me/profile-appearance`. | local browser | Customize application theme | new |
| `/settings/accessibility` | **Accessibility** (utility) — Font scale, motion and accessible display options. | local browser | Save preferences | new |
| `/settings/connection` | **Selected node** (utility) — Connection/trust changes with explicit impact on session and signed writes. | local browser | Verify selected node | new |
| `/settings/advanced` | **Advanced mode** (utility) — Opt-in to technical UI only; does not grant protocol authority. | local browser | Set advanced mode | new |
| `/help` | **Help center** (hub) — Short procedural help indexed by task rather than stacked on every route. | public | Choose topic | new |
| `/help/verification` | **Verification guide** (detail) — Consent, recording, case states, access and recovery guidance. | public | Open verification | new |
| `/help/node` | **Node guide** (detail) — Observer vs operator vs validator, IPFS requirements and trust artifacts. | public | Open node status | new |

### M. Appearance customization & visual identity · Personal UI and groups

**Architectural decision:** Visual customization has three distinct ownership scopes: (1) the **viewer's local application presentation**; (2) the **public visual identity of a person or group**, if supported by authorized public records; (3) **protocol-authoritative statuses, actions and warnings**, which cannot be restyled into ambiguity. These scopes must never be conflated.

| Intended route | Screen / purpose | Access posture | Single primary action | Migration status |
|---|---|---|---|---|
| `/settings/themes` | **Theme gallery** (hub) — Presets, saved custom themes, current selection, safe previews, and default reset. | local browser | Apply a theme | new |
| `/settings/themes/new` | **Theme studio** (task) — Create a named theme from design tokens with real-time preview and contrast guardrails. | local browser | Save custom theme | new |
| `/settings/themes/:themeId` | **Saved theme detail** (utility) — Preview, edit, duplicate, rename, export, delete and restore previous choice. | local browser | Apply saved theme | new |
| `/settings/themes/import` | **Import theme** (task) — Validate a portable non-executable theme file, preview changes, then request explicit application. | local browser | Import theme | new |
| `/settings/layout` | **Display and layout** (utility) — Typography, font size, reading width, spacing, density, corners and nonessential motion. | local browser | Save layout preferences | new |
| `/groups/:id/manage/appearance` | **Group visual identity** (governed workspace) — Propose or, where canonical permission exists, submit a scoped change to public group avatar, banner and suggested palette. | current authorized group actor; action governed by existing backend rules | Submit authorized appearance change or proposal | new |

**Navigation:** `Settings → Appearance` leads to Themes, Layout, and Accessibility. Public profile background management is available only at `/me/profile-appearance`, not in private app settings. The standard five primary destinations remain fixed. The public group profile still displays its public banner/avatar; group appearance management is reached only from that group's own responsibilities/management area. Theme customization never appears inside a review verdict or signed treasury-action form.

#### M-001 · Customization layers and precedence

| Layer | Scope and owner | Who sees it | Precedence / limits |
|---|---|---|---|
| Application base | WeAll design-system defaults | All clients unless overridden | Fallback that always remains available |
| Personal theme | Viewer, stored in the browser profile | Only viewer on that browser | Overrides the ordinary application palette/layout |
| Public person identity | Profile owner, through explicit authorized public-profile publication | Other accounts and public visitors wherever the profile read is permitted | Public avatar/cover/background and bounded presentation metadata on that one profile canvas only; never another person's browser theme |
| Public group identity | Group via canonical authorization/governance | Public readers where supported | Group banner/avatar and suggested palette; no unilateral admin shortcut |
| Group-theme suggestion | Public group profile metadata if authorized and supported | Visitors who **opt in** to group styling | Never overrides viewer accessibility requirements or security UI |
| Accessibility and safety | Viewer accessibility choice + enforced application safeguards | Applicable view | Highest precedence over all decorative layers |

**Selected policy:** Group styling is **opt-in** for the viewer and **off by default**. The group identity banner/avatar still appears as public content. Group branding does not change the visitor's global navigation theme, other groups, account pages or protocol records. The viewer can always choose *Use my theme*, *Preview this group's theme*, or *Use this group's appearance on group pages* and revert without losing the group context.

#### M-002 · Theme gallery and presets

The theme gallery offers a balanced set of built-in visual choices: WeAll Default Dark, WeAll Default Light, High Contrast Dark, High Contrast Light, Ocean, Forest, Sunset, and Monochrome. The names and palette families are **proposed design specifications**, not claims that PR #81 implements them.

Each theme preview shows the same representative header, card, text, button, form, link, focus ring, and success/warning/error treatment to expose readability problems before applying. Selecting a theme previews it without permanent changes; **Apply** saves the choice, **Cancel** restores the exact prior state, and **Reset to WeAll default** always works.

Support `Dark`, `Light`, and `Follow device` appearance modes. A theme may declare matching light and dark variants; if only one variant exists, the client must show that limitation rather than synthesize a broken palette. High-contrast themes must remain independently selectable regardless of theme choice.

#### M-003 · Theme Studio: user-editable design tokens

The Theme Studio supports the following declarative controls, grouped into separately previewable sections rather than stacked into one continuous form:

| Control group | User-adjustable attributes | Invariants |
|---|---|---|
| Palette | Primary/accent, secondary accent, application background, card/surface, header, text and muted text, borders | Semantic warning/error/success meaning remains distinguishable and labelled; contrast must meet M-009 |
| Surfaces | Card opacity, overlay strength, borders, shadow strength | Security-critical text remains on a fully legible surface |
| Typography | Safe bundled font choices, font scale, line height, reading-width preset | Never loads executable/user-supplied font programs in the initial spec; screen-reader order unchanged |
| Shape and spacing | Corner radius, card style, compact/comfortable/spacious density | Touch targets and focus visibility preserved |
| Motion | Reduced/no decorative animation and normal presentation | OS/browser reduced-motion preference wins; no forced animation |
| Application background colors | Solid color and bounded gradient theme tokens only, without user-uploaded image wallpapers | No individual profile or chat wallpaper; safety surfaces retain independent contrast |
| Navigation shortcuts | Optional favorites in the secondary menu or account home shortcuts | Five primary destinations stay stable; no hiding emergency/safety controls |

Offer curated starter palettes and an **Advanced colors** subsection, not arbitrary CSS. Preview changes in the context of a feed card, group header, proposal vote page and verification case summary. The user may edit, duplicate, rename, save, delete and reset locally saved themes. Theme names are descriptive labels, **not account identities**.

A custom theme must not silently change another person's theme or alter a public group record.

#### M-004 · Public visual backgrounds and image limits

**Two public-facing image contexts only:** (1) the account-owner-published **public personal profile background** in `/me/profile-appearance`, shown to other accounts at `/people/:account`; and (2) governed **public group visual identity** in the appropriate group responsibilities workspace. There is **no private image-wallpaper feature** on profile pages, no app-wide uploaded image wallpaper, and no chat wallpaper. Application themes may still define solid/gradient background *colors* through safe design tokens; they are not uploaded media or public-profile appearance data.

**Allowed public image formats and proposed limits:** JPEG, PNG or WebP still raster images, at most 10 MiB and 4096 × 4096 source pixels; inspect the actual decoded content, strip EXIF/location/identifying metadata and create appropriately sized derivatives before explicit public publication. Reject SVG, HTML, animated/video backgrounds, executable payloads and third-party URL hotlinks. These are proposed acceptance thresholds subject to later technical validation, not PR #81 capabilities.

**Owner-facing edit controls:** Choose a permitted preset or image; position/crop it; choose cover-only or cover-plus-public-profile-canvas placement; preview on desktop/mobile; apply readable dim/blur/tint overlays; explicitly authorize **Publish publicly**, **Replace**, or **Remove public background**. Previewing or selecting a local image is **not** publication.

**Visitor-facing behavior:** Display the currently committed public background by default inside that profile canvas. A visitor can suppress *all decorative profile images* through accessibility or data-use preferences or choose **View without background** for readability; the visitor cannot substitute a private wallpaper or impose a different public background on the profile. Mandatory profile identity, account state, posts, reports and safety notices remain readable without decorative media.

**Privacy and canonical status:** Publishing public media must be an explicit account-owner-authorized or group-governed action under a verified existing backend contract. Do not infer such a contract exists merely from this specification. Status must distinguish local selection, upload, signed submission, inclusion, applied or rejected canonical result, and subsequent visibility. A public image may be replicated or archived; removal stops its current display after confirmation but cannot guarantee deletion of historic copies. Any missing/unavailable media falls back to a neutral public header without hiding profile content.

#### M-005 · Public personal profile appearance versus private application theme

**Single profile-appearance scope:** `/me/profile-appearance` is solely the account owner's editor for public-facing profile background and bounded related presentation metadata. `/people/:account` is the public read view of the committed result. **No private profile background, owner-only profile wallpaper, per-visitor profile theme, or alternate private appearance layer is specified.** The owner sees the same committed public profile appearance as other viewers, subject only to general accessibility preferences.

**App theme remains separate:** A viewer can locally choose their WeAll application color palette, font size, spacing and contrast at `Settings → Appearance`. This ordinary app presentation does not replace the profile owner's public image, publish media or affect any other user's stored appearance. No private wallpaper upload route is included in Settings.

**Owner journey:** Account → My profile → Customize public appearance → permitted public preset or local source → crop and placement → preview as an outside viewer → explicit **Publish publicly** confirmation → signed/accepted/included/applied-or-rejected result. **Replace**, **Remove public background** and **Restore simple public profile** operate on public appearance records, never private wallpapers.

**Visitor journey:** Open a public profile → see the owner's committed identity, banner/background, bio and public post feed → optionally suppress decorative media for contrast, safety or data savings. The suppression is a general accessibility/display choice, **not** a private profile-theme feature. It does not change what anyone else sees or modify authoritative records.

**Rendering priority:** Mandatory safety/authorization/state labels and viewer accessibility settings → committed owner-published public profile background in the bounded profile canvas where rendering is permitted → viewer's general application theme for standard UI chrome. Group color suggestions remain separately opt-in and scoped to group pages.

**Contract boundary:** If a canonical public-profile media update mechanism does not exist yet, publishing remains explicitly unsupported until separately reviewed and authorized. Nothing in this UX spec grants signing authority, visibility rights or a new media transaction type. See M-012 and M-013.

#### M-006 · Group visual identity and governance

A public group can display a banner, emblem/avatar, accent suggestion, short visual description and its existing canonical scope. The group post feed remains primary; treasury, decisions, emissaries and responsibility desks remain separate group-local destinations.

A proposed group palette is *metadata for presentation*, **not authority**. Only an action already authorized by the existing group protocol can commit a public group identity change. If an authorized update action does not exist, show an explicit **unsupported/pending product capability** and route any proposed change through the applicable group decision flow; do not fabricate a direct administrator edit or pretend that a vote automatically executes a nonexistent transaction.

**Public reader:** sees the current committed group banner/avatar, readable charter and post stream, may opt into the suggested palette locally, may revert anytime.

**Group participant:** sees approved public branding/proposals and the same theme choice as other viewers; cannot overwrite collective identity by changing personal settings.

**Authorized group actor:** enters `/groups/:id/manage/appearance` via the exact group's responsibilities, sees provenance, mandate/scope, existing approved record, pending request/decision and a clear signed-action/result state *only where supported*. Change history remains public when the protocol makes it public. No group styling affects other groups, protocol-wide governance or the viewer's account.

**Group visual media:** the public assets are treated as shared content subject to whatever storage/provenance rules the canonical group object supports; no claim is made that the current PR #81 API already stores group banners or theme metadata.

#### M-007 · Portability: saved, imported and shared themes

Support local **Export theme** and **Import theme** as plain, versioned, non-executable structured data containing the theme's name, palette, surfaces, typography choice, spacing, shapes and optional reference to an existing bundled background. Theme exports contain **no account ID, node address, keys, local file paths, cookies, session tokens, private images or telemetry**.

Import requires schema validation, constrained values, an explicit visual preview and an *Apply* confirmation. Reject arbitrary CSS, JavaScript, HTML, remote URLs, external `@import`, browser storage instructions and hidden network endpoints. Do not run or dynamically interpret any imported code. An unsupported schema version fails visibly and leaves the existing theme intact.

Theme sharing at the initial design baseline means **user-controlled import/export of the safe data file**. An on-chain theme marketplace, remote theme-store service, distributed publication registry or automatic cross-device sync is **not part of this specification**; each would require its own privacy, moderation, storage and provenance decision.

#### M-008 · Persistence, portability, and failure-safe reset

Personal appearance settings persist per-browser-profile by default, independently of account signing material and backend network selection. A device with multiple signed-in WeAll accounts must not accidentally leak one account's private settings into public content; the initial specification chooses **device/browser-scoped visual settings**, with explicitly selectable local profile presets if desired, rather than claiming on-chain or cross-device ownership.

If the browser clears local state or another device is used, show the default theme unless the user imports their saved theme file. Reconnecting to another node must not silently replace appearance preferences. A broken or missing saved theme resets only the visual presentation, not session keys, ledger state, recovery files or group membership.

Always provide a discoverable **Restore default appearance** control, including a keyboard-accessible fallback that works even if the theme makes normal settings difficult to read.

#### M-009 · Accessibility, safety, and minimum visual standards

- Normal text on surfaces must meet WCAG 2.2 AA contrast **at least 4.5:1**; large text and essential non-text UI indicators at least **3:1** where those requirements apply.
- Controls and visible focus indicators remain distinguishable regardless of accent choice; never convey an error, proposal status, jurisdiction/scope or PoH outcome by color alone.
- Theme application must preserve keyboard traversal, screen reader names, logical focus order, safe minimum hit targets, text expansion, 200% zoom and readable content at 400% zoom/reflow.
- Respect OS/browser reduced-motion preference even if a theme requests movement. Animated backgrounds and uploaded private wallpapers are outside the design baseline.
- Status banners, protected-evidence notices, camera/microphone consent, key-recovery warnings, recipient identities, proposal approval/scope and transaction rejection/finality retain mandatory application-defined emphasis and cannot be obscured by public profile imagery or custom application colors.
- If a user-entered color fails the accessibility thresholds, provide a clear fix/adjustment in the preview and block applying it as an inaccessible default. High-contrast override remains one action away.
- Public group branding is no exception: viewer accessibility preferences and mandatory protocol-state semantics always override suggested group colors.

#### M-010 · Responsive experience and empty/error states

**Desktop:** a theme sample gallery alongside a preview panel; adjustments grouped into Palette, Surfaces, Typography and Layout. The public-profile editor separately manages public media crop and placement. Do not make the live application reflect *unconfirmed* changes in other tabs or accounts.

**Mobile:** one current theme-setting category at a time with a sticky preview/apply/reset area. Image crop is available only in the dedicated public-profile/group publication editor; no uncontrolled parallax, video or side-scroll. Preview and action controls remain reachable by touch, keyboard and assistive technology.

**Explicit states:** no saved themes → preset gallery; damaged/unsupported theme file → keep existing app theme; app color preference unavailable → quiet default palette; public image missing/invalid/too large → reject publication or show neutral public header; local theme storage full → retain current app appearance; device theme changes → update only when Follow device is active; attempted group appearance change without authority → visible unauthorized state; group asset missing → neutral public banner and preserved group identity.

#### M-011 · Theme contract and non-implementation boundary

A theme is a **presentation token document**, never a rule engine, permission policy or executable plugin. Its semantic fields are bounded to visual choices. The protocol remains unaware of ordinary private theme selection. An **explicit public-profile background publication** may reference media as part of authorized public profile state if a verified canonical mechanism supports it; it must not turn private theme selection into a transaction. No new consensus transaction types or economic authority are authorized by this UI specification.

Source baseline: PR #81 currently offers only `dark`/`light`, four accent tones (`mint`, `cyan`, `gold`, `rose`), three font scales (`sm`, `md`, `lg`), two densities (`compact`, `comfortable`) and a reduced-motion toggle via browser client settings (`web/src/lib/settings.ts`). Public profile image-background publication, custom theme import/export, group-suggested themes and the routes above are **proposals, not implemented functionality**. Private profile and chat wallpapers are intentionally excluded. The existing canonical profile/media update capabilities require separate verification before implementation.

#### M-012 · Public profile background visual contract

The owner's published background is a **bounded, public-facing visual layer**, not an application-level theme and not a privileged data surface.

| Public profile region | Expected placement and behavior | Must never happen |
|---|---|---|
| Profile header / cover | Full-width crop of published background with avatar, display name, handle and essential identity information on opaque/contrast-controlled foreground | Portrait or banner covers canonical identity, account status or report controls |
| Profile body / post stream | Owner may choose **Cover only** or **Cover + profile canvas**; profile-canvas wallpaper is behind the public bio, group previews and posts on legible cards | Unbounded wallpaper over global header, account settings, other profiles or signing dialogs |
| Profile content | Tabs/links for **Posts**, **About**, **Groups** and publicly verifiable roles; profile background stays stable across local tabs | Decorative image turns posts into rasterized content, prevents text selection or overrides protocol facts |
| Owner context | Owner sees **Customize public appearance** from Account or their own public profile; owner-only edit controls are visibly separate from visitor view | Other accounts see edit/upload controls or local source filenames |
| Visitor context | Visitor sees the published background by default, with a **View without background** choice and persistent **Hide decorative profile backgrounds** preference | Visitor's own theme, contrast, text size or data-saver choice is overwritten |
| Compact/mobile | One responsive crop per viewport; safe focal point, cards, readable overlays, no parallax | Crop obscures identity, creates horizontal overflow, prevents tap/keyboard navigation |

**Owner-level controls:** choose no background, bundled preset, or approved public raster image; set fit and focal point (cover/contain; horizontal/vertical positioning); choose cover-only versus extend behind the profile feed; choose dim/blur and neutral overlay for readability; preview at desktop and mobile widths; inspect the **public** visibility warning before publication. These options are **proposed bounded presentation metadata**, not arbitrary CSS or executable design files.

**Other-account acceptance:** The same committed profile background is visible from a second authenticated account and, where public profile reads exist, in a signed-out browser; it is not merely a local appearance preview from the owner's browser. A page refresh or different device must reconstruct the public layout from the authoritative profile reference and publicly retrievable media, not from the owner's local storage.

**Rendering precedence:** (1) enforce mandatory safety labels, contrast and visitor accessibility preferences; (2) show the account's published identity/background within the profile canvas if allowed by viewer settings; (3) render the visitor's selected theme for common application chrome and ordinary UI surfaces. A profile may suggest compatible accent colors **inside its own canvas**, but this is purely decorative and must not replace semantic status colors or force a different application theme.

**Accessibility/data usage:** public profile backgrounds are nonessential content. Hide-decorations, high-contrast and reduced-data modes can omit the image request entirely and show a safe color fallback. The selected source file name, unpublished crop/edit drafts and personal application-theme settings never appear in visitor data; only explicitly committed public profile media/presentation metadata are exposed.

#### M-013 · Public profile media publication, moderation and lifecycle

**Public profile appearance object** (conceptual data contract; must be matched to an existing authorized backend contract, not implemented speculatively): canonical account identifier; declared display placement; approved public image reference or preset ID; sanitized derived dimensions and display crop/focal point; optional bounded overlay; verified publication status/provenance; update timestamp or canonical receipt. No embedded scripts, arbitrary remote URL, third-party font, local path, device tokens, GPS/EXIF, viewer secrets or privileged account roles in presentation fields.

**Explicit publication flow:** local asset selected → file size/type/decode check → privacy and content warning → metadata stripping and safe raster re-encoding → owner preview as a visitor (no publication yet) → explicit public publish confirmation → authorized signer and submission → pending/included/applied/failed status → only canonical committed media becomes visible to other viewers. Temporary preparation and upload state is never labelled a public update. If the protocol does not yet support public profile media persistence, the editor clearly remains a **proposed capability / unsupported action**.

**Media safety baseline:** constrain images to JPEG/PNG/WebP, max 10 MiB source and max 4096×4096 source pixels (initial specification thresholds subject to engineering review); strip EXIF and identifying metadata before any intentional public upload; decode/re-encode in a trusted process; generate safe sizes for desktop and mobile; no SVG, animation, remote URL hotlinks or embedded code. Avoid unbounded network, storage or rendering demands. Selecting an image in the public-profile editor is never sufficient to publish it; always require separate explicit public-visibility confirmation and protocol authorization.

**Profile content safety:** background remains distinguishable from official verification badges, provenance, account status and content/report actions. Publicly abusive/inappropriate backgrounds need the same public reporting/moderation entry points as other public user-generated media when the protocol supports that mechanism; do not imply a moderator or client can instantly erase historical distributed copies. A reporting or safety preference may replace the rendered media with a neutral placeholder while retaining auditable public references where appropriate.

**Replacement and removal:** An owner can request to replace a background or return to no public background through an appropriately authorized update. Other viewers see the **last canonically confirmed** state until the new one is confirmed. A successful removal stops current-profile display and future references in the client, but **cannot promise deletion from the blockchain, caches, replicas or other already-public stores**. Show that warning before the first public upload. Failed/rejected updates preserve the old confirmed state and expose the receipt or reason.

**Failure/empty states:** no published background → neutral profile header; media missing or unavailable → neutral header plus unchanged identity and posts; malformed/unsafe upload → reject before any publish; network storage upload fails → unsent draft persists locally where safe; signed but unconfirmed update → previous committed image still visible publicly; conflicting/superseded update → canonical state wins and local draft is marked stale; removed/hidden/flagged media → safe neutral fallback, clear owner/visitor explanation as permitted; visitor turns off decorative images → no background request and no effect on the owner's public record.

**Cross-account privacy acceptance:** Changing the viewer's local theme never changes another account's published background. Changing the owner's public profile background does not publish their local app theme, expose unpublished drafts or keys, or give the editor any privilege outside the owner's permitted public-profile updates. A third party cannot publish for the owner by visiting the route. Public assets must not embed sensitive or private PoH evidence.

## 4. Within-page maps (not giant vertical pages)

The following subviews are **locally navigable and URL-addressable** for durable links and browser-back history. Where a child URL exists—especially group sections—that path is canonical; tabs are merely the visual presentation of those paths. Other detail objects may use a hash-local query tab where no dedicated child route is specified. Selecting a tab or route never grants permission or submits a signed transaction.

- `/groups/:id` → **Community profile + post preview (default)** → **Posts** (`/posts`) → **About / charter** (`/about`) → **Members** (`/members`) → **Decisions** (`/decisions`) → **Treasury** (`/treasury`) → **Emissaries** (`/emissaries`) → **Reports** (`/reports`) → **Public records** (`/records`). Conditional **My responsibilities** links to `/responsibilities`, never into a stacked panel on the public feed.
- `/groups/:id/treasury` → **Public overview** → **Proposals/approvals** → **Canonical ledger/receipts** → **Rules/constraints**.
- `/groups/:id/emissaries` → **Current seats** → **Elections** → **Public mandate records**; the signed-in emissary desk is a distinct authorized route.
- `/groups/:id/responsibilities` → **Assigned duties** → **Membership review** (`/manage/members`) → **Scoped moderation** (`/manage/moderation`) → **Emissary mandates** (`/emissaries/work`) → **Approved treasury mandates** (`/responsibilities/treasury`) → **Signed action results**. Only show tasks that canonically exist and for which this person has authority.
- `/decisions/:id` → **Summary** → **Discussion** → **Ballot** → **Results** → **Canonical history**
- `/reports/:id` → **Summary** → **Public timeline** → **Appeal status** → **Public records**
- `/tasks/:lane/:id` → **Assignment** → **Protected evidence (when authorized)** → **Decision** → **Signed receipt**
- `/verification/async` → **Prepare** → **Consent & camera** → **Record** → **Review & encrypt** → **Submit**
- `/verification/live/:caseId` → **Preflight & consent** → **Live media** → **Attendance or reviewer action** → **Canonical result**
- `/me` → **Overview** → **Public profile preview** → **Customize public appearance** (`/me/profile-appearance`) → **Eligibility snapshot** → **Recent activity**.
- `/people/:account` → **Published background + identity** → **Posts** (default) → **About** → **Groups** → **Public roles**. Other-account visitors see the committed image in the profile canvas, unless local decorative-media preferences suppress it.
- `/protocol` → **Chain** → **Procedures** → **Reputation** → **Economics** → **Storage**
- `/settings/appearance` → **Themes** (`/settings/themes`) → **Theme studio** (`/settings/themes/new` or `/settings/themes/:themeId`) → **Layout** (`/settings/layout`) → **Accessibility** (`/settings/accessibility`). The application theme has no user-image wallpaper upload and does not edit a public profile.
- `/groups/:id` → **Committed public group identity** → **Optional group suggested appearance** (viewer opt-in) → **Group role holder's governed appearance-change workspace** (`/groups/:id/manage/appearance`).
- `/me/profile-appearance` → **Background source** → **Crop / placement** → **Preview as outside viewer** → **Public visibility confirmation** → **Publish / canonical status**. It remains separate from private application-theme settings; the only personal-profile background destination is its **public publication editor**.

**Group default behavior:** The first fold of `/groups/:id` is the group profile and public posts, not membership management, treasury, emissary controls and diagnostics stacked vertically. Only actual canonical roles unlock private duty routes.

**Default tab logic:** on a decision, show Summary until voting is genuinely available, then present an explicit Vote CTA; do not automatically switch into a signing form. On a verification case, terminal status stops media acquisition/retries and shows Result. On public groups/reports, public read visibility is unchanged.

## 5. Existing route-by-route migration / link preservation

| PR #81 source URL | Intended canonical URL | Compatibility behavior |
|---|---|---|
| `/login` | `/start` | Entry split; keep /login as sign-in/restore compatibility entry. |
| `/home` | `/home` | Compact next action; tester content moved into Help. |
| `/activity` | `/activity` | Keep activity list; preferences to dedicated settings. |
| `/feed` | `/feed` | Retain; public browser gating needs separate authorization review. |
| `/create` | `/feed/new` | Compatibility alias; composer stays independent. |
| `/post/:id` | `/post/:id` | Retain existing post deep links. |
| `/content/:id` | `/post/:id` | Alias only after checking identity and links. |
| `/thread/:id` | `/thread/:id` | Retain thread and signed response path. |
| `/groups` | `/groups` | Retain directory. |
| `/groups/create` | `/groups/new` | Alias to canonical creation route. |
| `/groups/:id` | `/groups/:id` | Retain group ID and public post-centered landing page; internal sections use explicit `/groups/:id/<section>` child links, with backward-compatible hash tabs if present. |
| `/decisions` | `/decisions` | Retain public decision index. |
| `/decisions/create` | `/decisions/new` | Alias to focused composer. |
| `/decisions/:id` | `/decisions/:id` | Retain case ID and tabs. |
| `/reports` | `/reports` | Retain public reports. |
| `/reports/:id` | `/reports/:id` | Retain public report/appeal status. |
| `/reviews` | `/tasks` | Old review hub redirects to role-aware queue. |
| `/reviews/:id` | `/tasks/:lane/:id` | Resolve legacy review type, never guess mismatched lane. |
| `/verification` | `/verification` | Overview only; case-aware next step. |
| `/verification/live/:caseId` | `/verification/live/:caseId` | Keep room links and role checks intact. |
| `/profile` | `/me` | Compatibility alias to personal overview. |
| `/account/:account` | `/people/:account` | Public read-only profile; alias preserve account links. |
| `/session` | `/me/security/sessions` | Alias to existing device/session workflow. |
| `/settings` | `/settings` | Keep entry; split settings into categories. |
| `/node` | `/node` | Keep summary and link to service workspaces. |
| `/economics` | `/protocol/economics` | Alias; keep activation locked. |
| `/advanced` | `/protocol/tools` | Alias; advanced mode controls only UI complexity. |
| `/transactions` | `/me/transactions` | Alias to signed submission / receipt history. |

**Routing compatibility requirement:** in the existing hash router, paths are fragments such as `#/groups/abc`. A legacy query-tab URL stays within the hash, e.g., `#/groups/abc?tab=posts`, and resolves to the canonical `/groups/abc/posts` view without losing its group ID; case IDs/transaction IDs must be encoded and preserved. Old links need explicit alias routing rather than silent fallback to sign-in. Legacy `/reviews/:id` cannot be mapped to a new lane without resolving its canonical type.

## 6. End-to-end journey map — all primary actions

### J01 · First-time account setup · Entry / account
Get from no local signer to a recoverable account without implying that registration is final before chain confirmation.

**Screen path:** `/start` → `/auth/create` → `/auth/backup` → `/auth/status` → `/home` → `/verification`.

**Evidence / guard:** Recovery file locally saved; account registration and key custody checked independently. Failure and unsynced node states remain explicit.

### J02 · Restore to a new device · Identity / safety
Recover local control without accidental duplicate registration or stale node session.

**Screen path:** `/auth/restore` → `/auth/status` → `/me/security/sessions` → `/me`.

**Evidence / guard:** Signer and server session state distinguished. No secrets in UI diagnostic exports.

### J03 · Verified Person (async) · Verification
Complete Tier 1 evidence request as a focused task.

**Screen path:** `/verification` → `/verification/async` → `/verification/async/:caseId` → `/verification/cases/:caseId` → `/verification`.

**Evidence / guard:** Consent, local capture, encryption/upload, signed receipt, review and final state shown separately; protected video never public.

### J04 · Trusted Verified Person (live) · Verification
Request and attend live human review with bounded reviewer authority.

**Screen path:** `/verification` → `/verification/live/request` → `/verification/live/:caseId` → `/verification/cases/:caseId` → `/verification`.

**Evidence / guard:** Actual remote media state separate from local preview; session attendance, signed review verdict, canonical terminal status never conflated.

### J05 · Review encrypted async evidence · Reviewer
Allow only authorized, accepting reviewers to inspect evidence and sign outcome.

**Screen path:** `/tasks` → `/tasks/poh-async` → `/tasks/:lane/:id` → `/verification/cases/:caseId`.

**Evidence / guard:** Assignee and conflicts checked before decrypt; response is signed; finality checked on chain.

### J06 · Assigned live review · Reviewer
Join as assigned reviewer and record verifiable participation.

**Screen path:** `/tasks` → `/tasks/poh-live` → `/verification/live/:caseId` → `/verification/cases/:caseId`.

**Evidence / guard:** Participant identity, remote frames, media teardown and status of accepted/declined role are visible; no post-terminal join.

### J07 · Publish and discuss · Social
Write one public post and continue in a thread.

**Screen path:** `/feed` → `/feed/new` → `/post/:id` → `/thread/:id`.

**Evidence / guard:** Signed post acceptance and chain inclusion distinguished from local toast.

### J08 · Report a post · Public oversight
Submit a report and see public case progress without becoming the reviewer.

**Screen path:** `/post/:id` → `/post/:id/report` → `/reports` → `/reports/:id`.

**Evidence / guard:** Reporter progress is separate from juror assignment and protected evidence.

### J09 · Discover, join and participate · Groups
Locate a community, request membership and post only when eligible.

**Screen path:** `/groups` → `/groups/:id` → `/groups/:id/join` → `/groups/:id` → `/groups/:id/posts/new`.

**Evidence / guard:** Public group reading remains open; membership gates actions, not content visibility.

### J10 · Create and administer group · Groups
Scope group actions to its own electorate and governance.

**Screen path:** `/groups` → `/groups/new` → `/groups/:id` → `/groups/:id/manage` → `/decisions/new`.

**Evidence / guard:** Approval-required memberships and decisions remain protocol-authorized.

### J10a · Group-scoped governance · Groups
Open a group's Decisions section, create a scope-bound proposal, and read the same canonical proposal from global Decisions without changing electorate context.

**Screen path:** `/groups/:id` → `/groups/:id/decisions` → `/groups/:id/decisions/new` → `/decisions/:id` → `/groups/:id/records`.

**Evidence / guard:** Group ID, electorate, proposal scope and stage remain backend-authoritative. A global listing is not authority to vote outside the group.

### J10b · Group treasury oversight · Groups
Read the group's funding record and propose a use through ordinary scoped governance rather than a direct spend mechanism.

**Screen path:** `/groups/:id` → `/groups/:id/treasury` → `/groups/:id/treasury/propose` → `/decisions/:id` → `/groups/:id/records`.

**Evidence / guard:** Proposed, approved, executed and recorded are not interchangeable. Never invent balances or payments when canonical data is absent.

### J10c · Emissary election and bounded mandate · Groups
Inspect the group's emissary roles and elections, then enter the mandate desk only with confirmed current authority for that group.

**Screen path:** `/groups/:id` → `/groups/:id/emissaries` → `/groups/:id/emissaries/elections` → `/groups/:id/emissaries/elections/:electionId` → `/groups/:id/responsibilities` → `/groups/:id/emissaries/work` → `/groups/:id/records`.

**Evidence / guard:** An election without a valid winner does not create an emissary. An emissary never gains independent treasury or protocol-wide authority through a UI route.

### J10d · Membership approval and scoped moderation · Groups
An authorized group role holder opens a task from the group's own responsibility desk, checks group/case identity, and signs only a permitted decision.

**Screen path:** `/groups/:id` → `/groups/:id/responsibilities` → `/groups/:id/manage/members` or `/groups/:id/manage/moderation` → `/groups/:id/records`.

**Evidence / guard:** Requester privacy, actual assigned group role, signed transaction, dispute/appeal boundaries and authoritative receipt remain distinct. This flow does not authorize broader protocol moderation.

### J10e · Approved treasury mandate transparency · Groups
Inspect a group funding decision, determine whether any approved execution mandate actually exists, and trace its public outcome.

**Screen path:** `/groups/:id/treasury` → `/groups/:id/decisions` → `/decisions/:id` → `/groups/:id/responsibilities/treasury` (only for a current authorized actor and only if supported) → `/groups/:id/records`.

**Evidence / guard:** Proposal, approval, mandate, execution and receipt are separate. Unsupported or locked operation remains non-actionable.

### J11 · Deliberate and vote · Decisions
Read a scoped proposal, discuss it, cast one eligible ballot and inspect result.

**Screen path:** `/decisions` → `/decisions/:id` → `/decisions/:id/vote` → `/decisions/:id`.

**Evidence / guard:** Scope, eligibility and phase derive from canonical state, not UI countdown.

### J12 · Dispute and appeal · Public oversight
Separate public case tracking from conflicted reviewer actions.

**Screen path:** `/reports` → `/reports/:id` → `/reports/:id/appeal` → `/reports/:id`.

**Evidence / guard:** Appeal eligibility/window enforced by backend; public timeline does not reveal restricted identity evidence.

### J13 · Inspect trust and capabilities · Account
Understand what user can currently do and why without treating reputation as single arbitrary score.

**Screen path:** `/me` → `/me/reputation` → `/me/eligibility` → `/me/responsibilities`.

**Evidence / guard:** Only canonical dimensions and statuses; read-only overview cannot grant roles.

### J14 · Enroll as node operator · Operator
Create separate operational key, enroll and await deterministic eligibility.

**Screen path:** `/me/responsibilities` → `/me/responsibilities/operator` → `/node` → `/node/responsibilities`.

**Evidence / guard:** Separate node key from account backup; enrollment ≠ activation ≠ validator status.

### J15 · Inspect observer sync · Operator
Explain what two local processes have and have not proven.

**Screen path:** `/node` → `/node/connection` → `/node/sync` → `/node/diagnostics`.

**Evidence / guard:** Matching height, tip, state root and receipt sync shown; one-host test not cross-machine proof.

### J16 · Opt into storage service · Operator
Inspect IPFS and capacity evidence without implying validated public provider service.

**Screen path:** `/node` → `/node/responsibilities` → `/node/storage` → `/protocol/storage`.

**Evidence / guard:** Declared capacity ≠ challenged/proven capacity; no live storage market claim.

### J17 · Understand locked economics · Protocol
Inspect protocol economic posture without opening live transfer actions.

**Screen path:** `/protocol` → `/protocol/economics`.

**Evidence / guard:** Fees, transfers, rewards and treasury remain explicitly locked in current environment.

### J18 · Verify signed action and result · Transparency
Move from submitted to confirmed or rejected canonical record.

**Screen path:** `/me/transactions` → `/protocol/transactions/:txId` → `/protocol/chain`.

**Evidence / guard:** Signed / queued / included / applied / rejected / final are distinguishable.

### J19 · Personal application-theme customization · Appearance
Choose application colors, typography, spacing and contrast without editing or overriding any public profile background.

**Screen path:** `/settings` → `/settings/appearance` → `/settings/themes` → `/settings/themes/new` → `/settings/layout` → `/settings/appearance`.

**Evidence / guard:** Real preview before apply; accessible contrast and reset; no local image wallpaper editor and no theme-save action that publishes profile media.

### J20 · Import, preview and restore a theme · Appearance
Transfer theme choices without inadvertently transferring identity, device or security information.

**Screen path:** `/settings/themes` → `/settings/themes/import` → validated preview → `/settings/themes/:themeId` → apply or cancel.

**Evidence / guard:** Declarative token schema only; no scripts, remote resources or private media; incompatible import leaves current theme intact.

### J21 · Visit a branded group and change public group appearance · Groups
Keep collective public identity distinct from each visitor's private preferences.

**Screen path:** `/groups/:id` → optional group-theme preview → viewer local opt-in; authorized group actor: `/groups/:id/responsibilities` → `/groups/:id/manage/appearance` → canonical existing proposal/authorized update path → `/groups/:id`.

**Evidence / guard:** Visitor controls whether suggested palette applies; group assets are only treated as public when legitimately published; group authority and proposal status derive from committed state, never visual ownership.

### J22 · Publish and preview public personal profile background · Account
Make an explicitly public personal-profile design visible to other accounts without mistaking a local preview or draft for confirmed publication.

**Screen path:** `/me` → `/me/profile-appearance` → local source/preset and crop → second-account/signed-out visual preview → explicit public confirmation → canonical pending/confirmed/rejected result → `/people/:account`.

**Evidence / guard:** Public media sanitized before upload, signed authority verified, URL/media reference derived from actual canonical profile state; different account or signed-out reader sees the committed result. Unsupported backend profile-image publication stays unavailable, not simulated as success.

### J23 · Visit and customize readability of another user's public profile · Social
View another account's chosen visual background around their identity, bio and public posts without surrendering your own application theme.

**Screen path:** `/feed` or `/groups/:id/posts` → `/people/:account` → view public profile background / posts → optional **View without background** → continue reading or open group.

**Evidence / guard:** Same account-owned public image reference across devices; viewer accessibility/high contrast/reduced-data suppression overrides decorations; account identity and canonical status never obscured; visitor gains no edit controls.

## 7. Role and access policy expressed in UX

| User posture | Default visible destinations | Actions that remain conditional |
|---|---|---|
| Visitor / not signed in | Public groups, decisions, reports, public content/profile, public protocol reference where the API actually permits read | Creating accounts, posting, voting, review work and evidence viewing require sessions; the current `/feed` frontend is gated and opening it requires implementation/API review. |
| T0 account | Home, Feed, Groups, Decisions, Account, Verification; public read surfaces | Async PoH request subject to canonical eligibility; posts/group/decision actions gated by current protocol rules. |
| T1 / Verified Person | Same stable navigation | Live PoH request; any tier-dependent write shows exact state/standing requirements. |
| T2 / Trusted Verified Person | Same navigation; review duties surfaced by eligibility | Reviewer opt-ins and operator enrollment still require role rules, account status and separate keys; T2 alone does not grant assignment or signing. |
| Group visitor / nonmember | Group profile, posts, charter, public members where available, group decisions/treasury/emissaries/reports/records | Membership-gated posting/voting, protected workspaces and internal requests stay locked. |
| Group member | Same public group destinations plus contextual participation entry | Signed posting, proposal creation and ballots depend on exact group-scope policy, role and standing, not membership alone. |
| Authorized group moderator / membership approver | `Group → My responsibilities → Membership or Moderation desk` | Only named group case types and signed actions permitted by canonical role; no unilateral protocol-wide powers. |
| Elected emissary / mandate holder | `Group → Emissaries → My responsibilities` and current scoped mandate | Election is not treasury authority; actions require a currently valid specific mandate, approvals and receipt. |
| Assigned juror / reviewer | `My work` queue plus one assigned case action page | Protected identity evidence only after appropriate authorization; conflicts/recusal checked by backend. |
| Group member, moderator, or elected emissary | Public group profile, group-scoped posts, decisions, treasury read, election records; authorized duty desks appear under **that group** | Participation, moderation, voting, proposed funding and emissary mandates require exact group-scope backend authorization; no unilateral financial or protocol control. |
| Node operator / validator / storage roles | Node overview, role-specific workspaces, diagnostics and public protocol explorer | Validator authority and production service remain fail-closed until canonical assignment and readiness evidence; local devnet role is not public-network qualification. |
| Every viewer (appearance) | Application theme palette, typography, contrast, layout and safe theme import/export in Settings; accessibility preference to suppress decorative public-profile backgrounds | No per-profile private wallpaper or chat theme; app preferences never change canonical identity, public profile media, voting, roles, evidence access, signing or group authority. |
| Public profile owner | `/me` → `/me/profile-appearance` with previews and publication status; own public profile preview | Can publish/replace/remove public background only through an existing authorized public-profile update path; no unsupported backend action is invented. |
| Other-account profile visitor | `/people/:account` with owner-published background, public posts and identity | Can choose to hide decorations locally; cannot edit owner's public media or alter own/global theme via someone else's profile. |
| Group branding contributor | Public group identity + group-scoped appearance proposal/management entry where legitimate role exists | A custom group palette is not a treasury, emissary or protocol mandate; real public changes require existing canonical authority. |

## 8. Universal state semantics / visible truth

| Status | Plain language | Must / must not claim |
|---|---|---|
| `not_started` | **Not started** | Nothing submitted; safe to enter flow. |
| `local_preparation` | **Local preparation** | User is recording, editing, or generating keys. No on-chain claim. |
| `uploading` | **Encrypted media uploading** | Storage intake may be in progress; no on-chain submission implied. |
| `signed` | **Signed** | Local signer produced an authentic signed request, no network guarantee. |
| `submitted` | **Submitted** | API/queue accepted request, not necessarily committed. |
| `pending` | **Pending inclusion / review** | Waiting for canonical block or reviewer action; retry not automatic. |
| `confirmed` | **Included or applied** | Receipt available; check successful versus rejected apply. |
| `rejected` | **Rejected** | Canonical rejected receipt or validation failure clearly shown. |
| `final` | **Final / terminal** | Authoritative case/proposal state is terminal; disable incompatible actions and media restart. |
| `stale` | **Unverified / stale** | Node/session/case view unavailable or inconsistent; fail closed. |
| `recovery` | **Recovery needed** | Preserve evidence and keys, show safe next step, avoid destructive reset. |

A UI transaction status component should surface one typed state consistently across account, PoH, post, governance, disputes and node actions. **Do not** use a generic “Success!” when only a submission or upload succeeded. Rejected canonical apply receipts must remain distinct from network errors and local validation. Timeout cannot silently re-sign/re-submit a nonce.

## 9. Shared layout templates, density, design constraints

| Template | Required regions | Content budget |
|---|---|---|
| **Hub** | Title + short purpose → one next step → compact list/filter → links to detail/action | One primary CTA; target ≤2 explanatory blocks above first real content; no inline complex forms. |
| **Detail** | Object title + phase/status → tab bar → one related content panel → contextual permitted action | One subview per tab; query/hash deep link; no stacked full history and forms. |
| **Task** | Back breadcrumb → progress/why → one focused input/confirmation → signed status/receipt | One task step per viewport; safe step-back; warnings cannot be hidden. |
| **Case / review** | Assigned role + conflict gate → protected evidence → verdict → canonical receipt | Only assignee can view evidence/sign; no public case detail leakage. |
| **Node workspace** | Node identity + health → one operator responsibility → proof/status drilldown | Separate devnet mode, key custody, capacity and validator-readiness tooling. |
| **Global shell** | Compact brand/menu + activity + account/status → page title/breadcrumb → main; optional context drawer | No permanent route-mode explainer, duplicate title/header status or repeated network payload on every page. |

**Desktop (≥1024 px):** readable content max ~1120 px, text column ~65–80 characters, optional secondary panel that never duplicates route main content. **Tablet:** contextual panel becomes drawer. **Mobile (~360–430 px):** five stable bottom destinations; title + phase + next action before explanatory panels, no horizontal overflow, scoped object tabs horizontally scrollable with clear focus indicators. **All sizes:** support keyboard, screen readers, sufficient control targets, high contrast and reduced motion; active call/video must not rely on a narrow side card.

**Customization contract:** Global shell, cards and task templates take validated personal presentation tokens; safety-critical components keep minimum contrast and unmistakable status semantics. No private application-image wallpaper exists in this scope; public profile imagery is bounded to the public profile canvas and cannot displace critical actions, signing or live PoH video. **Published personal profile backgrounds** render within the visited profile canvas only, are visible to other accounts by default, and remain suppressible for accessibility. Group-suggested colors are optional and never override viewer accessibility requirements. See M-001 through M-013.

**Safety exceptions to “less information”:** signing authority, loss-of-key warnings, consent before camera capture, evidence recipient identity, conflict-of-interest checks, recusal, irreversible action/appeal deadlines, network trust/mismatch, requested scope and rejected results must remain visible at the moment the user makes a decision. Move technical dumps and generic tutorial paragraphs, not critical safety details.

### Pattern-by-pattern visual wireframes

**Hub:** `Title · status` → `Next action / one CTA` → `Filter` → `Relevant list` → `Past/history link`.

**Detail:** `Public object + scope + stage` → `Local tabs` → `One selected panel` → `Permitted action` → `Receipt reference`.

**Task:** `Back · step N/M` → `What you are doing` → `Mandatory safety/consent` → `Fields/media` → `One submit button` → `Submitted / canonical result`.

**Live room:** `Case + participant/status` → `Large reciprocal video grid` → `Connection, mic/camera state` → `Attendance/decision (when assigned)` → `Canonical finality / teardown`. Technical room descriptors are in Help/advanced, never between video and required control.

**Reviewer case:** `Assignment/recusal` → `Evidence preview (authorized)` → `Signed verdict` → `Review record`; preserve reporter and jury roles as distinct views.

**Node:** `Selected chain identity / trust root` → `Readiness summary` → `One role-specific action` → `Dedicated sync, storage, validator and incident tabs`; do not bury sync mismatch in raw JSON.

## 10. Permissions, privacy and product non-claims

- Protocol-authoritative roles, membership, tiers and signing gates remain backend-enforced; UI never grants authority.
- Public-native civic/group content stays publicly readable; write operations and protected PoH evidence remain permission-gated.
- P2P/private/direct/encrypted messaging is **out of scope** by explicit design decision. No Messages inbox, conversation page, chat-specific background/theme, messaging route or transport/E2EE promise is included in this specification.
- Local application color-theme and layout preferences are **not protocol data**. **Explicitly published personal-profile media** and collective group branding are separate authorized public publication processes; no secret, location metadata, session or key may leak through a theme export or background image metadata.
- Public personal-profile background removal changes the current visual reference; historical distributed copies cannot be guaranteed erased. No browser-side image-selection action alone should make private images public.
- Arbitrary user CSS, scriptable themes, third-party wallpaper fetches and automatic theme synchronization are outside this specification.
- Development/bootstrap identities and local two-process rehearsal are not independent human or public-network proof.
- No activation of locked economics, validator, helper, storage-market, production or constitutional authority from this design.
- Do not confuse signed requests, API acceptance, inclusion, rejected-apply receipts, chain finality and user-facing success.
- Existing deep links, key custody, transaction nonces and canonical case IDs must be preserved.
- Unresolved PR81 README check_v15_artifacts failure remains open; layout design does not close it.

Additionally: a client tab or URL is not an authorization policy. Client defaults must reflect backend state. Public-native protocol objects and records should be findable; PII or encrypted identity evidence must not become public merely because it is “inspectable” in principle. Protocol-native private chat/DMs are not an active feature.

## 11. Specification review and sign-off boundaries — no implementation

This phase is **specification completion only**. The sequence below is a product-design review checklist, not a coding schedule or authorization to edit the repository.

| Review checkpoint | Required design evidence | Sign-off condition |
|---|---|---|
| S0 — global information architecture | Five stable navigation destinations; 28 current-route migrations; all 103 target route patterns; primary user journeys | Every destination has a clear parent, object, purpose, action and visibility posture. |
| S1 — screen and density contracts | Hub, detail, task, review, live-room, group-profile and node templates; responsive/motion/keyboard behavior | No overloaded page must be necessary to complete a normal task; safety-critical information remains visible when it matters. |
| S2 — group ownership and responsibilities | Group profile/posts, charter, members, scoped decisions, public treasury, emissary elections, mandates, duty desks, reports and records | A public visitor can browse a group; a member can find legitimate actions; a role holder enters duties via that group; scope is never expanded by navigation. |
| S3 — protocol truth and privacy boundaries | Product states from local preparation to canonical receipt; public/private disclosure; data-unavailable and economics-locked cases | No UI state invents approval, identity proof, transaction finality, funds, role assignment or cross-scope authority. |
| S4 — stakeholder review of all journeys | Account/PoH, feed/posts, groups, governance, oversight, reviewer duties, node/storage, transparency | Each described journey has a start, next action, distinct failure/empty states, canonical outcome, and a navigable return path. |
| S5 — appearance and visual identity | Preset/custom **application color themes**, safe import/export, **owner-published public profile background**, external visitor preview, accessibility overrides, group-suggested theme and governed group branding | A second account sees the same committed public profile background; there is no private profile/app image wallpaper or chat theme; visitors can hide decorative media for accessibility; authority and mobile readability remain intact. |

**Out of scope for this phase:** changing JSX/CSS/router code, implementing new APIs or consensus rules, opening a development PR, selecting implementation order, running visual regression, merging branches, or resolving the existing clean-clone `check_v15_artifacts` failure. Those belong to separate engineering/evidence decisions after this product specification is accepted.

## 12. Acceptance rubric for the entire information architecture

1. All 28 current route patterns have exact migration behavior and preservation tests; direct URLs and reload/back work.
2. Top-level navigation has five stable slots; role changes do not reshuffle them.
3. Home shows one canonical next action and no competing tester walkthrough in routine use.
4. Every route has a single primary purpose and one contextual CTA; deeper tools require deliberate navigation.
5. Verification Tier 1/Tier 2 each has one focused pathway; no microphone/camera auto-start before consent.
6. Async evidence decrypt/view respects assigned reviewer and accepted assignment, not anonymous read.
7. Live room displays connected and decoded remote media, distinct from local preview, and forbids post-terminal restart.
8. Report visibility is public where intended, while protected evidence and reviewer signing controls are restricted.
9. Decision scope/phase and member-authority gates derive from backend, not client timers or tabs.
9a. Every group profile prominently shows group identity, scope, membership posture and public posts. Admin and governance tools live in linked sections, not below the feed.
9b. Group decisions and public reports match the same canonical record IDs, scopes, stages and receipts surfaced in global indexes.
9c. Treasury states distinguish **unavailable**, **locked**, **pending approval**, **authorized but unexecuted**, **executed with receipt**, and **failed/rejected**; no direct ungated transfer.
9d. Emissary positions, seats, ballots, terms and scoped mandates are sourced from authoritative records; `no_decision` outcomes confer no role.
9e. Signed-in group role holders can locate *their* group-specific duty desk from that group; non-role users cannot access protected data or action controls.
9f. Group identity remains visible on every nested page, including treasury proposals and global decision detail; cross-scope actions never arise from the client alone.
9g. Public financial and election transparency must not leak protected identity evidence, hidden votes or sensitive application records.
10. Profile appearance is public only when deliberately published and canonically confirmed; private recovery/session/device controls and unpublished drafts remain separate and never leak. No private profile wallpaper or per-visitor profile theme exists.
11. Node identity, sync, validator, helper and storage readiness are intelligible without claiming authority.
12. Every signed action shows submitted/confirmed/rejected/final with receipt and retry/nonce safeguards.
13. Mobile and keyboard navigation preserve focus, tab selection and form draft across appropriate route changes.
14. All current release/economics/public readiness NO-GO claims remain accurately displayed.
15. Each viewer can choose preset/custom **application color themes** with preview, cancel, apply and reset. Custom image wallpapers and per-conversation themes are out of scope; theme selection cannot modify public profile state.
16. Theme colors meet contrast and focus/accessibility requirements; critical signing, PoH and governance controls never inherit unsafe decorative styles.
17. Theme import/export is validated declarative data only and excludes private images, credentials, local paths, tracking endpoints and arbitrary executable content.
18. Group visuals are public only after authorized publication; optional group-suggested palettes require viewer opt-in and do not override personal accessibility settings.
19. Failed image loads, corrupted themes, storage exhaustion, cross-device use and unsupported group branding have explicit safe fallbacks.
20. An account owner can access `/me/profile-appearance`, choose a static background, preview at desktop/mobile sizes as an outside viewer, and separately confirm that it will be public.
21. Another authenticated account (and signed-out visitors wherever public profile reads exist) sees the **same committed public profile background** on `/people/:account`; this is public record-backed presentation, not owner-local wallpaper. Refresh and cross-device read preserve the confirmed result.
22. The public background is confined to the profile's cover/canvas and posts; visitor theme, accessibility, high-contrast and reduced-data preferences retain priority, with a visible background-suppression control.
23. Only the profile owner with canonical authorization can publish, replace or remove public appearance, and only where the supported profile contract permits it. Pending/failure states cannot replace the previously committed public image as if final.
24. A public-profile image is sanitized, metadata-stripped and size-bounded; merely selecting it in the **public-profile editor** cannot publish it without explicit confirmation and canonical authorization. No unpublished image, key, local path or PoH evidence leaks into public media or theme export.
25. Background replacement/removal has truthful storage/history wording: stop current display after committed removal, without promising deletion of prior public replicas; failures, unavailability and user-reported inappropriate backgrounds have safe fallbacks.

## 13. Source provenance and interpretation

**Current route and shell inventory** from [`web/src/lib/router.ts`](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/c5f66b9c602630384da944e93fcdfec45126c8d8/web/src/lib/router.ts), [`web/src/App.tsx`](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/c5f66b9c602630384da944e93fcdfec45126c8d8/web/src/App.tsx), [`AppShell.tsx`](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/c5f66b9c602630384da944e93fcdfec45126c8d8/web/src/components/AppShell.tsx), [`SidebarNav.tsx`](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/c5f66b9c602630384da944e93fcdfec45126c8d8/web/src/components/SidebarNav.tsx), and [`AppRightRail.tsx`](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/c5f66b9c602630384da944e93fcdfec45126c8d8/web/src/components/AppRightRail.tsx), plus component headings in `web/src/pages/*` at the exact SHA. Target screens and UX boundaries are **design decisions**, not claims of implemented features. No direct connection to your localhost browser was made in this analysis.

**Artifacts:** interactive full-layout map (HTML), this complete blueprint (Markdown), machine-readable full route/journey map (JSON). Before implementation, the map is complete as a scoped design proposal; individual UI details can be refined without rewriting its navigation backbone.

## 14. Architecture revision record and specification decisions

The v1.0 map treated `/groups/:id` as a generalized group workspace. v1.1 reframed it as a public community profile. **v1.2** specified group object ownership, exact child destinations, treasury status semantics, emissary mandates, group-specific role desks, public/private disclosure, independent acceptance scenarios and safe cross-scope navigation. **v1.3** proposed application themes, group branding and a private device-image wallpaper; the wallpaper portion is now superseded. **v1.4** added the dedicated `/me/profile-appearance` public publication task and cross-account display rules. **v1.5 introduced a proposed messaging module and per-chat themes; the user has explicitly withdrawn both. v1.6 restores messaging to out-of-scope, removes private image-wallpaper/profile appearance, retains ordinary local app color themes, and keeps only explicitly owner-published public personal-profile and governed public-group background media.** No changes to source code or PR #81 are implied. The `check_v15_artifacts` clean-clone failure remains unresolved and separate from UX design.


## 15. Specification-wide completion criteria and scope of sign-off

**This is a product specification, not a delivery order.** Approval of this document decides information placement and intended user-facing behavior; it does not approve protocol changes, create a release, close existing audit findings, or authorize a pull request or source-code edits.

Before design sign-off, reviewers should evaluate five cross-product consistency decisions as a set:

1. **Five stable primary destinations:** Home, Feed, Groups, Decisions, Account. All operator, oversight, and assigned-review functions remain discoverable through contextual/secondary entrances without displacing these five.
2. **Public profile symmetry:** Person and Group both have a readable public identity and public posts. A **person** may explicitly publish a background for visiting accounts; a **group** may publish collective visual identity under the group's governance/authorization rules. Their private duties/security/workspaces are not mixed into the public-facing post feed.
3. **Canonical object ownership:** Posts have one post ID; proposals have one decision ID; reports have one case ID; groups have one canonical scope; receipts have one authoritative provenance. Global pages index these same objects rather than copying them.
4. **Role and duty specificity:** Personal roles belong to Account/Node; group roles and mandates belong to the respective Group. A global task shortcut can *link* to a group desk but never becomes its authority source.
5. **Progressive disclosure without hidden safety:** Every view shows one principal task/object. Consent, scope, signer identity, authority, conflict/recusal, deadlines, key custody, and rejection/finality must stay visible at the decision point, not be buried in a drawer.
6. **Personal presentation vs public identity:** A viewer controls their **local application color theme and accessibility**, but does not have a private image wallpaper on any profile or chat. A person may explicitly publish a **public profile** background that others see; a group owns only legitimately published collective branding. The visited profile's image never overrides the visitor's global theme, accessibility or protocol status. A group's optional theme suggestion is never mandatory.

**Remaining verification—not speculative design gaps:** The blueprint is complete as a navigation and behavioral proposal. A separate protocol contract review must confirm which treasury/election/moderation data fields and signed actions already exist at the target PR before any screens claiming them are built. Absent support must render an explicit unsupported/locked state. The two-node rehearsal and the unresolved README artifact-verification failure remain independent technical evidence, not architectural acceptance.

**Status:** v1.6 — corrected **proposed specification for stakeholder review**; no implementation started or authorized by this document. Any changes after acceptance should be versioned as product-spec changes with recorded rationale.