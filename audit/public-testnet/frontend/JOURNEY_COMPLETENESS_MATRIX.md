# Phase 11 — frontend journey coverage and evidence gap matrix

**Date:** 2026-11-20 · **Canonical main:** [`6d3d692`](https://github.com/errol1swaby2-bit/WeAll-Protocol/commit/6d3d69234415d294936d99e819367cff589ced3d) · **PR #97 head:** `2ab08aa74b86806e1c4fef1f47b184d4f80c4793` (draft, open)  
**Mode:** Documentation-only, strictly read-only. No new browser runs, CI dispatch, transactions, edits, branch or merge actions.

Route coverage is sourced from the Phase 7 journey inventory and the intervening Phase 8–10 findings. “E0 reviewed” means source support, not successful navigation in a production browser.

| Journey | Surfaces | Related FE examples | Established evidence | Missing acceptance |
|---|---|---|---|---|
| **J01: Anonymous observer** | Feed, Groups, Decisions, thread, read-only navigation | FE-001, FE-003, FE-024, FE-045 | E0 source reviewed; E1 selected PR Web CI | E2 public-tab, deep-link, empty/error, E3 keyboard+mobile |
| **J02: Basic account creation and restoration** | LoginPage, AccountRegistrationPage, SessionDevicesPage | FE-017, FE-021, FE-030, FE-056, FE-058, FE-059 | E0 source reviewed; E1 PR browser custody subset | E2 registration journal/node switch; E3 accessible recovery |
| **J03: PoH guided asynchronous** | AccountVerificationPage, evidence upload, reviewer dashboard | FE-011, FE-017, FE-029, FE-030 | E0; E1 source/production smoke only | E2 all stages+interrupted journaling; E3 consent/assistive access |
| **J04: PoH live meeting** | LiveVerificationRoom, JurorDashboard, restricted evidence | FE-031, FE-032, FE-052 | E0; no media-access replay | E2 accepted/unaccepted/rejected + multi-browser media |
| **J05: Public Feed and search** | Feed, FeedView, group discovery | FE-001, FE-004, FE-005, FE-006, FE-028, FE-044, FE-045 | E0; some E1 smoke | E2 ranking race/search/pagination; E3 screen-reader sort |
| **J06: Post, reply and media publishing** | CreatePostPage, Thread, MediaGallery | FE-042, FE-047, FE-048, FE-051, FE-055 | E0; limited E1 static contract | E2 receipt unknown/failed/retry; E3 alt/caption/touch |
| **J07: Group creation and membership** | Groups, Group, GroupCreate | FE-002, FE-003, FE-040, FE-041, FE-046 | E0 | E2 Tier1/Tier2, collision, approval, pagination |
| **J08: Decisions and ballots** | Proposals, Proposal, ProposalCreate | FE-033, FE-034, FE-035, FE-036, FE-039, FE-043, FE-063 | E0; E1 limited rendered deliberation | E2 electorate/nullifier/ID; E3 timeline layout |
| **J09: Group elections/emissaries** | Group elections, GroupBallotPlanner | FE-040 | E0; E1 source checks in selected routes | E2 >100 election history and round-bound eligibility |
| **J10: Reports and juror work** | Disputes, DisputeReview, DisputeDetail, JurorDashboard | FE-011, FE-012, FE-014, FE-015, FE-016, FE-029 | E0 | E2 partial failures, cancellation, post-review states |
| **J11: Account profile and reputation presentation** | Account, public profile, roles | FE-037, FE-038, FE-039 | E0 | E2 Tier0-3, expired, suspended, changed role |
| **J12: Transaction history and recovery** | TxQueueProvider, TransactionsPage | FE-013, FE-022, FE-051, FE-057, FE-064 | E0; E1 receipt source checks | E2 two-node pending/rejected/unknown; E3 live announcements |
| **J13: Activity and preferences** | ActivityBell, Activity, activityReadState | FE-053, FE-060, FE-061, FE-062 | E0 | E2 notice freshness/read-state/offline/token renewal |
| **J14: Responsive & assistive navigation** | AppShell, mobile primary, dialogs, tabs | FE-024, FE-025, FE-026, FE-027, FE-028, FE-043, FE-049, FE-050, FE-054, FE-056 | E0; E1 theme contrast subset | E2 320/390/768/1440, 200/400% zoom; E3 screen reader |

## Cross-cutting personas and constraints

- **Anonymous / Tier0 / Tier1 / Tier2 / Tier3**: validate visually presented rights independently of signer/PoH backend protections. No real-person footage, identity secrets or governance actions on live community accounts.
- **Same account across two nodes, and two accounts on one browser**: verify chain identity, receipt provenance, sticky drafts, stale responses and disabled actions; do not loosen canonical source of truth.
- **320/390/768/1440px, 200% and 400% zoom, touch, keyboard and screen reader**: these are planned acceptance conditions, not claims of existing coverage.
- **Offline, delayed, failed, unknown and confirmed**: no false-empty, false-finality or premature draft loss.
