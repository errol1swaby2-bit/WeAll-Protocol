# WeAll frontend — 64-item normalized finding index

**Date:** 2026-11-20 · **Canonical main:** [`6d3d692`](https://github.com/errol1swaby2-bit/WeAll-Protocol/commit/6d3d69234415d294936d99e819367cff589ced3d) · **PR #97 head:** `2ab08aa74b86806e1c4fef1f47b184d4f80c4793` (draft, open)  
**Mode:** Documentation-only, strictly read-only. No new browser runs, CI dispatch, transactions, edits, branch or merge actions.

This is a **navigation and traceability index**, not a replacement for full finding narratives or a change to severity. All original reports remain in the accompanying ZIP. Priorities are carried forward as recorded, including P1/P2, candidates and program-level dependencies.

| ID | Phase | Original priority | Workstream | Original finding title | Numbered-case refs |
|---|---:|---|---|---|---|
| FE-001 | 1 | P1 | W1 | Public Feed incorrectly disabled in five-tab navigation | R4-10, P8-28 |
| FE-002 | 1 | P1 | W5 | Directory overstates the PoH requirement for joining groups | P11-01 |
| FE-003 | 1 | P1/P2 | W2 | API errors can coexist with “empty directory / no decisions” messages | P11-02 |
| FE-004 | 1 | P1 candidate | W2 | Feed may display a stale response after scope or sorting changes | P11-03 |
| FE-005 | 1 | P2 | W2 | Directory and decision-count language does not clearly communicate result bounds | P11-04 |
| FE-006 | 1 | P2 | W2 | Group directory discovery is less capable than the intended product contract | P11-05 |
| FE-007 | 1 | P2 | W2 | Core civic pages remain heavy with technical/context copy | P11-06 |
| FE-008 | 1 | P2 candidate | W2 | Some account-dependent directory data is initialized only on mount | P11-07 |
| FE-009 | 1 | P2 | W2 | Large composite screens need bounded presentation refactoring | P11-08 |
| FE-010 | 1 | Program-level dependency | W2 | Existing status documents flag unfinished v1.6 task delivery | P11-09 |
| FE-011 | 2 | P1 | W6 | Reviewer queues suppress service failures | R2-01, R2-02, R2-03, R2-04 |
| FE-012 | 2 | P1/P2 | W5 | Reviewer readiness assumes signer availability on several pages | R2-05, R2-06 |
| FE-013 | 2 | P2 | W7 | Transaction activity history is not scoped to account | R2-15, R2-16 |
| FE-014 | 2 | P1 | W5 | Provisional bootstrap “assigned” status can overstate reviewer authority | R2-07, R2-08, R2-09, R2-10 |
| FE-015 | 2 | P2 | W6 | Reports “Open / unresolved” counter disagrees with backend stages | R2-11, R2-12 |
| FE-016 | 2 | P2 | W6 | “Assigned to me” matches past/terminal juror statuses | R2-13, R2-14 |
| FE-017 | 3 | P1 | W3 | Selected-account identity has two disconnected sources | R3-01, R3-02, R4-11, P8-29 |
| FE-018 | 3 | P1 | W3 | In-flight account reads are not guarded against account or node switches | R3-02, R3-03, R3-04, R3-05 |
| FE-019 | 3 | P1/P2 | W3 | Mounted pages and development Settings can retain old API targets | R3-06, R3-07, R3-08, R3-09, R4-12 |
| FE-020 | 3 | P2 | W3 | Chain ID cache is global rather than tied to the selected node | R3-10, R3-11, R3-12 |
| FE-021 | 3 | P2 | W3 | Missing tab-scoped session bearer may be displayed as active | R3-13, R3-14, R3-15, R4-13 |
| FE-022 | 3 | P2 | W3 | Finality monitoring can follow a different node than the submitted action | R3-16, R3-17, R3-18, R4-14, P8-29 |
| FE-023 | 3 | P1 investigation | W3 | Session teardown can clear coordination state while an operation is still pending | R3-19, R3-20, R3-21, R4-15 |
| FE-024 | 4 | P1 | W1 | Skip-to-content anchor changes hash route (P1, confirmed source defect) | R4-01, R4-02, P8-23 |
| FE-025 | 4 | P2 | W1 | Duplicate top-level headings (P2, source-confirmed hierarchy inconsistency) | R4-03, R4-04 |
| FE-026 | 4 | P2 candidate | W1 | Route-change focus is not explicitly managed (P2 candidate) | R4-05, R4-06, P8-24 |
| FE-027 | 4 | P3 | W1 | Breadcrumb accessible-label semantics (P3, source confirmed) | R4-07 |
| FE-028 | 4 | P2 | W1 | Feed sort active state only conveyed visually (P2, confirmed source gap) | R4-08, R4-09, P8-25 |
| FE-029 | 5 | P1 | W4 | Cancel on reviewer note prompts does not cancel the verdict | P5-01, P5-02, P5-03, P5-04, P5-05 |
| FE-030 | 5 | P2 | W4 | Existing session bearer is displayed in a plaintext native prompt | P5-06, P5-07 |
| FE-031 | 5 | P1 candidate | W4 | External video room is opened before the canonical accept/check-in sequence | P5-08, P5-09, P5-15 |
| FE-032 | 5 | P1 investigation | W4 | Media signaling eligibility is based on case membership, not explicit acceptance | P5-10, P5-11, P5-12, P5-13, P5-14 |
| FE-033 | 6 | P1 | W5 | Voting UI Tier2 readiness ignores active electorate | P6-01, P6-02, P6-03, P6-04, P6-05 |
| FE-034 | 6 | P2 | W5 | Redacted ballots leave repeat-vote action available | P6-06, P6-07, P6-08, P6-09 |
| FE-035 | 6 | P2 | W5 | Public vote-map fallback cannot reconcile strict redacted ballot | P6-10, P6-11, P6-12 |
| FE-036 | 6 | P1/P2 | W5 | Multi-option ballots expose invalid Vote Yes shortcut | P6-13, P6-14, P6-15, P6-16 |
| FE-037 | 6 | P2 | W5 | Tier1 Interaction Enabled overstates ordinary rights | P6-17, P6-18, P6-19 |
| FE-038 | 6 | P1/P2 | W5 | Account registration badge conflates basic account and posting | P6-20, P6-21, P6-22, P6-23 |
| FE-039 | 6 | P1 investigation | W5 | Effective PoH differs from legacy tier used by electorate | P6-24, P6-25, P6-26, P6-27, P6-28 |
| FE-040 | 7 | P2 | W2 | Group election index has no UI pagination despite known next offset | P7-01, P7-02, P7-03 |
| FE-041 | 7 | P2 | W7 | Group creation abandons composer after submission without awaiting canonical inclusion | P7-04, P7-05, P7-06, P7-07, P8-27 |
| FE-042 | 7 | P2 | W7 | Post and reply drafts are cleared before all canonical transaction outcomes are known | P7-08, P7-09, P7-10, P7-11, P7-12 (+2 further; see machine index) |
| FE-043 | 7 | P2 candidate | W2 | Decision lifecycle forces eight columns, bypassing responsive grid rule | P7-14, P7-15, P7-16, P7-17, P8-21 (+1 further; see machine index) |
| FE-044 | 7 | P2 | W1 | Feed scope selector does not expose the selected scope programmatically | P7-18, P7-19, P7-20, P8-25 |
| FE-045 | 7 | P3 | W1 | Signed-out “My posts” selection renders public feed beneath an explanatory notice | P7-21, P7-22, P7-23, P8-26 |
| FE-046 | 7 | P2 | W7 | Group ID derives solely from title, with no collision recovery or alternate choice | P7-24, P7-25, P7-26, P7-27 |
| FE-047 | 8 | P2 | W8 | Social images have no author-entered descriptive text; viewer uses file or object labels as alt | P8-01, P8-02, P8-03, P8-04, P8-05 |
| FE-048 | 8 | P2 | W8 | Uploaded audio/video has no caption, subtitle or transcript workflow in the inspected UI | P8-06, P8-07, P8-08, P8-09, P8-10 |
| FE-049 | 8 | P3 candidate | W1 | Verification/settings section selectors lack explicit controlled-panel relationships | P8-11, P8-12, P8-13, P8-14, P8-15 |
| FE-050 | 8 | P3 candidate | W2 | Eight group-profile sections depend on horizontal scrolling without an explicit overflow cue | P8-16, P8-17, P8-18, P8-19, P8-20 |
| FE-051 | 9 | P1 candidate | W7 | Unknown transaction status is treated as sufficient in post/media submission fallback | P9-01, P9-02, P9-03, P9-04, P9-05 |
| FE-052 | 9 | P2 | W6 | Restricted evidence-video timer resets on replay/resume and does not account for pause | P9-06, P9-07, P9-08, P9-09, P9-10 |
| FE-053 | 9 | P2 | W9 | Activity count does not refetch new notices while user stays on the same route | P9-11, P9-12, P9-13, P9-14, P9-15 |
| FE-054 | 9 | P2 candidate | W1 | Context drawer marks itself modal but does not make the application background inert | P9-16, P9-17, P9-18, P9-19, P9-20 |
| FE-055 | 9 | P2 | W8 | Media loading failures have no explicit error, retry, or degraded-content affordance | P9-21, P9-22, P9-23, P9-24, P9-25 |
| FE-056 | 9 | P2 | W1 | Account registration renders a main landmark nested inside the shell main landmark | P9-26, P9-27, P9-28, P9-29, P9-30 |
| FE-057 | 9 | P3 | W7 | Illustrative action lifecycle card does not reflect actual transaction progress | P9-31, P9-32, P9-33, P9-34, P9-35 |
| FE-058 | 10 | P1/P2 | W3 | Pending registration journal omits node and chain provenance | P10-01, P10-02, P10-03, P10-04 |
| FE-059 | 10 | P2 candidate | W3 | Registration pending ID can remain associated with a prior selected account | P10-05, P10-06, P10-07, P10-08 |
| FE-060 | 10 | P2 | W9 | Activity refresh clears last-known notices and read-state presentation before success | P10-09, P10-10, P10-11, P10-12 |
| FE-061 | 10 | P3 | W9 | Previously muted Activity category may have no visible unmute control | P10-13, P10-14, P10-15, P10-16 |
| FE-062 | 10 | P2 candidate | W3 | Activity authorization headers are memoized only by account, not live session state | P10-17, P10-18, P10-19, P10-20 |
| FE-063 | 10 | P2 | W7 | Normal decision auto-generated IDs use only account, title slug and current second | P10-21, P10-22, P10-23, P10-24 |
| FE-064 | 10 | P2/P3 | W7 | Transaction history can be cleared without confirmation or recovery, across all local accounts | P10-25, P10-26, P10-27, P10-28 |

## How to retrieve the evidence

Each item in `08_PHASE11_MACHINE_READABLE.json` contains its **exact original ZIP member path**, source excerpt where retained, and all matching acceptance-case IDs. Never replace the original multi-paragraph FE finding with this one-line index.
