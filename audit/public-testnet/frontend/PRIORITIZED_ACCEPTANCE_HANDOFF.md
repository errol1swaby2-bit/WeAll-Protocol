# Phase 11 — prioritized read-only browser acceptance handoff

**Date:** 2026-11-20 · **Canonical main:** [`6d3d692`](https://github.com/errol1swaby2-bit/WeAll-Protocol/commit/6d3d69234415d294936d99e819367cff589ced3d) · **PR #97 head:** `2ab08aa74b86806e1c4fef1f47b184d4f80c4793` (draft, open)  
**Mode:** Documentation-only, strictly read-only. No new browser runs, CI dispatch, transactions, edits, branch or merge actions.

**This is a test plan, not a passed test report.** Run on isolated dummy accounts/test nodes. Keep PR #97 unmodified; if test execution requires separate fixtures, record fixture commit and never claim the PR’s UI changed. Every cited original case remains available in the ZIP.

| Batch | Priority | Frontend journey | Required role and context | Device/runtime | Related IDs | Existing test IDs to execute | Minimum acceptance outcome |
|---|---|---|---|---|---|---|---|
| **B01** | P1 | Anonymous/public navigation and skip link | Anonymous observer | 320px, 390px, 1440px + keyboard | FE-001, FE-024, FE-026, FE-045 | R4-01, R4-02, P8-23, P8-28, P7-21 | Keyboard skip must preserve route, Feed remains publicly reachable, no signing unlocked |
| **B02** | P1 | Account/node race and provenance | Account A/B, Node A/B, same/different chain | Two-browser two-node simulated delays | FE-017, FE-018, FE-019, FE-022, FE-023, FE-058, FE-059, FE-062 | R3-01, R3-02, P10-01, P10-05, P10-07, P10-17 | Only selected identity/network can update UI; receipts stay anchored; no duplicated sign |
| **B03** | P1 | Reviewer verdict cancellation | Tier3 juror, review fixture | Keyboard & browser prompt | FE-029 | P5-01, P5-02, P5-03, P5-05 | Cancel must cause zero signed verdict transactions; confirmed choice still obeys backend |
| **B04** | P1 investigation | Live room authority and confidential media | Applicant, accepted/unaccepted/declined jurors, outsider | Two-browser isolated WebRTC; backend signaling mocks | FE-031, FE-032, FE-052 | P5-08, P5-10, P5-11, P5-12, P5-13, P9-06 | Verify intended policy before pass/fail; no unauthorized media or false admission |
| **B05** | P1/P2 | Governance electorate and strict ballots | Tier2 member/outsider; closed/frozen election snapshot | Browser + canonical backend test fixtures | FE-033, FE-034, FE-035, FE-036, FE-039 | P6-02, P6-04, P6-08, P6-11, P6-13, P6-24, P6-28 | Unknown eligibility never shown as yes; redaction and nullifier remain protected |
| **B06** | P1 candidate | Media/post transaction unknown-state branch | Signed dummy account, media declaration | Backend tx-status returns pending/unknown/confirmed/rejected | FE-042, FE-051 | P9-01, P9-02, P9-03, P9-04, P7-10, P7-13 | Unknown is non-final and cannot authorize dependent continuation; drafts recoverable |
| **B07** | P2 | Civic directories and group actions | Tier0/1/2; group moderator | Error injection, >100 index rows | FE-002, FE-003, FE-005, FE-006, FE-040, FE-041, FE-046 | P7-01, P7-03, P7-04, P7-05, P7-24, P7-27 | Correct join tier, true empty/error, complete paged results, preserve creation intent |
| **B08** | P2 | Activity, notices, and account recovery | Authenticated dummy accounts with safe notice fixtures | Fast refresh, quiet hours, bearer renewal, node switches | FE-053, FE-060, FE-061, FE-062 | P9-11, P9-12, P9-13, P10-09, P10-13, P10-17 | Retain last-good authorized notices, fresh headers, auditable attention states |
| **B09** | P2 | Mobile/a11y visual acceptance | Anonymous + signed roles | 320/390/768/1440px; zoom 200/400%; screen reader | FE-025, FE-027, FE-028, FE-043, FE-044, FE-049, FE-050, FE-054, FE-056 | P7-14, P7-15, P8-11, P8-16, P8-21, P8-25, P9-17, P9-26, P9-30 | No unreadable overflow; landmarks, focus, choice and dialog isolation verified |
| **B10** | P2 | Social media accessibility and failed delivery | Media post with image/audio/video, restricted evidence | Screen reader and network 403/404/503 | FE-047, FE-048, FE-055 | P8-01, P8-06, P8-08, P9-21, P9-22, P9-23 | Meaningful alt/caption/transcript policy; media retry; no privacy leaks |
| **B11** | P2 | Composers, transaction activity, local history | Two dummy accounts, two signed actions | Delayed receipts, cross-account refresh, destructive action | FE-013, FE-041, FE-042, FE-057, FE-063, FE-064 | P7-08, P7-09, P7-12, P9-31, P10-21, P10-25, P10-26, P10-27 | Save draft and identity context; prevent ID collisions; no unconfirmed success |
| **B12** | P2 | Reports, roles and permissions | Reporter, reviewer, group moderator, juror | Partial endpoint failure and role transition | FE-011, FE-012, FE-014, FE-015, FE-016 | R2-01, R2-02, R2-03, R2-07, R2-17 | No false empty/assigned rights; distinguish provisional from canonical status |

## Evidence capture contract

For **each individual original case**: (1) exact commit and diff vs audited `main`; (2) environment (hosted/local, dummy accounts, node/chain IDs); (3) fixture and resulting request/response **without secrets**; (4) viewport, zoom and assistive technology, if relevant; (5) screen/console/trace capture with privacy review; (6) observed result and whether reproduced; (7) proposed fix or justified exception; (8) repeat after fixes with independent evidence. Record PASS, FAIL, BLOCKED or NOT RUN with precise rationale, not inference from unrelated CI.

## Safe execution boundary

- Read-only *audit* does not require a new PR or change to canonical `main`; use existing PR #97 only for tests if a runnable environment is available.
- Mocked **test fixtures** can simulate faults; do not send signed PoH, juror, financial or governance transactions to real accounts.
- Preserve canonical ballot privacy, PoH validity, media confidentiality, deterministic transaction ordering, and local observer receipt checks.
- Stop at the first potential unintended real-world authorization or credential exposure.
- Existing PR Web CI passed selected browser tests; it cannot be used to backfill PASS to any unexecuted FE acceptance case.
