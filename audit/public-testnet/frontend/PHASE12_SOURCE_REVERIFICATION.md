# Phase 12 — three targeted batches: exact-head source evidence

**Reference:** [`main` at `6d3d692`](https://github.com/errol1swaby2-bit/WeAll-Protocol/commit/6d3d69234415d294936d99e819367cff589ced3d); PR #97 `web/` subtree unchanged relative to this base (Phase 11 comparison of the PR). All links below point to exact audited-source paths, not to a development or remediation branch.

## B01: Anonymous Feed primary navigation and keyboard skip link

### FE-001 — source-confirmed primary-navigation inconsistency

- `web/src/components/PrimaryNavigation.tsx` lines 6–11 declare `{ label: "Feed", href: "/feed", sessionOnly: true }`. Lines 20–31 calculate `unavailable = item.sessionOnly && !ready` and set `disabled={unavailable}`.
- `web/src/App.tsx` lines 51–55 deliberately render `<Feed />` on `/feed` without requiring a session.
- **Narrow finding:** the **primary** public Feed tab is disabled for an anonymous observer, despite the public route. The page remains potentially accessible through a direct route; do not claim full feed lockout.
- Source: [https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/components/PrimaryNavigation.tsx](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/components/PrimaryNavigation.tsx); [https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/App.tsx](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/App.tsx).

### FE-024 — skip-link route-collision mechanism, not rendered yet

- `web/src/components/AppShell.tsx` lines 202–206: `<a className="appShellSkipLink" href="#app-shell-content">` without an activation handler.
- Lines 308–311: `<main id="app-shell-content" ... tabIndex={-1}>`. A DOM anchor target exists but the application uses a hash router (`/#/feed`). Following a raw fragment can replace that route segment. The actual navigation/focus response still requires browser observation.
- Source: [https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/components/AppShell.tsx](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/components/AppShell.tsx).

**Existing-test gap:** `web/scripts/test_accessibility_source.mjs` verifies that the text `Skip to content` and the target `id="app-shell-content"` exist. It does not activate the link or assert the hash route/focus. `web/scripts/test_focused_shell_source.mjs` similarly asserts source tokens, not keyboard behavior.

**Required runtime assertions:** anonymous `/#/feed` loads; primary Feed control remains available; Tab→Skip→Enter leaves the route `/#/feed`; focus lands on main; signed actions remain backend-gated; keyboard order and 320/390/1440px variations captured. **Status: NOT RUN.**

## B03: FE-029 juror decision cancellation

- `web/src/pages/JurorDashboard.tsx` lines 518–529: `const note = window.prompt("Optional note", "") || "";`, followed by `weall.pohAsyncTxReview(body, apiBase, headers)` and `submitSkeletonTx(...)`. Browser `prompt()` returns `null` on Cancel; the fallback converts it to `""` and no early return is visible in that function.
- Contrasting safeguard: `web/src/components/FeedView.tsx` explicitly checks `if (reasonRaw === null) return;` after its report prompt. This is **behavioral consistency evidence**, not a substitute reviewer authorization check.
- Source: [https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/JurorDashboard.tsx](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/JurorDashboard.tsx), [https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/components/FeedView.tsx](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/components/FeedView.tsx).

**Required runtime assertions:** with fake authenticated Tier3 reviewer and fully mocked endpoints, choose Approve/Reject→Cancel optional-note prompt; request counter for juror-review skeleton and signed submission remains **zero**. Deliberate confirmation should proceed through canonical gates. No real case or identity involved. **Status: NOT RUN.**

## B06: FE-051 unknown transaction state in post publishing

- `web/src/pages/CreatePostPage.tsx` lines 82–85: `isSubmittedOrConfirmed()` returns true for `confirmed`, `pending`, **and `unknown`**.
- Lines 643–664: when no nonzero submission nonce is returned but a transaction ID exists, the function checks `waitForTxConfirmed()` and then accepts any status recognized by that predicate before proceeding to retain `finalPostId` / return the submission object.
- **Boundary:** This is a conditional fallback; the ordinary nonzero-nonce path instead waits for account nonce advancement. No fresh test has shown which API branch is reached in production, whether backend inclusion fails, or what finality UI states result. The frontend distinguishes local transaction receipt in other components.
- Source: [https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/CreatePostPage.tsx](https://github.com/errol1swaby2-bit/WeAll-Protocol/blob/6d3d69234415d294936d99e819367cff589ced3d/web/src/pages/CreatePostPage.tsx).

**Required runtime assertions:** dummy node reply with tx ID and missing/zero nonce; return `unknown` vs `pending` vs valid successful receipt vs rejected; verify no optimistic **confirmed** outcome, no premature dependent stage/irreversible draft loss, no duplicate dispatch on retry, and honest path to Transactions. **Status: NOT RUN.**

## Evidence grading

- **E0 reverified:** exact source snippets above were fetched at the canonical SHA with the connected GitHub reader.
- **E1 historical:** existing PR #97 CI applies to the same `web/` tree but its successful tests are narrower than these cases.
- **E2 / E3:** no Phase 12 application browser or assistive-technology evidence. **No finding closed.**
