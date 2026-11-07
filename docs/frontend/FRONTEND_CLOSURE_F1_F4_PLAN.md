# Frontend protocol integration and guided journeys — F1–F4

Status: **implementation plan / open acceptance**, November 4, 2026.
This document is not release evidence and does not imply production readiness.

## Direction

The WeAll application is a public civic client, not a protocol inspector.
A first-time user should understand a page before learning protocol vocabulary.
Each section's landing page should show current status, the next available
action, and recent activity. Multi-step actions should open guided pages.
Advanced technical receipts and audit records remain inspectable on demand.

Keep backend admission and consensus as the authority. Frontend steps are
usability controls, not substitutes for signed actions, PoH adjudication,
quorum certificates, or verified state synchronization.

## F1 — Account creation, authentication, recovery

**F1a — drafted in PR #82 (not merged):**
- Generate a local signing key and distinct recovery/evidence authorities.
- Verify the exported recovery material *before* creating the new account session.
- Route account registration through /onboarding/register, not the dense
  verification landing page.
- Check real account state and its public key. The existing
  /v1/accounts/{account}/registered endpoint measures Tier-2 eligibility,
  **not** the existence of a basic account.
- Submit the canonical ACCOUNT_REGISTER transaction with current work policy.
- Track a transaction until the local node has synchronized confirmed state.
- Block duplicate registration while pending, and do not call a mismatch or
  unreachable node a successful registration.
- Keep raw private material session-scoped; persist only nonsecret tx pointers.

**F1b — not yet completed:**
- Resume an interrupted creation journey across page refresh/device restarts
  without generating new key material over an existing account.
- End-to-end return-user sign-in, restoration, signer loss, session expiration,
  passkey convenience, logout/revocation, and registered key mismatch messaging.
- Device/session key registration and expiry handled through protocol-backed
  paths, not prompts requiring nontechnical users to paste raw session keys.
- Accessibility including keyboard-only and screen-reader flows.
- Browser E2E with fresh account, wrong recovery file, account collision,
  already registered account, rejected transaction, node outage, and
  upstream accepted-but-unsynced transaction.

F1a must remain DRAFT until the actual browser custody journey is green on
the exact branch head. Unit/static checks alone are insufficient.

## F2 — Guided Proof-of-Humanity journeys

The existing AccountVerificationPage contains multiple responsibilities,
including account setup, async video acquisition, encrypted evidence upload,
reviewer-access binding, live request generation, trusted roles, and case
history. Extract the transactional operations into reusable actions/hooks;
do not copy-paste them into independent pages.

Proposed separate routes:
- /verification — status and next action only.
- /verification/async/start — why, privacy, eligibility and overview.
- /verification/async/prepare — camera/mic test, consent, challenge.
- /verification/async/record — accessible prompt and 1–2 minute recording.
- /verification/async/review — watch/redo, verify consent.
- /verification/async/submit — encrypted evidence + sequential chain actions,
  explicit partial success, nonce reservations and idempotency.
- /verification/async/status — reviewability, reviewer access and decision.
- /verification/live/* — similar staged live-room preparation, session,
  attendance and outcome; preserve its P2P/commitment trust boundary.
- /reviews — reviewers see only assigned, authorized cases.

The flow must not persist raw video in unsecured storage, bypass account
tier/reputation gates, mark accepted as confirmed, or claim that a media upload
alone means reviewable/finalized. Interrupted workflows should recover status
from chain and queued tx receipts, not resend evidence blindly.

## F3 — Full frontend protocol action inventory

**Statuses below are audit TODO, not claims of completed integration.**
For each feature, record:
(1) UI entry route,
(2) protocol API/read model,
(3) signed tx type where applicable,
(4) who is eligible to act,
(5) accepted vs committed vs synced status,
(6) empty/error/retry paths,
(7) reviewer-visible/auditable evidence and test references.

| Capability | UI surface to audit | Validation status |
| --- | --- | --- |
| Identity and key custody | /login, /session, /settings, /account/:account | F1a draft; F1b open |
| Async / live PoH | /verification, /verification/live/:caseId | F2 open |
| PoH juror assignment/review | /reviews, /verification | F2 open |
| Social feed, posts, replies, reactions | /feed, /create, /post/:id | F3 open |
| Public profiles and reputation | /profile, /account/:account | F3 open |
| Groups and membership administration | /groups, /groups/:id, /groups/create | F3 open |
| Governance proposals and voting | /decisions, /decisions/:id, /decisions/create | F3 open |
| Reports, disputes and appeals | /reports, /reports/:id, /reviews/:id | F3 open |
| Economic balances and transfers | /economics, /transactions | F3 open |
| Node joining and participation | /node, /advanced | F3 open |
| Role/service responsibilities | /verification, /reviews, /account/:account | F3 open |

A button present on a page does not count as connected. Each journey must
complete a real authorized signed action, verify canonical finality, and
reconcile the resulting state on both endpoints where applicable.

## F4 — UI quality, accessibility and acceptance

- Mobile-first layouts, limited information density, short plain-language
  descriptions, progress indicators and one primary action at a time.
- Clear difference between a technical error, an in-progress transaction, and
  a genuine denial. Advanced payloads can be expanded without hiding the
  underlying facts.
- Color/contrast, focus visibility, keyboard navigation, error association,
  permission alternatives and video captions/instructions where applicable.
- Clear recoverable status across navigation, page reload and connection loss.
- Run frontend typecheck/build, source contracts, Playwright E2E, security
  controls, two isolated browser profiles, and preserved-state two-node
  rehearsal *after* UI closure.

## Branch discipline

Backend integration work and unfinished review of PR #81 are separate.
PR #82 branches from main and concerns F1a only. Future PoH and full feature
work should be separate draft reviews or explicitly stacked without changing
the consensus/security truth of PR #81. Do not merge or advertise general
testnet readiness solely because the two local devnet ledger roots match.
