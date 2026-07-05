# Dispute and review rendered journey readiness

This checklist is for bounded public observer / controlled testnet reviewers inspecting the Reports, Report Detail, Review Center, and Report Review pages.

The goal is not to prove public beta, public validator safety, mainnet moderation readiness, complete identity infrastructure, or complete anti-Sybil/collusion detection. The goal is to make the dispute/review journey understandable and honest during a controlled public-observer rehearsal.

## Required visible boundary

Every rendered dispute/review surface should make this boundary clear:

- report records, review tallies, appeals, reasoning records, and outcomes are public civic state;
- group or account membership may affect who can act, but it must not hide public report read visibility;
- selected reviewers can accept, decline, withdraw, check in, and vote only through signed protocol transactions;
- raw PoH/video/government identity evidence must not be exposed on broad report/detail routes;
- protected identity evidence may only unlock through reviewer-specific acceptance gates where the backend permits it;
- a browser timer cannot trigger timeout, appeal, sanction, or finalization;
- a submitted review action is not final until transaction status and the backend read model reconcile.

## Canonical rendered path

The normal tester path is:

```text
Reports queue → Report detail → Review Center → Report review action route → Transactions → Report detail
```

The dispute lifecycle should be understandable as:

```text
submission → assignment → acceptance/decline → attendance/check-in → review vote → tally/outcome → appeal window → appeal review if filed → finalization
```

A page may use backend-specific stage names such as `open`, `assigned`, `juror_review`, `voting`, `appeal_window`, `appealed`, `resolved`, or `finalized`, but it must still explain where the tester is in the lifecycle.

## Reports queue

Expected behavior:

- queue title explains that reports are public dispute records;
- visible report count, account standing, assigned count, and reviewer readiness are visible;
- queue filters do not imply private visibility;
- every report card shows target id/type, opened-by record, current stage, current reviewer status, review tally, attendance status, and deadline block information when exposed;
- selected reviewers get an obvious next action toward the review workspace;
- unassigned testers can still open the report detail read-only;
- no queue item labels a report final merely because a local action was submitted.

## Report detail

Expected behavior:

- detail page is the explanation route, not the final vote route;
- it shows the report id, target, opened-by record, reason, current status, reviewer status, vote tally, current recorded choice, and target content when available;
- timeline cards show current procedure block, next deadline block, blocks remaining, and estimated time as display-only;
- wall-clock estimates are explicitly subordinate to backend/finalized block height;
- appeal deadline, appeal count, and appeal filing eligibility are visible when relevant;
- public reasoning/outcome records are distinguished from protected identity evidence;
- finalization height and outcome summary are visible when the backend exposes them;
- reviewer notes, votes, appeals, and outcome records may be public; raw PoH/video/government identity evidence must not render on this broad route.

## Review Center / juror dashboard

Expected behavior:

- review lanes are separated: content review, dispute review, PoH async review, and PoH live review;
- the dashboard describes itself as a public outcome work queue, not a private inbox;
- Tier-2 human status is eligibility, not consent to every reviewer duty;
- assigned content/dispute reports route to the focused review workspace;
- PoH evidence is not loaded before reviewer acceptance;
- reviewer evidence controls clearly state the backend source and consent boundary.

## Report review action route

Expected behavior:

- the action page is visibly narrower than the queue/detail pages;
- it shows the same report id, target content, reason, stage, current reviewer status, vote tally, and recorded choice;
- action lifecycle text includes checking, saving, recorded, updating, visible, and failed states;
- accept, decline, withdraw, Keep Post, Remove Post, and Need More Review are signed protocol actions;
- the withdrawal window, review deadline, timeout posture, appeal window, and finalization height come from backend block-height state;
- accepted attendance must be visible before final choices unlock;
- one reviewer account cannot vote twice;
- submitted review actions point the tester to Transactions and read-model reconciliation rather than claiming immediate finality.

## Evidence to capture for AUD-628-P1-001

For an external public observer transcript, capture screenshots or logs for:

- Reports queue with public dispute boundary copy;
- a report detail page showing target, reason, timeline, deadline, appeal, outcome/reasoning cards, and protected evidence boundary;
- Review Center showing separated lanes and reviewer consent boundary;
- report review action route showing lock reason, timeline, withdrawal/deadline/finality cards, action controls, and transaction lifecycle wording;
- Transactions page for any accept/decline/withdraw/vote action, or an honest fail-closed result if the account is not permitted to act.

## Stop conditions

Stop and file a bug if any rendered page:

- treats a local click, mempool acceptance, or queue refresh as final review confirmation;
- lets browser time advance timeout, appeal, sanction, or finalization;
- exposes raw PoH/video/government identity evidence through a broad public route;
- presents Review Center as a private inbox;
- hides public report read visibility behind group or account membership;
- implies public beta, mainnet, public validator, live economics, automatic upgrade, production helper, legal, or storage-market readiness.
