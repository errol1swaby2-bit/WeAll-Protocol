# Phase 12 — bounded read-only runtime acceptance runbook

**This is an executable test plan, not an executed test report.** It does not modify source, CI, PR #97, or any canonical chain state. Use an isolated instance of the exact PR #97 frontend with test-only mocked APIs or dedicated disposable nodes; do not transmit real signed PoH, governance, economic or reviewer transactions.

## Common evidence manifest

Record: test-case ID and batch; repository and exact SHA; browser build/version; fixture identity (dummy, redacted); node/chain/genesis identity; request/response and clock (sanitized); viewport and zoom; initial/final URL and focused element; screenshot/video/trace when safe; intercepted submission count; expected/observed; result PASS/FAIL/BLOCKED; reason; evidence artifact SHA256. Never record bearers, private keys, recovery files or real evidence media.

## B01 — public route and keyboard skip

1. On an isolated browser profile with no local account, start at `/#/feed` with a public fixture endpoint and zero bearer.
2. Assert public Feed can be opened from primary navigation; no hidden authentication requirement to read.
3. Focus the first `Skip to content` link, activate by keyboard; record `location.hash`, `document.activeElement`, main content visibility, and console exceptions.
4. Repeat at 320px, 390px, and 1440px and with a direct deep link. Verify writes remain disabled for anonymous actor.
5. Tie observations to FE-001 / FE-024, R4-01/R4-02, and P8-23/P8-28. No code fix or failed-test retry should be automatically invoked.

## B03 — canceled juror note

1. Use a disposable, non-live Tier3 reviewer identity and mocked async review case. Block all outbound nonlocal requests.
2. Instrument mocks for the juror skeleton endpoint and any eventual signed transaction submission, initially zero.
3. Trigger approve and reject separately; dismiss the optional-note prompt with **Cancel**.
4. Assert zero request/signed-submission calls. If calls occur, record the exact intercepted payload and abort any actual signature or broadcast.
5. Compare against the deliberate-confirmation scenario in the same fixture. Tie to FE-029 and P5-01/P5-02/P5-03/P5-05.

## B06 — post creation unknown status

1. Use a dummy account with mocked signer and a deterministic media/post submission response.
2. Arrange a response with tx ID and **missing or zero** nonce (the conditional fallback) and inject `unknown` from the status endpoint; record all later stage requests.
3. Repeat with `pending`, `confirmed`, `rejected`, and an empty transaction ID, plus a separate nonzero nonce scenario.
4. Record whether drafts persist, whether any dependent step/confirmed UI advances prematurely, and whether repeat submission is prevented while outcome is unknown.
5. Tie to FE-042/FE-051, P9-01–P9-04 and P7-10/P7-13. Do not regard a submitted transaction as confirmed.

## Stop and release condition

Abort test execution on unexpected real credentials, personal media, nonmock authorization, uncontrolled signing, or nonlocal node writes. Each case must receive independently recorded PASS/FAIL/BLOCKED with evidence. Source assertion success, existing CI pass, or a nonfunctional route preview cannot close cases. All three batches remain **NOT RUN** in this Phase 12 handoff.
