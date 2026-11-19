import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { retryTransientCanonicalRead } from "../src/lib/revalidation.ts";
import {
  allowedAsyncPohStep,
  allowedLivePohStep,
  findExpectedAsyncPohCase,
  findExpectedLivePohCaseId,
  asyncPohRoute,
  livePohRoute,
  parseAsyncPohRoute,
  parseLivePohJourneyRoute,
} from "../src/lib/pohGuidedRoutes.ts";

const ready = {
  basicAccountCreated: true,
  prepared: true,
  recordedValid: true,
  consentAndEvidenceValid: true,
  pendingJournal: false,
  recordingActive: false,
};
for (const step of ["explain", "prepare", "record", "review", "submit", "track"]) {
  const url = asyncPohRoute(step);
  assert.equal(parseAsyncPohRoute(url), step);
  assert.equal(allowedAsyncPohStep(step, ready), step);
  assert.equal(parseAsyncPohRoute(url + "?refresh=1"), step);
}
for (const step of ["explain", "request", "track"]) {
  assert.equal(parseLivePohJourneyRoute(livePohRoute(step)), step);
  assert.equal(allowedLivePohStep(step, 1, false, false), step);
}
assert.equal(parseAsyncPohRoute("/verification/async/garbage"), null);
assert.equal(parseAsyncPohRoute("/verification/live/journey/track"), null);
assert.equal(parseLivePohJourneyRoute("/verification/live/a-real-case"), null);
assert.equal(allowedAsyncPohStep("submit", { ...ready, recordedValid: false }), "record");
assert.equal(allowedAsyncPohStep("submit", { ...ready, consentAndEvidenceValid: false }), "review");
assert.equal(allowedAsyncPohStep("record", { ...ready, prepared: false }), "prepare");
assert.equal(allowedAsyncPohStep("prepare", { ...ready, basicAccountCreated: false }), "explain");
assert.equal(allowedAsyncPohStep("submit", { ...ready, pendingJournal: true }), "track");
assert.equal(allowedAsyncPohStep("explain", { ...ready, recordingActive: true }), "record");
assert.equal(allowedAsyncPohStep("track", { ...ready, recordingActive: true, pendingJournal: true }), "record");
assert.equal(allowedLivePohStep("request", 0, false, false), "explain");
assert.equal(allowedLivePohStep("request", 2, false, false), "explain");
assert.equal(allowedLivePohStep("request", 1, true, false), "track");
assert.equal(allowedLivePohStep("explain", 1, false, true), "track");
// Old async cases or a similarly named case for another owner cannot confirm an
// unrelated new upload, and case visibility alone is not reviewer readiness.
const olderAsyncCases = [
  { case_id: "pohasync:alice:past", account_id: "@alice" },
  { case_id: "pohasync:alice:incoming", account_id: "@mallory" },
];
assert.equal(findExpectedAsyncPohCase(olderAsyncCases, "@alice", "pohasync:alice:incoming"), null);
assert.equal(findExpectedAsyncPohCase(olderAsyncCases, "@alice", "pohasync:alice:past")?.account_id, "@alice");
assert.equal(findExpectedAsyncPohCase([{ case_id: "pohasync:alice:incoming", account_id: "@alice" }], "@alice", "pohasync:alice:incoming")?.case_id, "pohasync:alice:incoming");
assert.equal(findExpectedAsyncPohCase(olderAsyncCases, "@alice", "pohasync:alice:"), null);
assert.equal(findExpectedAsyncPohCase([], "@alice", "pohasync:alice:incoming"), null);
assert.equal(findExpectedAsyncPohCase(null, "@alice", "pohasync:alice:incoming"), null);
// Old cases, even for this same account, must never confirm a different signed request.
const oldLiveCases = [
  { case_id: "poh_live:@alice:4", account_id: "@alice" },
  { case_id: "poh_live:@alice:7", account_id: "@alice" },
];
assert.equal(findExpectedLivePohCaseId(oldLiveCases, "@alice", "poh_live:@alice:8"), "");
assert.equal(findExpectedLivePohCaseId([...oldLiveCases, { case_id: "poh_live:@alice:8", account_id: "@alice" }], "@alice", "poh_live:@alice:8"), "poh_live:@alice:8");
assert.equal(findExpectedLivePohCaseId([{ case_id: "poh_live:@alice:8", account_id: "@mallory" }], "@alice", "poh_live:@alice:8"), "");
assert.equal(findExpectedLivePohCaseId([{ case_id: "poh_live:@alice:8", account_id: "@alice" }], "@alice", "poh_live:@alice:0"), "");
assert.equal(findExpectedLivePohCaseId([{ case_id: "poh_live:@alice:8", account_id: "@alice" }], "@alice", ""), "");
assert.equal(findExpectedLivePohCaseId(null, "@alice", "poh_live:@alice:8"), "");
// Live request reconciliation must bind to the nonce-derived case, never any() case.
const livePage = readFileSync(new URL("../src/pages/AccountVerificationPage.tsx", import.meta.url), "utf8");
assert.match(livePage, /reconcileLiveCaseVisible\(acct, submittedLiveCaseId, base, headers\)/);
assert.match(livePage, /reconcileAsyncCaseVisible\(acct, submittedAsyncCaseId, base, headers\)/);
assert.match(livePage, /if \(!asyncCaseReviewability\(matched\)\.reviewable\)/);
assert.doesNotMatch(livePage, /reconcileAsyncCompatibilityCase/);
assert.match(livePage, /let submittedLiveCaseId = "";/);
assert.match(livePage, /waitForLiveCaseIdVisible\(acct, expectedCaseId, base, headers/);
assert.match(livePage, /if \(!clean\) return false;/);
assert.match(livePage, /if \(!txId\) throw new Error\("The signed live request returned no transaction ID/);

// App-shell route transitions MUST NOT remount the native recorder when
// only a guided step changed. All unrelated routes retain their distinct keys.
const shell = readFileSync(new URL("../src/components/AppShell.tsx", import.meta.url), "utf8");
const app = readFileSync(new URL("../src/App.tsx", import.meta.url), "utf8");
const router = readFileSync(new URL("../src/lib/router.ts", import.meta.url), "utf8");
assert.match(shell, /route.path === "\/verification\/async\/:stage"/);
assert.match(shell, /route.path === "\/verification\/live\/journey\/:stage"/);
assert.match(shell, /<main key=\{contentRouteKey\}/);
assert.match(shell, /setMenuOpen\(false\)/);
assert.match(app, /case "\/verification\/async\/:stage":/);
assert.match(app, /case "\/verification\/live\/journey\/:stage":/);
assert.ok(router.includes('"/verification/live/:caseId"'), "do not shadow existing case-room route");
// Exercise the exact shared read-only helper, with deterministic fake delays.
for (const status of [429, 502, 503, 504]) {
  let calls = 0;
  const delays = [];
  const actual = await retryTransientCanonicalRead(async () => {
    if (++calls < 3) throw { status };
    return { ok: true, cases: [] };
  }, () => true, async (ms) => { delays.push(ms); });
  assert.deepEqual(actual, { ok: true, cases: [] });
  assert.equal(calls, 3);
  assert.deepEqual(delays, [500, 1500]);
}
for (const status of [0, 400, 401, 403, 404, 409, 422, 500]) {
  let calls = 0;
  const failure = { status };
  await assert.rejects(retryTransientCanonicalRead(async () => {
    calls += 1;
    throw failure;
  }, () => true, async () => { assert.fail("nontransient read retried"); }), (error) => error === failure);
  assert.equal(calls, 1);
}
let attempts = 0;
const exhausted = { status: 429 };
await assert.rejects(retryTransientCanonicalRead(async () => {
  attempts += 1;
  throw exhausted;
}, () => true, async () => {}), (error) => error === exhausted);
assert.equal(attempts, 3);
let current = true;
let cancelledAttempts = 0;
await assert.rejects(retryTransientCanonicalRead(async () => {
  cancelledAttempts += 1;
  throw exhausted;
}, () => current, async () => { current = false; }), (error) => error === exhausted);
assert.equal(cancelledAttempts, 1);
// The helper must not coerce malformed successes, or grant readiness.
assert.equal(await retryTransientCanonicalRead(async () => null), null);
assert.match(livePage, /retryTransientCanonicalRead\(\(\) => weall\.pohAsyncMyCases\(acct, base, headers\), isCurrent\)/);
assert.match(livePage, /retryTransientCanonicalRead\(\(\) => weall\.pohLiveMyCases\(acct, base, headers\), isCurrent\)/);
assert.match(livePage, /if \(!isCurrent\(\)\) return;/);
assert.match(livePage, /historyReadSequenceRef\.current \+= 1/);
console.log("PASS: bounded canonical read retries preserve denial, exhaustion, cancellation and malformed-response boundaries");
console.log("PASS: URL-backed PoH routes cannot revive video, skip consent, or repeat uncertain signing");
