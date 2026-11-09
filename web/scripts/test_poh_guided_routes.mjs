import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  allowedAsyncPohStep,
  allowedLivePohStep,
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
assert.equal(allowedLivePohStep("request", 0, false, false), "explain");
assert.equal(allowedLivePohStep("request", 2, false, false), "explain");
assert.equal(allowedLivePohStep("request", 1, true, false), "track");
assert.equal(allowedLivePohStep("explain", 1, false, true), "track");
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
console.log("PASS: URL-backed PoH routes cannot revive video, skip consent, or repeat uncertain signing");
