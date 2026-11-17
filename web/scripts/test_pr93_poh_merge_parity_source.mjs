import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const read = (path) => readFileSync(new URL(`../${path}`, import.meta.url), "utf8");

const app = read("src/App.tsx");
const wrapper = read("src/pages/PohPage.tsx");
const active = read("src/pages/AccountVerificationPage.tsx");
const archived = read("src/pages/AccountVerificationPageV16Preserved.tsx");
const rolePanel = read("src/components/TrustedResponsibilitiesPanel.tsx");
const historyPanel = read("src/components/VerificationHistoryPanel.tsx");
const registration = read("src/pages/AccountRegistrationPage.tsx");
const guided = read("src/lib/pohGuidedRoutes.ts");

// The active verified route MUST be the #82 guided source with #88 features
// intentionally extracted; #88's archived page may never become a second live
// registration or verification authority by accidentally being routed.
assert.match(app, /const PohPage = lazy\(\(\) => import\("\.\/pages\/PohPage"\)\)/);
assert.match(wrapper, /import AccountVerificationPage from "\.\/AccountVerificationPage"/);
assert.match(wrapper, /return <AccountVerificationPage \/>/);
assert.doesNotMatch(app + wrapper, /AccountVerificationPageV16Preserved/);
for (const target of [
  'case "/verification":',
  'case "/verification/async/:stage":',
  'case "/verification/live/journey/:stage":',
]) assert.ok(app.includes(target), `Missing production verification route: ${target}`);
assert.match(app, /case "\/verification\/live\/:caseId"/);

// The preserved v1.6 registration was replaced by the dedicated governed
// account registration journey. There must not be a second hidden signup flow.
assert.match(archived, /async function registerAccount\(/);
assert.doesNotMatch(active, /async function registerAccount\(/);
assert.match(active, /nav\("\/onboarding\/register"\)/);
assert.match(app, /case "\/onboarding\/register":/);
assert.match(registration, /persistSubmissionIntent\(/);

// Historical v1.6 tier-specific responsibility controls were moved to a
// dedicated panel, retaining their signed parent-driven opt-in/withdrawal.
assert.match(archived, /Responsibilities you can earn over time/);
assert.match(active, /<TrustedResponsibilitiesPanel/);
assert.match(rolePanel, /Responsibilities you can earn over time/);
assert.match(rolePanel, /onUpdateContentReviewLane\(true\)/);
assert.match(rolePanel, /onUpdateContentReviewLane\(false\)/);
assert.match(active, /tx_type: active \? "REVIEWER_LANE_OPT_IN" : "REVIEWER_LANE_OPT_OUT"/);
assert.match(rolePanel, /if \(accountLevel < 2\)/);
assert.match(rolePanel, /Applying or opting into a lane does not grant authority/);

// Verification history is an extracted read-only surface, not an empty-state
// substitution when a node fails to serve the current case history.
assert.match(archived, /Requests, reviews, and live sessions/);
assert.match(active, /<VerificationHistoryPanel/);
assert.match(historyPanel, /Requests, reviews, and live sessions/);
assert.match(historyPanel, /const allReady = asyncHistoryReady && liveHistoryReady/);
assert.match(historyPanel, /!visibleCount && allReady/);
assert.match(historyPanel, /poh-history-unavailable/);
assert.doesNotMatch(historyPanel, /submitSignedTx/);

// #82's guided URL stages, durable submission journal, and exact-case
// reconciliation must remain present in the active, routed page.
for (const required of [
  "readPohSubmissionJournal(",
  "savePohSubmissionJournal(",
  "requireNoUnresolvedPoh(",
  "allowedAsyncPohStep(",
  "allowedLivePohStep(",
  "findExpectedAsyncPohCase(",
  "findExpectedLivePohCaseId(",
  "finishAsyncReviewerAccess(",
  "submitAsyncEvidence(",
  "submitLiveRequest(",
]) assert.ok(active.includes(required), `Active verification source missing: ${required}`);
assert.match(guided, /if \(readiness\.pendingJournal\) return "track"/);
assert.match(guided, /if \(pendingJournal \|\| requestBusy\) return "track"/);
assert.doesNotMatch(active, /reconcileAsyncCompatibilityCase/);

// Section navigation is a presentation layer on the sole active controller.
assert.ok(active.includes('aria-label="Verification sections"'));
assert.ok(active.includes("VERIFICATION_SECTIONS.map"));
assert.ok(active.includes('asyncRecordingState === "recording" || isAsyncJourneyRoute'));
assert.ok(active.includes('isLiveJourneyRoute ? "live" : verificationSectionFromHash(guidedRoutePath)'));
assert.ok(active.includes('if (asyncRecordingState === "recording" || section === activeSection) return;'));
assert.ok(active.includes('disabled={asyncRecordingState === "recording" && entry.id !== "async"}'));
assert.ok(active.includes('if (asyncRecordingState === "recording" && parseAsyncPohRoute(path) !== "record")'));
assert.ok(active.includes('isAsyncJourneyRoute || asyncRecordingState === "recording" ? ('));
assert.ok(active.includes('activeSection !== "responsibilities"'));
assert.ok(active.includes('showHistory={showCaseHistory}'));
assert.ok(active.includes('showTechnical={activeSection === "technical"}'));
assert.ok(active.includes('isAsyncJourneyRoute && asyncGuideStep === "track"'));
assert.ok(active.includes('isLiveJourneyRoute && liveGuideStep === "track"'));
assert.ok(historyPanel.includes('hidden={!showHistory}'));
assert.ok(historyPanel.includes('hidden={!showTechnical}'));
assert.ok(historyPanel.includes('hidden={!showHistory && !showTechnical}'));

console.log(
  "PASS: PR93 active guided PoH retains focused v1.6 sections, recording and journal safeguards; archived page is not live"
);
