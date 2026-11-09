import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const dir = dirname(fileURLToPath(import.meta.url));
const read = (path) => readFileSync(resolve(dir, "..", path), "utf8");
const page = read("src/pages/AccountVerificationPage.tsx");
const history = read("src/components/VerificationHistoryPanel.tsx");
const responsibility = read("src/components/TrustedResponsibilitiesPanel.tsx");

// An unavailable or malformed case-history response is UNKNOWN. A stale
// read-only list may remain visible but never implies no earlier request.
assert.match(page, /<VerificationHistoryPanel/);
assert.match(page, /asyncHistoryReady=\{verificationHistoryReady\.async\}/);
assert.match(page, /liveHistoryReady=\{verificationHistoryReady\.live\}/);
assert.match(page, /Promise\.allSettled\(\[/);
assert.match(page, /asyncResponse\.value\?\.ok === true/);
assert.match(page, /live\.value\?\.ok === true/);

assert.match(history, /const allReady = asyncHistoryReady && liveHistoryReady/);
assert.match(history, /!allReady \? \(/);
assert.match(history, /data-testid="poh-history-unavailable"/);
assert.match(history, /data-testid="poh-confirmed-empty-history"/);
assert.match(history, /!visibleCount && allReady/);
assert.match(history, /previous requests/);
assert.match(history, /role="status"/);
assert.match(history, /onClick=\{onRefresh\}/);
assert.ok(!history.includes("submitSignedTx"), "history must remain read-only");
assert.ok(!history.includes("setSession("), "history must not issue sessions");
assert.ok(!history.includes("localStorage.setItem"), "history must not write authority state");

// Advanced records remain opt-in and do not cover the history state.
assert.match(history, /<details className="advancedDisclosure" data-testid="poh-technical-records">/);
assert.match(history, /renderAsyncCase\(item\)/);
assert.match(history, /renderLiveCase\(item\)/);

// Eligibility is tier-gated in component while actual signed mutation still
// stays in the parent; extraction never grants juror or validator authority.
assert.match(page, /<TrustedResponsibilitiesPanel/);
assert.match(responsibility, /if \(accountLevel < 2\)/);
assert.match(responsibility, /data-testid="trusted-responsibilities-locked"/);
assert.match(responsibility, /TRUSTED_RESPONSIBILITIES\.map/);
assert.match(responsibility, /onUpdateContentReviewLane\(true\)/);
assert.match(page, /tx_type: active \? "REVIEWER_LANE_OPT_IN" : "REVIEWER_LANE_OPT_OUT"/);

console.log("PASS: extracted verification history distinguishes unavailable, empty and eligible responsibility views");
