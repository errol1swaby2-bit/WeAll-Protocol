import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const dir = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(resolve(dir, "../src/pages/AccountVerificationPage.tsx"), "utf8");
const responsibilities = readFileSync(resolve(dir, "../src/components/TrustedResponsibilitiesPanel.tsx"), "utf8");
assert.match(source, /recordingPreviewRef/);
assert.match(source, /preview\.srcObject = stream/);
assert.match(source, /async-evidence-live-preview/);
assert.match(source, /autoPlay muted playsInline/);
assert.match(source, /async-evidence-playback-review/);
assert.match(source, /preload="auto"/);
assert.match(source, /async-upload-accepted/);
assert.match(source, /if \(!String\(upload\?\.cid \|\| ""\)\.trim\(\)\)/);
assert.match(source, /acceptedUpload = upload/);
assert.match(source, /post_upload_chain_steps/);
assert.match(source, /post_submission_refresh/);
assert.match(source, /do not re-upload the recording/);
assert.match(source, /POH_ASYNC_EVIDENCE_DECLARE/);
assert.match(source, /POH_ASYNC_EVIDENCE_BIND/);
// F2: every local step is independently visible and explicitly advanced.
for (const stage of ["explain", "prepare", "record", "review", "submit", "track"]) {
  assert.ok(source.includes(`data-testid="async-step-${stage}"`), `missing guided ${stage} stage`);
  assert.ok(source.includes(`asyncGuideStep === "${stage}"`), `stage ${stage} must be gated`);
}
assert.match(source, /aria-current=\{asyncStepIds\[index\] === asyncGuideStep/);
assert.match(source, /disabled=\{!asyncPreparationReady \|\| !registered/);
assert.match(source, /disabled=\{!asyncRecordedBlob \|\| !!asyncDurationError/);
assert.match(source, /disabled=\{!asyncSubmitCheck\.ok \|\| asyncEvidenceBusy/);
assert.match(source, /disabled=\{[^\n]+!!asyncUpload\}/);
assert.match(source, /setAsyncGuideStep\("track"\)/);
assert.match(source, /setAsyncConsent\(false\)/);
assert.match(source, /Only a canonical account tier update confirms verification/);
assert.match(source, /Inspect existing verification cases/);
assert.match(source, /Do not repeat an uncertain signed submission/);
assert.match(source, /asyncStepHeadingRef\.current\?\.focus\(\)/);
assert.match(source, /liveStepHeadingRef\.current\?\.focus\(\)/);
assert.equal((source.match(/ref=\{asyncStepHeadingRef\}/g) || []).length, 6);
assert.equal((source.match(/ref=\{liveStepHeadingRef\}/g) || []).length, 3);

// Live PoH must display request and canonical case visibility as separate stages.
for (const step of ["explain", "request", "track"]) {
  assert.ok(source.includes(`data-testid="live-step-${step}"`), `missing live ${step} stage`);
  assert.ok(source.includes(`liveGuideStep === "${step}"`), `ungated live ${step} stage`);
}
assert.match(source, /onClick=\{\(\) => void submitLiveRequest\(\)\}/);
assert.match(source, /No canonical live case is visible yet/);
assert.match(source, /A deterministic expected case ID or pending request is not proof/);
assert.match(source, /data-testid="live-verification-complete"/);
assert.match(source, /accountLevel >= 2 \? \(/);
assert.match(source, /<TrustedResponsibilitiesPanel/);
assert.match(responsibilities, /if \(accountLevel < 2\)/);
assert.match(responsibilities, /data-testid="trusted-responsibilities-locked"/);
assert.match(responsibilities, /data-testid="trusted-responsibilities-eligible"/);
assert.match(responsibilities, /onUpdateContentReviewLane\(true\)/);
assert.match(source, /tx_type: active \? "REVIEWER_LANE_OPT_IN" : "REVIEWER_LANE_OPT_OUT"/);
assert.match(source, /aria-label="Async verification steps"/);
assert.match(source, /aria-label="Live verification steps"/);

// A read error is unknown, never a confirmed empty history.
assert.match(source, /Promise\.allSettled\(\[/);
assert.ok(!source.includes('pohAsyncMyCases(acct, base, headers).catch(() => ({ cases: [] }))'));
assert.ok(!source.includes('pohLiveMyCases(acct, base, headers).catch(() => ({ cases: [] }))'));
assert.match(source, /setVerificationHistoryReady\(\{ async: false, live: false \}\)/);
assert.match(source, /asyncResponse\.value\?\.ok === true/);
assert.match(source, /live\.value\?\.ok === true/);
assert.match(source, /data-testid="async-history-unavailable"/);
assert.match(source, /data-testid="live-history-unavailable"/);
assert.match(source, /if \(!verificationHistoryReady\.async\)/);
assert.match(source, /if \(!verificationHistoryReady\.live\)/);

// Durable warning markers are written before any external side effect.
// The journal is not a receipt or evidence backup and must never auto-resend.
assert.match(source, /requireNoUnresolvedPoh\("async"\)/);
assert.match(source, /recordPohStage\("async", "upload_started", caseId\)/);
assert.match(source, /recordPohStage\("async", "encrypted_uploaded", caseId\)/);
assert.match(source, /recordPohStage\("async", "signed_started", caseId\)/);
assert.match(source, /requireNoUnresolvedPoh\("live"\)/);
assert.match(source, /recordPohStage\("live", "signed_started", ""\)/);
assert.match(source, /recordPohStage\("live", "signed_returned", expectedCaseId, txId\)/);
assert.match(source, /clearReconciledPohJournal\(acct, "async"/);
assert.match(source, /clearReconciledPohJournal\(acct, "live"/);
assert.match(source, /asyncJournalBlocked/);
assert.match(source, /liveJournalBlocked/);
assert.match(source, /PohSubmissionStatusNotice/);

console.log("PASS: async camera preview and local playback, upload-versus-signed-case status truth");
