import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const dir = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(resolve(dir, "../src/pages/AccountVerificationPage.tsx"), "utf8");
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
console.log("PASS: async camera preview and local playback, upload-versus-signed-case status truth");
