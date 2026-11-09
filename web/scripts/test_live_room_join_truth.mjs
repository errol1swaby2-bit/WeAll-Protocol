import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import ts from "typescript";

const here = dirname(fileURLToPath(import.meta.url));
const page = readFileSync(resolve(here, "../src/pages/LiveVerificationRoom.tsx"), "utf8");
const start = page.indexOf("export type LiveRoomJoinInputs");
const end = page.indexOf("export default function LiveVerificationRoom");
assert(start >= 0 && end > start, "live-room presentation contract must be defined in the mapped source module");
const source = page.slice(start, end);
const compiled = ts.transpileModule(source, {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
}).outputText;
const exports = {};
new Function("exports", compiled)(exports);
const view = exports.getLiveRoomJoinPresentation;
assert.equal(typeof view, "function");

const initial = {
  canJoinReview: true, busy: "", isReviewer: true,
  acceptedOnChain: false, attendedOnChain: false,
  p2pRunning: false, activeLocalMedia: false,
  expectedPeerCount: 1, connectedPeerCount: 0,
};
const status = (patch = {}) => view({ ...initial, ...patch });
assert.match(status().buttonLabel, /Accept review, check in/);
assert.match(status({ acceptedOnChain: true }).buttonLabel, /Record attendance/);
assert.match(status({ acceptedOnChain: true, attendedOnChain: true }).buttonLabel, /Start local media/);
assert.match(status({ isReviewer: false }).buttonLabel, /Start local media/);

const capture = status({ acceptedOnChain: true, attendedOnChain: true, p2pRunning: true, activeLocalMedia: true });
assert.equal(capture.disabled, true);
assert.match(capture.buttonLabel, /waiting for peer/);
assert.match(capture.mediaStatus, /0\/1 connected/);
assert.doesNotMatch(capture.mediaStatus, /connection established/);

const remote = status({ acceptedOnChain: true, attendedOnChain: true, p2pRunning: true, activeLocalMedia: true, connectedPeerCount: 1 });
assert.match(remote.buttonLabel, /Connected to 1/);
assert.match(remote.mediaStatus, /connection established/);
assert.match(status({ p2pRunning: true, activeLocalMedia: true, connectedPeerCount: 1 }).buttonLabel, /check-in unconfirmed/);
assert.match(status({ acceptedOnChain: true, attendedOnChain: true, p2pRunning: true, activeLocalMedia: false }).buttonLabel, /Media interrupted/);
assert.equal(status({ busy: "Recording on-chain attendance…" }).buttonLabel, "Recording on-chain attendance…");
assert.equal(status({ canJoinReview: false }).disabled, true);

assert.match(page, /disabled={joinPresentation\.disabled}/);
assert.match(page, /joinPresentation\.buttonLabel/);
assert.match(page, /data-testid="live-room-join-status"/);
assert.match(page, /peerConnectionsRef\.current\.get\(peer\)\?\.connectionState === "connected"/);
assert.doesNotMatch(page, /"Live room ready"/);
assert.match(page, /await pollWebRTCSignals\(\);\s+setP2pRunning\(true\)/);

// Independent-browser F2 acceptance must prove remote video in BOTH contexts
// before reviewer verdicts. A local preview or signaling status cannot pass.
const browserJourney = readFileSync(resolve(here, "../tests/e2e/poh_live_independent_browsers.spec.ts"), "utf8");
const actors = readFileSync(resolve(here, "../tests/e2e/m2_actor_helpers.ts"), "utf8");
assert.match(browserJourney, /waitForLiveRemoteMedia\(applicant\.page/);
assert.match(browserJourney, /waitForLiveRemoteMedia\(actor\.page/);
assert.match(browserJourney, /All independent browsers receive peer video before reviewers vote/);
assert.match(actors, /stream\.getVideoTracks\(\)\.some\(\(track\) => track\.readyState === "live"\)/);
assert.match(actors, /data-peer-connection-state/);
assert.match(actors, /data-remote-account/);
assert.match(actors, /HTMLMediaElement\.HAVE_CURRENT_DATA/);
assert.match(actors, /element\.videoWidth > 0/);
assert.match(actors, /!track\.muted/);
assert.match(page, /if \(!p2pRemoteAccounts\.includes\(from\)\) return;/);
assert.match(page, /const refreshCanonicalCase = async/);
assert.match(page, /nextCase\?\.case_id === caseId/);
assert.match(page, /if \(!allowedPeers\.has\(peer\)\) resetPeerConnection\(peer\)/);
assert.match(page, /if \(!isFinal\) return;/);
assert.match(page, /Verification concluded; live media stopped/);
assert.match(page, /window\.setInterval\(\(\) => void refreshCanonicalCase\(\), 4000\)/);
assert.doesNotMatch(
  page.slice(page.indexOf("const p2pParticipantAccounts = useMemo"), page.indexOf("const p2pRemoteAccounts = useMemo")),
  /chainParticipants\.forEach|presence\.forEach/,
);
console.log("PASS: reviewer attendance, local capture and connected peers reported independently");
