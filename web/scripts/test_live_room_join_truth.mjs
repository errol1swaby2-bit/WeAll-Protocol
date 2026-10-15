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
console.log("PASS: reviewer attendance, local capture and connected peers reported independently");
