#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";

const root = process.cwd();
const liveRoom = fs.readFileSync(path.join(root, "src/pages/LiveVerificationRoom.tsx"), "utf8");
const webrtc = fs.readFileSync(path.join(root, "src/lib/webrtcLiveRoom.ts"), "utf8");

function assertIncludes(src, needle, label) {
  if (!src.includes(needle)) {
    console.error(`Missing ${label}: ${needle}`);
    process.exit(1);
  }
}

assertIncludes(webrtc, "new MediaStream([event.track])", "remote track fallback stream materialization");
assertIncludes(liveRoom, "pendingIceCandidatesRef", "pending ICE queue");
assertIncludes(liveRoom, "flushPendingIceCandidates", "pending ICE flush");
assertIncludes(liveRoom, "recoverMissingPeerMedia", "missing remote media recovery");
assertIncludes(liveRoom, "sendWebRTCSignal({ type: \"hello\", to_account: peer })", "targeted hello handshake");
assertIncludes(liveRoom, "processedSignalsRef", "signal dedupe");
assertIncludes(liveRoom, "setLocalDescription({ type: \"rollback\" }", "offer glare rollback");
assertIncludes(liveRoom, "Peer states:", "peer state diagnostics");

console.log("batch453 live-room remote media source checks passed");
