#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";

const root = process.cwd();
const read = (p) => fs.readFileSync(path.join(root, p), "utf8");
const accountVerification = read("src/pages/AccountVerificationPage.tsx");
const jurorDashboard = read("src/pages/JurorDashboard.tsx");
const liveRoom = read("src/pages/LiveVerificationRoom.tsx");
const account = read("src/pages/Account.tsx");

function assertIncludes(src, needle, label) {
  if (!src.includes(needle)) {
    console.error(`Missing ${label}: ${needle}`);
    process.exit(1);
  }
}

function assertNotIncludes(src, needle, label) {
  if (src.includes(needle)) {
    console.error(`Unexpected ${label}: ${needle}`);
    process.exit(1);
  }
}

assertIncludes(accountVerification, "asyncPreviewVideoRef", "async evidence preview ref");
assertIncludes(accountVerification, 'preload="metadata"', "metadata-only async evidence video preview");
assertIncludes(accountVerification, "stopAsyncPreviewBuffering();\n          const file = new File", "preview is paused before async upload");
assertIncludes(accountVerification, "upload does not depend on clicking the video controls", "user-facing async upload no-click note");

assertIncludes(jurorDashboard, "Accept live review assignment", "review queue accepts assignment label");
assertIncludes(jurorDashboard, "separate attendance check-in step", "review queue separates attendance check-in copy");
assertIncludes(liveRoom, "Step 1: accept assignment, then check in", "live room first-step label");
assertIncludes(liveRoom, "Step 2: check in and enter live room", "live room second-step label");
assertIncludes(liveRoom, "Acceptance, attendance, and verdict are separate chain-backed milestones", "live room milestone copy");
assertNotIncludes(liveRoom, "accepts the review assignment, records on-chain attendance, and starts media in one reviewer action", "misleading single-action live copy");

assertIncludes(account, "generate and register a separate node key", "operator onboarding sequence copy");
assertIncludes(account, "scripts/boot_node_operator.sh", "node operator reboot command");
assertIncludes(account, "scripts/external_observer_to_validator_live_gate.sh", "promoted validator reboot command");

console.log("rehearsal UX bugfix source checks passed");
