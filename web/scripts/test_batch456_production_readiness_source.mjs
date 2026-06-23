import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const root = resolve(process.cwd(), "..");
function read(rel) {
  return readFileSync(resolve(root, rel), "utf8");
}
function assertIncludes(haystack, needle, label) {
  if (!haystack.includes(needle)) throw new Error(`${label} missing ${needle}`);
}

const status = read("Weall-Protocol/src/weall/api/routes_public_parts/status.py");
assertIncludes(status, '"block_production"', "status readiness payload");
assertIncludes(status, '"tokenomics"', "status readiness payload");
assertIncludes(status, '"protocol_native_private_messaging"', "status readiness payload");
assertIncludes(status, "PRIVATE_MESSAGING_UNSUPPORTED", "messaging status truth");

const messagingDoc = read("Weall-Protocol/docs/P2P_ENCRYPTED_MESSAGING_PRODUCTION_GATE.md");
assertIncludes(messagingDoc, "PRIVATE_MESSAGING_UNSUPPORTED", "public-only messaging gate doc");
assertIncludes(messagingDoc, "WeAll is not a private messaging protocol", "public-only messaging gate doc");
assertIncludes(messagingDoc, "notifications derive from public protocol events", "public-only messaging gate doc");

const econDoc = read("Weall-Protocol/docs/ECONOMICS_LOCKED_TOKENOMICS_MODEL.md");
assertIncludes(econDoc, "locked Genesis model", "locked tokenomics doc");
assertIncludes(econDoc, "Permanently fee-free", "locked tokenomics doc");

const reviewerScript = read("Weall-Protocol/scripts/reviewer_production_readiness_gate.sh");
assertIncludes(reviewerScript, "check_tx_canon_artifacts", "reviewer gate script");
assertIncludes(reviewerScript, "test_batch456_production_readiness_and_p2p_e2ee_gates.py", "reviewer gate script");

console.log("batch456 production readiness source checks passed");
