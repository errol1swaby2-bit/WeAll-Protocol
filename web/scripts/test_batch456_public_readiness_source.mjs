import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

const root = resolve(process.cwd(), "..");
function read(rel) { return readFileSync(resolve(root, rel), "utf8"); }
function assertIncludes(haystack, needle, label) { if (!haystack.includes(needle)) throw new Error(`${label} missing ${needle}`); }
function assertMissing(rel) { if (existsSync(resolve(root, rel))) throw new Error(`${rel} must be removed`); }

const status = read("Weall-Protocol/src/weall/api/routes_public_parts/status.py");
assertIncludes(status, '"block_production"', "status readiness payload");
assertIncludes(status, '"tokenomics"', "status readiness payload");
assertIncludes(status, '"public_only_protocol_surface"', "status readiness payload");

const econDoc = read("Weall-Protocol/docs/ECONOMICS_LOCKED_TOKENOMICS_MODEL.md");
assertIncludes(econDoc, "locked Genesis model", "locked tokenomics doc");
assertIncludes(econDoc, "Permanently fee-free", "locked tokenomics doc");

const reviewerScript = read("Weall-Protocol/scripts/reviewer_production_readiness_gate.sh");
assertIncludes(reviewerScript, "check_tx_canon_artifacts", "reviewer gate script");
assertIncludes(reviewerScript, "test_batch456_public_readiness_gates.py", "reviewer gate script");

console.log("batch456 public readiness source checks passed");
