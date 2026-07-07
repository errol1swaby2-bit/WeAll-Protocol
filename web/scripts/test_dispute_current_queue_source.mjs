import { readFileSync } from "node:fs";

const dashboard = readFileSync(new URL("../src/pages/JurorDashboard.tsx", import.meta.url), "utf8");
const api = readFileSync(new URL("../src/api/weall.ts", import.meta.url), "utf8");

function assertIncludes(src, needle, label) {
  if (!src.includes(needle)) {
    throw new Error(`${label}: missing ${needle}`);
  }
}

assertIncludes(api, "disputesCurrent", "API client exposes backend current dispute queue");
assertIncludes(dashboard, "weall.disputesCurrent(apiBase, headers)", "juror dashboard must use backend current disputes queue");
assertIncludes(dashboard, "backendCurrentReports.length > 0 ? backendCurrentReports : fallbackReports", "juror dashboard must prefer backend queue over broad list fallback");
assertIncludes(dashboard, "reportNeedsCurrentReviewer(item, account)", "juror dashboard keeps viewer-scoped report filtering");

console.log("batch596 dispute current queue source checks passed");
