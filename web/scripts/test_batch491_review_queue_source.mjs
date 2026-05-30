import fs from "node:fs";

const dashboard = fs.readFileSync(new URL("../src/pages/JurorDashboard.tsx", import.meta.url), "utf8");
const pendingWork = fs.readFileSync(new URL("../src/lib/pendingWork.ts", import.meta.url), "utf8");

function assertIncludes(name, source, needle) {
  if (!source.includes(needle)) {
    throw new Error(`${name} missing ${needle}`);
  }
}

assertIncludes("JurorDashboard report queue", dashboard, '"juror_review"');
assertIncludes("pending work reports", pendingWork, '"juror_review"');
assertIncludes("JurorDashboard still filters assigned reviewer reports", dashboard, "reportNeedsCurrentReviewer");
assertIncludes("pending work still routes assigned reports to reviews", pendingWork, "`/reviews/${encodeURIComponent(id)}`");

console.log("Batch 491 review queue source checks passed");
