import { readFileSync } from "node:fs";

const review = readFileSync(new URL("../src/pages/DisputeReview.tsx", import.meta.url), "utf8");
const revalidation = readFileSync(new URL("../src/lib/disputeRevalidation.ts", import.meta.url), "utf8");

function assertIncludes(src, needle, label) {
  if (!src.includes(needle)) throw new Error(`${label}: missing ${needle}`);
}

assertIncludes(review, "canMarkAttendance", "review action route must expose attendance unlock gate");
assertIncludes(review, "DISPUTE_JUROR_ATTENDANCE", "review action route must submit signed attendance tx");
assertIncludes(review, "Mark attendance / check in", "review action route must give the user a visible Step 2 action");
assertIncludes(review, "final choices unlock only after backend attendance is visible", "review action route must explain why voting stays locked");
assertIncludes(review, "Accept, mark attendance/check in, decline, withdraw, or vote using signed protocol transactions", "review action route must document signed attendance boundary");

assertIncludes(revalidation, "getAuthHeaders", "dispute mutation revalidation must use scoped reviewer headers");
assertIncludes(revalidation, "weall.dispute(disputeId, args.base, headers)", "accept reconciliation must read scoped dispute view");
assertIncludes(revalidation, "attendance?.present === true", "attendance reconciliation must understand nested viewer_juror attendance");
assertIncludes(revalidation, "DISPUTE_JUROR_ATTENDANCE", "attendance tx type must remain a first-class reconcile target");

console.log("OK: dispute review vote unlock source checks passed");
