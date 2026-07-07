import { readFileSync } from "node:fs";

const disputes = readFileSync(new URL("../src/pages/Disputes.tsx", import.meta.url), "utf8");
const detail = readFileSync(new URL("../src/pages/DisputeDetail.tsx", import.meta.url), "utf8");
const review = readFileSync(new URL("../src/pages/DisputeReview.tsx", import.meta.url), "utf8");
const dashboard = readFileSync(new URL("../src/pages/JurorDashboard.tsx", import.meta.url), "utf8");
const first15 = readFileSync(new URL("../../Weall-Protocol/docs/testnet/FIRST_15_MINUTES.md", import.meta.url), "utf8");
const docs = readFileSync(new URL("../../Weall-Protocol/docs/testnet/DISPUTE_REVIEW_RENDERED_JOURNEY.md", import.meta.url), "utf8");

function assertIncludes(src, needle, label) {
  if (!src.includes(needle)) {
    throw new Error(`${label}: missing ${needle}`);
  }
}

function assertNotIncludes(src, needle, label) {
  if (src.includes(needle)) {
    throw new Error(`${label}: forbidden ${needle}`);
  }
}

assertIncludes(disputes, "Reports move through a public dispute timeline.", "Reports queue must name public dispute timeline");
assertIncludes(disputes, "raw PoH/video/government identity evidence must stay protected", "Reports queue must protect raw identity evidence");
assertIncludes(disputes, "Submission → assignment → attendance → vote → appeal → finalization", "Reports queue must show lifecycle ladder");
assertIncludes(disputes, "Finality comes from backend block height", "Reports queue must keep backend-height authority visible");
assertIncludes(disputes, "queueDeadlineText(item)", "Reports queue must expose deadline block state when present");
assertIncludes(disputes, "Report visibility is public-read; reviewer actions remain permissioned signed transactions.", "Reports queue must separate public read from signed actions");

assertIncludes(detail, "Review and appeal timeline", "Report detail must include timeline");
assertIncludes(detail, "withdrawal windows, appeal windows", "Report detail must include withdrawal/appeal windows");
assertIncludes(detail, "submission → assignment → acceptance → attendance → vote → tally → appeal window → finalization", "Report detail must show canonical dispute path");
assertIncludes(detail, "Outcome and reasoning trail", "Report detail must show outcome/reasoning section");
assertIncludes(detail, "Public records without exposing protected identity evidence", "Report detail must protect identity evidence");
assertIncludes(detail, "Only backend/finalized block state can mark a dispute final.", "Report detail must avoid premature finality");
assertIncludes(detail, "Reviewer notes, votes, appeals, and outcome records may be public", "Report detail must expose public reasoning boundary");

assertIncludes(review, "Dispute review action timeline", "Review route must include action timeline");
assertIncludes(review, "Review, withdrawal, timeout, appeal, and finalization windows are controlled by backend block heights", "Review route must use block-height authority");
assertIncludes(review, "Accept, decline, withdraw, and final choices are signed transactions", "Review route must tie actions to tx lifecycle");
assertIncludes(review, "This page must not call a review final until backend/finalized block state says so.", "Review route must avoid finality overclaim");
assertIncludes(review, "Protected PoH/video/government identity evidence must only unlock through reviewer-specific acceptance gates.", "Review route must protect identity evidence");
assertIncludes(review, "A submitted review is not final until transaction status and the dispute read model reconcile.", "Review route must not call submitted final");

assertIncludes(dashboard, "public outcome work queue, not a private inbox", "Review Center must not frame disputes as private inbox");
assertIncludes(dashboard, "raw PoH/video/government identity evidence stays behind reviewer acceptance gates", "Review Center must gate protected evidence");

assertIncludes(first15, "Dispute and review rendered journey readiness", "First 15 minutes must link dispute/review checklist");
assertIncludes(first15, "Reports queue/detail/review-timeline screenshot", "First 15 minutes must request dispute transcript evidence");
assertIncludes(first15, "backend block height, not browser timers", "First 15 minutes must preserve block-height boundary");

assertIncludes(docs, "Reports queue → Report detail → Review Center → Report review action route → Transactions → Report detail", "Docs must define canonical rendered path");
assertIncludes(docs, "submission → assignment → acceptance/decline → attendance/check-in → review vote → tally/outcome → appeal window → appeal review if filed → finalization", "Docs must define canonical lifecycle");
assertIncludes(docs, "a submitted review action is not final until transaction status and the backend read model reconcile", "Docs must preserve tx lifecycle honesty");
assertIncludes(docs, "raw PoH/video/government identity evidence must not render on this broad route", "Docs must protect sensitive evidence");

const combined = `${disputes}\n${detail}\n${review}\n${dashboard}\n${docs}`.toLowerCase();
assertNotIncludes(combined, "private dispute inbox", "Dispute/review surfaces must not imply private dispute inboxes");
assertNotIncludes(combined, "browser timer can finalize", "Browser timers must not finalize disputes");

console.log("dispute/review rendered journey source checks passed");
