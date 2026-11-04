import { readFileSync } from "node:fs";

const api = readFileSync(new URL("../../Weall-Protocol/src/weall/api/routes_public_parts/disputes.py", import.meta.url), "utf8");
const detail = readFileSync(new URL("../src/pages/DisputeDetail.tsx", import.meta.url), "utf8");
const listing = readFileSync(new URL("../src/pages/Disputes.tsx", import.meta.url), "utf8");
const language = readFileSync(new URL("../src/lib/userLanguage.ts", import.meta.url), "utf8");

function mustInclude(source, text) {
  if (!source.includes(text)) throw new Error(`Missing pending-appeal contract: ${text}`);
}
function mustNotInclude(source, text) {
  if (source.includes(text)) throw new Error(`Unsafe raw appeal rendering: ${text}`);
}
mustInclude(api, '"appeal_panel_readiness"');
mustInclude(api, '"already_filed"');
mustInclude(api, 'return ["appeal_pending_panel"]');
mustInclude(detail, "dispute?.appeal_total");
mustInclude(detail, "appealEligibility?.can_file === true");
mustInclude(detail, "Appeal accepted — awaiting independent jurors.");
mustInclude(detail, "The filing remains recorded even after the original filing deadline.");
mustInclude(listing, "View pending appeal");
mustInclude(listing, "final enforcement remains held.");
mustInclude(language, 'if (stage === "appeal_pending_panel")');
mustNotInclude(detail, "dispute.appeals.map(");
console.log("PR77 pending appeal API/frontend source checks passed");
