import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

const webRoot = resolve(process.cwd());
const repoRoot = resolve(process.cwd(), "..");

function readWeb(rel) {
  return readFileSync(resolve(webRoot, rel), "utf8");
}

function readRepo(rel) {
  return readFileSync(resolve(repoRoot, rel), "utf8");
}

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

const txPage = readWeb("src/pages/TransactionsPage.tsx");
const timeline = readWeb("src/components/TxPropagationTimeline.tsx");
const statusLib = readWeb("src/lib/status.ts");
const feedbackLib = readWeb("src/lib/txFeedback.ts");
const toast = readWeb("src/components/TxStatusToast.tsx");
const queue = readWeb("src/components/TxQueueProvider.tsx");
const packageJson = readWeb("package.json");
const first15 = readRepo("Weall-Protocol/docs/testnet/FIRST_15_MINUTES.md");
const docPath = resolve(repoRoot, "Weall-Protocol/docs/testnet/TRANSACTION_LIFECYCLE_RENDERED_EVIDENCE.md");
if (!existsSync(docPath)) {
  throw new Error("docs/testnet/TRANSACTION_LIFECYCLE_RENDERED_EVIDENCE.md must exist");
}
const doc = readFileSync(docPath, "utf8");

for (const needle of [
  "Lifecycle evidence ladder",
  "Submitted is not confirmed",
  "Mempool acceptance is not confirmation",
  "submitted, locally accepted, queued/pending, forwarded/gossiped, included in block, finalized/confirmed, rejected, removed from mempool, and unknown/unavailable",
  "Clearing it does not delete protocol records.",
  "Clear browser history only",
  "local_state_synced=false stays non-final on this observer",
  "Unknown / unavailable",
]) {
  assertIncludes(txPage, needle, "Transactions page lifecycle evidence");
}

for (const needle of [
  "TxTimelineEvidence",
  "Unknown / unavailable",
  "Terminal evidence",
  "Mempool acceptance, observer queueing, and gossip propagation are never rendered as confirmation by themselves.",
  "unknown/unavailable evidence as non-final Pending evidence",
]) {
  assertIncludes(timeline, needle, "TxPropagationTimeline evidence semantics");
}

for (const needle of [
  "raw?.local_state_synced === false",
  "Upstream confirmed / local sync pending",
  "not final local confirmation",
  "local_confirmed",
  "Locally included / upstream sync pending",
  "Unknown / unavailable",
  "propagation, inclusion, finality, or rejection evidence",
]) {
  assertIncludes(statusLib, needle, "tx status normalization evidence semantics");
}

for (const needle of [
  "Submitted, updating",
  "Submitted. Waiting for status evidence",
  "Accepted / queued",
  "Checking status",
  "Finalized",
]) {
  assertIncludes(feedbackLib, needle, "tx feedback labels must avoid premature finality");
}

for (const needle of [
  "Accepted or queued by the backend. This is not final confirmation.",
  "Checking status evidence and read-model visibility.",
  "The backend reports final confirmed state for this node.",
]) {
  assertIncludes(toast, needle, "tx toast must separate acceptance from finality");
}

for (const needle of [
  "Submitted. Updating this page so the result becomes visible.",
  "No tx id was returned. Check the affected page before treating this as final.",
  "timed out before showing final status evidence",
]) {
  assertIncludes(queue, needle, "tx queue provider must not call submitted actions done too early");
}

for (const needle of [
  "# Transaction lifecycle rendered evidence",
  "Submitted",
  "Locally accepted",
  "Queued / pending",
  "Forwarded / gossiped",
  "Included in block",
  "Finalized / confirmed",
  "Rejected",
  "Removed from mempool",
  "Unknown / unavailable",
  "`local_state_synced=false` must not be rendered as final local confirmation",
]) {
  assertIncludes(doc, needle, "transaction lifecycle doc");
}

for (const needle of [
  "Transaction lifecycle rendered evidence",
  "submitted, locally accepted, queued/pending, forwarded/gossiped, included in block, finalized/confirmed, rejected, removed from mempool, and unknown/unavailable are visibly distinct",
  "observer-edge upstream accepted/confirmed is separate from local observer state synced",
]) {
  assertIncludes(first15, needle, "first 15 minutes transaction lifecycle link");
}

assertIncludes(packageJson, "test:transaction-lifecycle-rendered-evidence-source", "package script exposes Pass 18 source gate");

const checked = [txPage, timeline, statusLib, feedbackLib, toast, queue, first15, doc].join("\n");
for (const forbidden of [
  "mempool acceptance is confirmed",
  "local acceptance is confirmation",
  "queueing is confirmation",
  "gossip is confirmation",
  "unknown propagation is success",
  "clearing history deletes protocol records",
  "Public beta ready",
  "Mainnet ready",
  "public multi-validator BFT ready",
  "live economics ready",
  "automatic protocol upgrades enabled",
  "production helper execution ready",
]) {
  assertNotIncludes(checked, forbidden, "transaction lifecycle surfaces must not overclaim readiness or finality");
}

console.log("OK: transaction lifecycle rendered evidence source checks passed");
