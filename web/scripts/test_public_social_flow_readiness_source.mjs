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
    throw new Error(`${label}: forbidden phrase ${needle}`);
  }
}

const feedView = readWeb("src/components/FeedView.tsx");
const createPost = readWeb("src/pages/CreatePostPage.tsx");
const thread = readWeb("src/pages/Thread.tsx");
const content = readWeb("src/pages/Content.tsx");
const packageJson = readWeb("package.json");
const first15 = readRepo("Weall-Protocol/docs/testnet/FIRST_15_MINUTES.md");
const socialDocPath = resolve(repoRoot, "Weall-Protocol/docs/testnet/PUBLIC_SOCIAL_FLOW_READINESS.md");
if (!existsSync(socialDocPath)) {
  throw new Error("docs/testnet/PUBLIC_SOCIAL_FLOW_READINESS.md must exist");
}
const socialDoc = readFileSync(socialDocPath, "utf8");

for (const needle of [
  "data-testid=\"public-social-boundary-callout\"",
  "Posts, comments, reactions, reports, and group-scoped social activity are public-readable protocol records.",
  "Group membership can gate participation, not read visibility.",
  "Submission is not final until Transactions or backend tx status shows confirmation.",
  "Reaction submitted. Track confirmation in Transactions while the feed refreshes",
  "Report submitted. Track confirmation in Transactions while community review status refreshes",
  "txType: \"CONTENT_FLAG\"",
  "Reactions and reports submit signed transactions first.",
]) {
  assertIncludes(feedView, needle, "Feed public social readiness contract");
}

for (const needle of [
  "createdPostTxId",
  "data-testid=\"post-submission-status-links\"",
  "Track in Transactions",
  "Submission ≠ visibility",
  "signed post submission",
  "Track confirmation in Transactions",
  "Submitted",
]) {
  assertIncludes(createPost, needle, "Create Post lifecycle contract");
}

for (const needle of [
  "useTxQueue",
  "tx.runTx",
  "txPendingKey",
  "CONTENT_COMMENT_CREATE",
  "CONTENT_COMMENT_DELETE",
  "CONTENT_REACTION_SET",
  "CONTENT_FLAG",
  "data-testid=\"thread-public-social-boundary\"",
  "They become final only through the transaction lifecycle",
  "Reply submitted. Track confirmation in Transactions",
  "Reaction submitted. Track confirmation in Transactions",
  "Report submitted. Track confirmation in Transactions",
]) {
  assertIncludes(thread, needle, "Thread transaction lifecycle contract");
}

for (const needle of [
  "public-readable post",
  "Tracked by tx status",
  "submission progress first",
  "CONTENT_POST_EDIT",
  "CONTENT_POST_DELETE",
  "CONTENT_FLAG",
  "Track confirmation in Transactions",
]) {
  assertIncludes(content, needle, "Content detail transaction lifecycle contract");
}

for (const needle of [
  "# Public social flow readiness",
  "Group membership may gate participation, not read visibility.",
  "A button click, local form state, local validation, upload success, mempool acceptance, or browser toast is not final confirmation.",
  "Feed should show:",
  "Create Post should show:",
  "Thread should show:",
  "Ready for controlled internal/public-observer rehearsal candidate, with public beta readiness still blocked by explicit external evidence gates.",
]) {
  assertIncludes(socialDoc, needle, "Public social readiness doc");
}

assertIncludes(first15, "Public social flow readiness", "First 15 minutes doc must link public social readiness");
assertIncludes(packageJson, "test:public-social-flow-readiness-source", "package script must expose public social flow source check");

const checked = [feedView, createPost, thread, content, socialDoc, first15].join("\n");
for (const forbidden of [
  "Your reaction was saved",
  "Report sent.",
  "Report accepted.",
  "Saved with confirmation",
  "saved with confirmation",
  "created successfully and confirmed",
  "mempool accepted means confirmed",
  "member-only group read access is supported",
  "Public beta ready",
  "Mainnet ready",
  "public multi-validator BFT ready",
  "live economics ready",
  "automatic protocol upgrades enabled",
  "production helper execution ready",
  "legal approval granted",
]) {
  assertNotIncludes(checked, forbidden, "Public social surfaces must not overclaim or regress public-only safety");
}

const uiChecked = [feedView, createPost, thread, content].join("\n");
for (const forbidden of [
  "private protocol-native messaging",
  "private group read visibility",
  "member-only read access",
]) {
  assertNotIncludes(uiChecked, forbidden, "Public social UI must not expose private social semantics");
}

console.log("OK: public social flow readiness source checks passed");
