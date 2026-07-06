import fs from "node:fs";
import path from "node:path";

const root = path.resolve(import.meta.dirname, "..");
const read = (rel) => fs.readFileSync(path.join(root, rel), "utf8");

function assertIncludes(src, needle, label) {
  if (!src.includes(needle)) throw new Error(`${label}: missing ${needle}`);
}

function assertAnyIncludes(src, needles, label) {
  if (!needles.some((needle) => src.includes(needle))) {
    throw new Error(`${label}: missing one of ${needles.join(" | ")}`);
  }
}

function assertNotIncludes(src, needle, label) {
  if (src.includes(needle)) throw new Error(`${label}: unsafe/stale content remains: ${needle}`);
}

const router = read("src/lib/router.ts");
const account = read("src/pages/Account.tsx");
const verification = read("src/pages/AccountVerificationPage.tsx");
const liveRoom = read("src/pages/LiveVerificationRoom.tsx");
const createPost = read("src/pages/CreatePostPage.tsx");
const feed = read("src/components/FeedView.tsx");
const group = read("src/pages/Group.tsx");
const disputes = read("src/pages/DisputeReview.tsx");
const proposals = read("src/pages/Proposal.tsx");
const proposalsList = read("src/pages/Proposals.tsx");
const economics = read("src/pages/Economics.tsx");
const wallet = read("src/components/WalletPanel.tsx");
const node = read("src/pages/NodeDashboard.tsx");
const statusLib = read("src/lib/status.ts");
const protocolSummary = read("src/components/ProtocolStatusSummary.tsx");
const api = read("src/api/weall.ts");
const app = read("src/App.tsx");

const combined = [router, account, verification, liveRoom, createPost, feed, group, disputes, proposals, proposalsList, economics, wallet, node, statusLib, protocolSummary, api, app].join("\n");

// Account recovery / custody / profile reviewability.
assertAnyIncludes(account, ["needs recovery", "recovery secrets", "Account posture"], "account recovery/custody reviewer copy");
assertIncludes(account, "public profile", "account public profile copy");
assertIncludes(router, "Account Verification", "verification route metadata");

// Async and live PoH surfaces.
assertIncludes(verification, "native async human review", "native async PoH copy");
assertIncludes(verification, "Open live verification", "live PoH request copy");
assertIncludes(liveRoom, "live verification", "live verification room copy");
assertIncludes(api, "/v1/poh/live/tx/request", "live PoH API client route");
assertIncludes(api, "/v1/poh/async", "async PoH API client route family");

// Content posting / feed review.
assertIncludes(createPost, "Create", "create-post page");
assertIncludes(createPost, "public", "create-post public boundary");
assertIncludes(feed, "public", "feed public boundary");
assertIncludes(api, "/v1/feed", "feed API route");

// Public group read visibility with membership-gated participation.
assertIncludes(group, "membership", "group membership state");
assertIncludes(group, "public", "group public read boundary");
assertAnyIncludes(group, ["member-gated participation", "Membership can gate posting"], "group membership-gated participation copy");
assertIncludes(api, "private_groups_supported?: boolean", "API exposes private group unsupported flag");
assertIncludes(api, "member_only_read_supported?: boolean", "API exposes member-only-read unsupported flag");

// Dispute/review flow.
assertIncludes(disputes, "Review Center", "dispute review center copy");
assertIncludes(disputes, "DISPUTE_VOTE_SUBMIT", "dispute vote tx path");
assertIncludes(disputes, "final report-review choices", "dispute final choice boundary");
assertIncludes(api, "/v1/disputes/", "dispute API route family");

// Governance proposal/vote/status flow.
assertIncludes(proposalsList, "Decisions", "governance list route copy");
assertIncludes(proposals, "vote", "proposal vote copy");
assertIncludes(api, "/v1/gov/proposals", "governance proposal API route");
assertIncludes(api, "/votes", "governance votes API route");

// Locked wallet/economics status.
assertIncludes(wallet, "Genesis economics are locked", "wallet locked-economics copy");
assertIncludes(wallet, "read-only until the Genesis lock", "wallet read-only copy");
assertIncludes(economics, "locked", "economics locked copy");
assertIncludes(api, "/v1/economics/status", "economics status API route");
assertIncludes(api, "/v1/wallet/", "wallet status API route");

// Observer/public-testnet status copy.
assertIncludes(node, "Public observer testnet", "observer public-testnet panel");
assertIncludes(node, "observer experience", "observer readiness boundary copy");
assertIncludes(node, "does not replace", "frontend/operator evidence non-authority copy");
assertIncludes(statusLib, "crypto_profile", "frontend reads backend crypto profile status");
assertIncludes(protocolSummary, "Crypto profile", "observer UI exposes active crypto profile");
assertIncludes(combined, "pq-mldsa-v1", "frontend surfaces controlled-testnet PQ signature target");
assertIncludes(api, "/v1/observer/edge/status", "observer edge API route");

// No private/direct messaging active claim in reviewer-visible UI.
for (const stale of [
  'path: "/messages"',
  'href: "/messages"',
  "messageThreads(",
  "messageThread(",
  "DIRECT_MESSAGE_SEND",
  "DIRECT_MESSAGE_REDACT",
  "encrypted direct messages are supported",
  "private groups are supported",
  "member-only read access is supported",
]) {
  assertNotIncludes(combined, stale, "reviewer-visible private/direct messaging active claim");
}

console.log("OK: reviewer-critical frontend source checks passed");
