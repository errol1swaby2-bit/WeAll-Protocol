/**
 * Group sections share one canonical group ID. Query tabs are presentation
 * only: backend membership, governance and signer checks remain authoritative.
 */
export const GROUP_PROFILE_TABS = [
  { id: "posts", label: "Posts" },
  { id: "about", label: "About" },
  { id: "members", label: "Members" },
  { id: "decisions", label: "Decisions" },
  { id: "governance", label: "Governance" },
  { id: "treasury", label: "Treasury" },
  { id: "reports", label: "Reports" },
  { id: "responsibilities", label: "Responsibilities" },
  { id: "emissaries", label: "Emissaries" },
] as const;

export type GroupProfileTab = (typeof GROUP_PROFILE_TABS)[number]["id"];

export function groupProfileTabFromHash(hash: string): GroupProfileTab {
  const marker = String(hash || "").indexOf("?");
  const query = marker >= 0 ? hash.slice(marker + 1) : "";
  const requested = new URLSearchParams(query).get("tab") || "posts";
  const tab = GROUP_PROFILE_TABS.find((candidate) => candidate.id === requested);
  return tab ? tab.id : "posts";
}

// Group role work is not a public profile tab. The review desk is deliberately
// reachable only by an explicit deep link; its actions remain backend-gated.
export type GroupWorkspaceTab = GroupProfileTab | "membership_review" | "moderation_review" | "emissary_work" | "elections" | "election_detail";

export function groupWorkspaceTabFromHash(hash: string): GroupWorkspaceTab {
  const path = String(hash || "").replace(/^#/, "").split("?")[0];
  if (/^\/groups\/[^/]+\/manage\/members$/.test(path)) return "membership_review";
  if (/^\/groups\/[^/]+\/manage\/moderation$/.test(path)) return "moderation_review";
  if (/^\/groups\/[^/]+\/emissaries\/work$/.test(path)) return "emissary_work";
  if (/^\/groups\/[^/]+\/emissaries\/elections\/[^/]+$/.test(path)) return "election_detail";
  if (/^\/groups\/[^/]+\/emissaries\/elections$/.test(path)) return "elections";
  if (/^\/groups\/[^/]+\/reports$/.test(path)) return "reports";
  if (/^\/groups\/[^/]+\/responsibilities$/.test(path)) return "responsibilities";
  return groupProfileTabFromHash(hash);
}

/** IDs in deep links are presentation context, not proof of an election record. */
export function groupElectionIdFromHash(hash: string): string {
  const path = String(hash || "").replace(/^#/, "").split("?")[0];
  const match = /^\/groups\/[^/]+\/emissaries\/elections\/([^/]+)$/.exec(path);
  if (!match) return "";
  try { return decodeURIComponent(match[1]); } catch { return ""; }
}
