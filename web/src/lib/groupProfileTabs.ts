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
