/** Each reviewer queue is a distinct URL, not an authority grant.
 * Legacy /reviews?lane=... remains navigable for old links.
 */
export const REVIEWER_WORKSPACES = [
  { id: "overview", label: "Overview", href: "/tasks" },
  { id: "content_review", label: "Content review", href: "/tasks/content" },
  { id: "dispute_review", label: "Dispute juries", href: "/tasks/disputes" },
  { id: "poh_async_review", label: "Async PoH", href: "/tasks/poh-async" },
  { id: "poh_live_review", label: "Live PoH", href: "/tasks/poh-live" },
  { id: "reported", label: "My reports", href: "/tasks?lane=reported" },
] as const;

export type ReviewerWorkspace = (typeof REVIEWER_WORKSPACES)[number]["id"];

export function reviewerWorkspaceFromHash(hash: string): ReviewerWorkspace {
  const raw = String(hash || "").replace(/^#/, "");
  const question = raw.indexOf("?");
  const path = question >= 0 ? raw.slice(0, question) : raw;
  const params = new URLSearchParams(question >= 0 ? raw.slice(question + 1) : "");
  const matched = REVIEWER_WORKSPACES.find((item) => item.href.split("?")[0] === path && path !== "/tasks");
  if (matched) return matched.id;
  const legacyLane = params.get("lane");
  return REVIEWER_WORKSPACES.find((item) => item.id === legacyLane)?.id || "overview";
}
