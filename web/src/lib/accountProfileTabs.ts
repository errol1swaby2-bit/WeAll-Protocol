/** Public profile display and owner-only workspaces are different presentation scopes. */
export const ACCOUNT_PROFILE_TABS = [
  { id: "posts", label: "Posts", ownerOnly: false },
  { id: "overview", label: "Account details", ownerOnly: false },
  { id: "reputation", label: "Trust & reputation", ownerOnly: false },
  { id: "eligibility", label: "Eligibility", ownerOnly: false },
  { id: "responsibilities", label: "Responsibilities", ownerOnly: true },
  { id: "node", label: "Node setup", ownerOnly: true },
  { id: "appearance", label: "Edit public profile", ownerOnly: true },
] as const;

export type AccountProfileTab = (typeof ACCOUNT_PROFILE_TABS)[number]["id"];

export function accountProfileTabFromHash(hash: string, isOwner: boolean): AccountProfileTab {
  const raw = String(hash || "");
  const pathname = raw.replace(/^#/, "").split("?")[0];
  if (pathname === "/me/profile-appearance") return isOwner ? "appearance" : "posts";
  const ix = raw.indexOf("?");
  const query = new URLSearchParams(ix < 0 ? "" : raw.slice(ix + 1));
  const requested = query.get("tab") || (query.get("operator") === "1" ? "node" : "posts");
  const tab = ACCOUNT_PROFILE_TABS.find((entry) => entry.id === requested);
  return tab && (!tab.ownerOnly || isOwner) ? tab.id : "posts";
}
