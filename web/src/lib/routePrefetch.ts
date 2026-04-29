const routePrefetchers: Record<string, () => Promise<unknown>> = {
  "/login": () => import("../pages/LoginPage"),
  "/home": () => import("../pages/Home"),
  "/feed": () => import("../pages/Feed"),
  "/messages": () => import("../pages/Messaging"),
  "/profile": () => import("../pages/Account"),
  "/post": () => import("../pages/Post"),
  "/poh": () => import("../pages/Poh"),
  "/juror": () => import("../pages/JurorDashboard"),
  "/groups": () => import("../pages/Groups"),
  "/groups/create": () => import("../pages/GroupCreate"),
  "/groups/:id": () => import("../pages/Group"),
  "/proposals": () => import("../pages/Proposals"),
  "/proposals/create": () => import("../pages/ProposalCreate"),
  "/proposal/:id": () => import("../pages/Proposal"),
  "/proposals/:id": () => import("../pages/Proposal"),
  "/disputes": () => import("../pages/Disputes"),
  "/disputes/:id": () => import("../pages/DisputeDetail"),
  "/disputes/:id/review": () => import("../pages/DisputeReview"),
  "/tools": () => import("../pages/Tools"),
  "/settings": () => import("../pages/SettingsPage"),
  "/session": () => import("../pages/SessionDevicesPage"),
  "/transactions": () => import("../pages/TransactionsPage"),
  "/account/:account": () => import("../pages/Account"),
  "/content/:id": () => import("../pages/Content"),
  "/thread/:id": () => import("../pages/Thread"),
};

const warmedRoutes = new Set<string>();

export function prefetchRouteChunk(path: string): void {
  const normalized = String(path || "").trim();
  if (!normalized) return;
  const prefetch = routePrefetchers[normalized];
  if (!prefetch || warmedRoutes.has(normalized)) return;
  warmedRoutes.add(normalized);
  void prefetch().catch(() => {
    warmedRoutes.delete(normalized);
  });
}
