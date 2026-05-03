const routePrefetchers: Record<string, () => Promise<unknown>> = {
  "/login": () => import("../pages/LoginPage"),
  "/home": () => import("../pages/Home"),
  "/feed": () => import("../pages/Feed"),
  "/messages": () => import("../pages/Messaging"),
  "/profile": () => import("../pages/Account"),
  "/create": () => import("../pages/Post"),
  "/post": () => import("../pages/Post"),
  "/post/:id": () => import("../pages/Content"),
  "/verification": () => import("../pages/Poh"),
  "/poh": () => import("../pages/Poh"),
  "/reviews": () => import("../pages/JurorDashboard"),
  "/reviews/:id": () => import("../pages/DisputeReview"),
  "/juror": () => import("../pages/JurorDashboard"),
  "/groups": () => import("../pages/Groups"),
  "/groups/create": () => import("../pages/GroupCreate"),
  "/groups/:id": () => import("../pages/Group"),
  "/decisions": () => import("../pages/Proposals"),
  "/decisions/create": () => import("../pages/ProposalCreate"),
  "/decisions/:id": () => import("../pages/Proposal"),
  "/proposals": () => import("../pages/Proposals"),
  "/proposals/create": () => import("../pages/ProposalCreate"),
  "/proposal/:id": () => import("../pages/Proposal"),
  "/proposals/:id": () => import("../pages/Proposal"),
  "/reports": () => import("../pages/Disputes"),
  "/reports/:id": () => import("../pages/DisputeDetail"),
  "/disputes": () => import("../pages/Disputes"),
  "/disputes/:id": () => import("../pages/DisputeDetail"),
  "/disputes/:id/review": () => import("../pages/DisputeReview"),
  "/advanced": () => import("../pages/Tools"),
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
