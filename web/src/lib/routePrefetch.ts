const routePrefetchers: Record<string, () => Promise<unknown>> = {
  "/login": () => import("../pages/LoginPage"),
  "/home": () => import("../pages/HomeDashboard"),
  "/feed": () => import("../pages/Feed"),
  "/messages": () => import("../pages/Messaging"),
  "/profile": () => import("../pages/Account"),
  "/create": () => import("../pages/Post"),
  "/post/:id": () => import("../pages/Content"),
  "/verification": () => import("../pages/PohPage"),
  "/reviews": () => import("../pages/JurorDashboard"),
  "/reviews/:id": () => import("../pages/DisputeReview"),
  "/groups": () => import("../pages/Groups"),
  "/groups/create": () => import("../pages/GroupCreate"),
  "/groups/:id": () => import("../pages/Group"),
  "/decisions": () => import("../pages/Proposals"),
  "/decisions/create": () => import("../pages/ProposalCreate"),
  "/decisions/:id": () => import("../pages/Proposal"),
  "/reports": () => import("../pages/Disputes"),
  "/reports/:id": () => import("../pages/DisputeDetail"),
  "/advanced": () => import("../pages/Tools"),
  "/settings": () => import("../pages/SettingsPage"),
  "/session": () => import("../pages/SessionDevicesPage"),
  "/transactions": () => import("../pages/TransactionsPage"),
  "/economics": () => import("../pages/Economics"),
  "/node": () => import("../pages/NodeDashboard"),
  "/account/:account": () => import("../pages/Account"),
  "/content/:id": () => import("../pages/Content"),
  "/thread/:id": () => import("../pages/Thread"),
};

const warmedRoutes = new Set<string>();

function stripQueryAndHash(path: string): string {
  return path.split("?")[0]?.split("#")[0] || "";
}

function routePatternForPath(path: string): string {
  const normalized = stripQueryAndHash(String(path || "").trim()).replace(/\/+$/, "") || "/home";
  if (routePrefetchers[normalized]) return normalized;
  for (const pattern of Object.keys(routePrefetchers)) {
    if (!pattern.includes(":")) continue;
    const patternParts = pattern.split("/").filter(Boolean);
    const pathParts = normalized.split("/").filter(Boolean);
    if (patternParts.length !== pathParts.length) continue;
    const matched = patternParts.every((part, index) => part.startsWith(":") || part === pathParts[index]);
    if (matched) return pattern;
  }
  return normalized;
}

export function prefetchRouteChunk(path: string): void {
  const routeKey = routePatternForPath(path);
  if (!routeKey) return;
  const prefetch = routePrefetchers[routeKey];
  if (!prefetch || warmedRoutes.has(routeKey)) return;
  warmedRoutes.add(routeKey);
  void prefetch().catch(() => {
    warmedRoutes.delete(routeKey);
  });
}
