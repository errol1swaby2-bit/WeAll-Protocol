// web/src/lib/router.ts
import { useEffect, useMemo, useState } from "react";

export type RouteMatch =
  | { path: "/home" }
  | { path: "/poh" }
  | { path: "/tools" }
  | { path: "/feed" }
  | { path: "/groups" }
  | { path: "/groups/:id"; id: string }
  | { path: "/proposals" }
  | { path: "/proposal/:id"; id: string }
  | { path: "/account/:account"; account: string }
  | { path: "/content/:id"; id: string }
  | { path: "/thread/:id"; id: string };

function normalizeHash(): string {
  const h = window.location.hash || "#/home";
  const s = h.startsWith("#") ? h.slice(1) : h;
  return s.startsWith("/") ? s : `/${s}`;
}

export function useRouteRaw(): string {
  const [route, setRoute] = useState<string>(normalizeHash());

  useEffect(() => {
    const onHash = () => setRoute(normalizeHash());
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  return route;
}

export function matchRoute(route: string): RouteMatch {
  const r = (route || "/home").split("?")[0];

  if (r === "/home" || r === "/") return { path: "/home" };
  if (r === "/poh") return { path: "/poh" };
  if (r === "/tools") return { path: "/tools" };
  if (r === "/feed") return { path: "/feed" };
  if (r === "/groups") return { path: "/groups" };
  if (r === "/proposals") return { path: "/proposals" };

  const parts = r.split("/").filter(Boolean);

  if (parts[0] === "groups" && parts[1]) return { path: "/groups/:id", id: decodeURIComponent(parts[1]) };
  if (parts[0] === "proposal" && parts[1]) return { path: "/proposal/:id", id: decodeURIComponent(parts[1]) };
  if (parts[0] === "account" && parts[1]) return { path: "/account/:account", account: decodeURIComponent(parts[1]) };
  if (parts[0] === "content" && parts[1]) return { path: "/content/:id", id: decodeURIComponent(parts[1]) };
  if (parts[0] === "thread" && parts[1]) return { path: "/thread/:id", id: decodeURIComponent(parts[1]) };

  return { path: "/home" };
}

export function useRoute(): RouteMatch {
  const raw = useRouteRaw();
  return useMemo(() => matchRoute(raw), [raw]);
}

export function nav(path: string) {
  const p = path.startsWith("#") ? path.slice(1) : path;
  window.location.hash = p.startsWith("/") ? `#${p}` : `#/${p}`;
}
