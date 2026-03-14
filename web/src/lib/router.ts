export type RouteMatch =
  | { path: "/login" }
  | { path: "/home" }
  | { path: "/post" }
  | { path: "/poh" }
  | { path: "/juror" }
  | { path: "/tools" }
  | { path: "/feed" }
  | { path: "/groups" }
  | { path: "/groups/:id"; id: string }
  | { path: "/proposals" }
  | { path: "/proposal/:id"; id: string }
  | { path: "/settings" }
  | { path: "/account/:account"; account: string }
  | { path: "/content/:id"; id: string }
  | { path: "/thread/:id"; id: string };

function decodeRoutePart(value: string): string {
  const raw = String(value || "").trim();
  if (!raw) return "";
  try {
    return decodeURIComponent(raw);
  } catch {
    return raw;
  }
}

export function matchRoute(path: string): RouteMatch {
  const r = path.split("?")[0];

  if (r === "/" || r === "/login") return { path: "/login" };
  if (r === "/home") return { path: "/home" };
  if (r === "/post") return { path: "/post" };
  if (r === "/poh") return { path: "/poh" };
  if (r === "/juror") return { path: "/juror" };
  if (r === "/tools") return { path: "/tools" };
  if (r === "/feed") return { path: "/feed" };
  if (r === "/groups") return { path: "/groups" };
  if (r === "/proposals") return { path: "/proposals" };
  if (r === "/settings") return { path: "/settings" };

  if (r.startsWith("/groups/")) {
    const id = decodeRoutePart(r.slice("/groups/".length));
    if (id) return { path: "/groups/:id", id };
  }

  if (r.startsWith("/proposal/")) {
    const id = decodeRoutePart(r.slice("/proposal/".length));
    if (id) return { path: "/proposal/:id", id };
  }

  if (r.startsWith("/account/")) {
    const account = decodeRoutePart(r.slice("/account/".length));
    if (account) return { path: "/account/:account", account };
  }

  if (r.startsWith("/content/")) {
    const id = decodeRoutePart(r.slice("/content/".length));
    if (id) return { path: "/content/:id", id };
  }

  if (r.startsWith("/thread/")) {
    const id = decodeRoutePart(r.slice("/thread/".length));
    if (id) return { path: "/thread/:id", id };
  }

  return { path: "/login" };
}

export function nav(path: string): void {
  const p = path.startsWith("/") ? path : `/${path}`;
  window.location.hash = `#${p}`;
}
