// projects/web/src/lib/feed.ts
// web/src/lib/feed.ts
// Production-grade feed utilities: normalization, filtering, sorting, and pagination helpers.

export type FeedScope =
  | { kind: "public" }
  | { kind: "following" }
  | { kind: "mine" }
  | { kind: "account"; account: string }
  | { kind: "group"; groupId: string }
  | { kind: "private"; account?: string | null };

export type FeedSort = "new" | "top" | "hot" | "oldest";

export type FeedFilters = {
  query: string;
  visibility: "all" | "public" | "private";
  author: string; // optional; when set, match item author exactly
  tags: string; // comma-separated, OR semantics (matches backend tag filter)
};

export const DEFAULT_PAGE_SIZE = 25;
export const MAX_PAGE_SIZE = 100;

function asStr(x: any): string {
  return typeof x === "string" ? x : x == null ? "" : String(x);
}

function asNum(x: any, d = 0): number {
  const n = Number(x);
  return Number.isFinite(n) ? n : d;
}

export function getItemId(it: any): string {
  return asStr(it?.id) || asStr(it?.post_id) || asStr(it?.comment_id) || asStr(it?.content_id) || "";
}

// The backend feed sorts by created_at_nonce desc then content_id desc.
// We tolerate multiple field names to support evolving state shapes.
export function getItemCreatedNonce(it: any): number {
  return (
    asNum(it?.created_at_nonce, 0) ||
    asNum(it?.created_nonce, 0) ||
    asNum(it?.createdAtNonce, 0) ||
    asNum(it?.nonce, 0) ||
    0
  );
}

export function getItemAuthor(it: any): string {
  return asStr(it?.author) || asStr(it?.by) || asStr(it?.signer) || asStr(it?.account) || "";
}

export function getItemVisibility(it: any): "public" | "private" | "unknown" {
  const v = asStr(it?.visibility || it?.audience || it?.scope).toLowerCase();
  if (!v) return "unknown";
  if (v === "public") return "public";
  if (v === "private") return "private";
  // tolerate future values (e.g., "group", "followers")
  return "unknown";
}

export function parseTags(x: any): string[] {
  if (Array.isArray(x)) return x.map((t) => asStr(t).trim()).filter(Boolean);
  const s = asStr(x).trim();
  if (!s) return [];
  return s
    .split(",")
    .map((t) => t.trim())
    .filter(Boolean);
}

export function getItemTags(it: any): string[] {
  return parseTags(it?.tags || it?.tag || it?.labels || it?.topics);
}

export function guessItemGroupIds(it: any): string[] {
  // Best-effort group classification.
  // Supports:
  //  - explicit group_id fields
  //  - tags like "group:<id>" or "g:<id>" or "group/<id>"
  const out: string[] = [];

  const direct = asStr(it?.group_id || it?.groupId || "").trim();
  if (direct) out.push(direct);

  const tags = getItemTags(it);
  for (const t of tags) {
    const tt = t.trim();
    if (!tt) continue;
    const low = tt.toLowerCase();
    if (low.startsWith("group:")) out.push(tt.slice(6));
    else if (low.startsWith("g:")) out.push(tt.slice(2));
    else if (low.startsWith("group/")) out.push(tt.slice(6));
  }

  return Array.from(new Set(out.map((x) => x.trim()).filter(Boolean)));
}

export function itemMatchesQuery(it: any, query: string): boolean {
  const q = asStr(query).trim().toLowerCase();
  if (!q) return true;

  const id = getItemId(it).toLowerCase();
  const author = getItemAuthor(it).toLowerCase();
  const title = asStr(it?.title || it?.caption || "").toLowerCase();
  const body = asStr(it?.body || it?.text || "").toLowerCase();
  const tags = getItemTags(it).join(",").toLowerCase();

  return id.includes(q) || author.includes(q) || title.includes(q) || body.includes(q) || tags.includes(q);
}

export function itemMatchesVisibility(it: any, vis: FeedFilters["visibility"]): boolean {
  if (vis === "all") return true;
  const v = getItemVisibility(it);
  if (vis === "public") return v === "public";
  if (vis === "private") return v === "private";
  return true;
}

export function itemMatchesAuthor(it: any, author: string): boolean {
  const a = asStr(author).trim();
  if (!a) return true;
  return getItemAuthor(it) === a;
}

export function itemMatchesTags(it: any, tagsCsv: string): boolean {
  const tags = parseTags(tagsCsv).map((t) => t.toLowerCase());
  if (!tags.length) return true;

  const itemTags = getItemTags(it).map((t) => t.toLowerCase());
  if (!itemTags.length) return false;

  // OR semantics: match if ANY requested tag is present
  for (const t of tags) {
    if (itemTags.includes(t)) return true;
  }
  return false;
}

export function filterItems(items: any[], filters: FeedFilters): any[] {
  const out: any[] = [];
  for (const it of items || []) {
    if (!itemMatchesQuery(it, filters.query)) continue;
    if (!itemMatchesVisibility(it, filters.visibility)) continue;
    if (!itemMatchesAuthor(it, filters.author)) continue;
    if (!itemMatchesTags(it, filters.tags)) continue;
    out.push(it);
  }
  return out;
}

export function sortItems(items: any[], sort: FeedSort): any[] {
  const out = [...(items || [])];

  if (sort === "oldest") {
    out.sort((a, b) => {
      const na = getItemCreatedNonce(a);
      const nb = getItemCreatedNonce(b);
      if (na !== nb) return na - nb;
      const ia = getItemId(a);
      const ib = getItemId(b);
      return ia.localeCompare(ib);
    });
    return out;
  }

  if (sort === "top") {
    out.sort((a, b) => {
      const sa = Number(a?.reaction_count || 0) + 0.5 * Number(a?.comment_count || 0);
      const sb = Number(b?.reaction_count || 0) + 0.5 * Number(b?.comment_count || 0);
      if (sa !== sb) return sb - sa;
      const na = getItemCreatedNonce(a);
      const nb = getItemCreatedNonce(b);
      if (na !== nb) return nb - na;
      return getItemId(b).localeCompare(getItemId(a));
    });
    return out;
  }

  if (sort === "hot") {
    // If server provided hot ordering, preserve it.
    // Otherwise fall back to top.
    return sortItems(out, "top");
  }

  // "new" (default) matches backend newest
  out.sort((a, b) => {
    const na = getItemCreatedNonce(a);
    const nb = getItemCreatedNonce(b);
    if (na !== nb) return nb - na;
    const ia = getItemId(a);
    const ib = getItemId(b);
    return ib.localeCompare(ia);
  });
  return out;
}

export function dedupeById(items: any[]): any[] {
  const seen = new Set<string>();
  const out: any[] = [];
  for (const it of items) {
    const id = getItemId(it) || JSON.stringify(it);
    if (seen.has(id)) continue;
    seen.add(id);
    out.push(it);
  }
  return out;
}

export function makeFeedCacheKey(args: { base: string; scope: FeedScope; filters: FeedFilters; sort: FeedSort }): string {
  const s =
    args.scope.kind === "public"
      ? "public"
      : args.scope.kind === "following"
        ? "following"
        : args.scope.kind === "mine"
          ? "mine"
          : args.scope.kind === "account"
            ? `account:${args.scope.account}`
            : args.scope.kind === "group"
              ? `group:${args.scope.groupId}`
              : `private:${args.scope.account || ""}`;
  const f = `${args.filters.query}|${args.filters.visibility}|${args.filters.author}|${args.filters.tags}`;
  return `weall.feed.cache::${args.base}::${s}::${args.sort}::${f}`;
}

export function loadFeedCache(key: string): { items: any[]; nextCursor: string | null; tsMs: number } | null {
  try {
    const raw = sessionStorage.getItem(key);
    if (!raw) return null;
    const obj = JSON.parse(raw);
    if (!obj || typeof obj !== "object") return null;
    const items = Array.isArray(obj.items) ? obj.items : [];
    const nextCursor = obj.nextCursor == null ? null : String(obj.nextCursor);
    const tsMs = Number(obj.tsMs || 0);
    return { items, nextCursor, tsMs };
  } catch {
    return null;
  }
}

export function saveFeedCache(key: string, items: any[], nextCursor: string | null): void {
  try {
    const payload = {
      items: items.slice(0, 500), // cap to avoid blowing up sessionStorage
      nextCursor,
      tsMs: Date.now(),
    };
    sessionStorage.setItem(key, JSON.stringify(payload));
  } catch {
    // ignore
  }
}

export function isFeedCacheFresh(tsMs: number, ttlMs: number): boolean {
  if (!tsMs) return false;
  const now = Date.now();
  return now - tsMs <= ttlMs;
}
