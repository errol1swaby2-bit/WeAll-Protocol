// projects/web/src/lib/feed.ts
//
// Backend-aligned feed utilities.
// This module is intentionally conservative:
// - The chain currently provides deterministic newest-first ordering.
// - "Top" / "Hot" are UI concepts for forward-compat (not implemented on-chain yet).
// - "Following" is not implemented on-chain yet.
// - Account feed is served by /v1/accounts/{account}/feed.
// - Group feed is served by /v1/groups/{group_id}/feed.
// - Public feed is served by /v1/feed.

export type FeedScope =
  | { kind: "public" }
  | { kind: "group"; groupId: string }
  | { kind: "account"; account: string }
  | { kind: "unknown" };

export type FeedSort = "new" | "top" | "hot";

export type FeedVisibility = "public" | "private" | "all";

export type FeedFilters = {
  visibility?: FeedVisibility;
  tags?: string; // comma-separated
  author?: string;
};

export type FeedRequest = {
  path: string;
  query: Record<string, string>;
};

function clampInt(n: number, lo: number, hi: number): number {
  if (!Number.isFinite(n)) return lo;
  return Math.max(lo, Math.min(hi, Math.floor(n)));
}

export function buildFeedRequest(args: {
  scope: FeedScope;
  limit?: number;
  cursor?: string | null;
  filters?: FeedFilters;
  sort?: FeedSort;
}): FeedRequest {
  const limit = clampInt(args.limit ?? 25, 1, 100);
  const cursor = (args.cursor ?? "").trim() || "";
  const filters = args.filters ?? {};

  // Sort is kept for UI; backend currently ignores it.
  // We DO NOT encode it into query params to avoid implying support.
  void args.sort;

  const q: Record<string, string> = { limit: String(limit) };
  if (cursor) q.cursor = cursor;

  const vis = (filters.visibility ?? "all").toLowerCase();
  if (vis === "public" || vis === "private") q.visibility = vis;

  if (filters.tags && filters.tags.trim()) q.tags = filters.tags.trim();
  if (filters.author && filters.author.trim()) q.author = filters.author.trim();

  if (args.scope.kind === "group") {
    const gid = encodeURIComponent(args.scope.groupId);
    return { path: `/v1/groups/${gid}/feed`, query: q };
  }

  if (args.scope.kind === "account") {
    const acct = encodeURIComponent(args.scope.account);
    // Account feed endpoint only supports visibility/cursor/limit.
    // Drop tags/author for account feed (author is implied).
    const q2: Record<string, string> = { limit: String(limit) };
    if (cursor) q2.cursor = cursor;
    if (vis === "public" || vis === "private") q2.visibility = vis;
    return { path: `/v1/accounts/${acct}/feed`, query: q2 };
  }

  if (args.scope.kind === "public") {
    // Public feed is simple; keep only limit/cursor if supported later.
    // (Current backend: GET /v1/feed, no paging contract guaranteed.)
    return { path: "/v1/feed", query: {} };
  }

  return { path: "/v1/feed", query: {} };
}

export function toQueryString(query: Record<string, string>): string {
  const usp = new URLSearchParams();
  for (const [k, v] of Object.entries(query)) {
    if (!v) continue;
    usp.set(k, v);
  }
  const qs = usp.toString();
  return qs ? `?${qs}` : "";
}
