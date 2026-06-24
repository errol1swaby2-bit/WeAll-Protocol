// projects/web/src/lib/feed.ts
//
// Backend-aligned feed utilities.
// This module is intentionally conservative:
// - The chain reports its deterministic ranking mode in the feed response.
// - The default public view remains honest as latest protocol activity; no personalization is claimed.
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

export type FeedVisibility = "public" | "group" | "all";

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

  const q: Record<string, string> = { limit: String(limit) };

  // Sort is explicit. The backend reports the accepted deterministic ranking mode in the response.
  // Do not call this personalized; it is a backend-selected public ranking mode.
  if (args.sort === "top") q.ranking = "production";
  else if (args.sort === "hot") q.ranking = "balanced";
  if (cursor) q.cursor = cursor;

  const vis = (filters.visibility ?? "all").toLowerCase();
  if (vis === "public" || vis === "group") q.visibility = vis;

  if (filters.tags && filters.tags.trim()) q.tags = filters.tags.trim();
  if (filters.author && filters.author.trim()) q.author = filters.author.trim();

  if (args.scope.kind === "group") {
    const gid = encodeURIComponent(args.scope.groupId);
    return { path: `/v1/groups/${gid}/feed`, query: q };
  }

  if (args.scope.kind === "account") {
    const acct = encodeURIComponent(args.scope.account);
    // Account feed endpoint only supports public-only visibility/cursor/limit.
    // Drop tags/author for account feed (author is implied).
    const q2: Record<string, string> = { limit: String(limit) };
    if (cursor) q2.cursor = cursor;
    if (vis === "public") q2.visibility = vis;
    return { path: `/v1/accounts/${acct}/feed`, query: q2 };
  }

  if (args.scope.kind === "public") {
    return { path: "/v1/feed", query: q };
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

export const FEED_ALGORITHM_SUMMARY = "Current feed behavior is deterministic protocol activity from backend public-only visibility-filtered feed endpoints. The response reports the ranking mode used. It is not a personalized recommendation algorithm.";

export const FEED_PUBLIC_BETA_BLOCKER = "Personalized or reputation-weighted recommendation ranking remains a future/public-beta blocker until implemented by backend truth sources and tests.";
