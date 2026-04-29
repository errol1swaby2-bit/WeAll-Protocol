import { weall } from "../api/weall";
import { confirmed, firstReconcile, submitted, type ReconcileResult } from "./revalidation";

type ReconcilePostVisibleArgs = {
  postId: string;
  account?: string;
  body?: string | null;
  groupId?: string | null;
  base: string;
};

function bodyMatches(candidate: any, expectedBody: string): boolean {
  if (!expectedBody) return true;
  const body = String(candidate?.body || candidate?.text || "").trim();
  return body === expectedBody;
}

function accountMatches(candidate: any, expectedAccount: string): boolean {
  if (!expectedAccount) return true;
  const needle = String(expectedAccount || "").trim().toLowerCase();
  return [candidate?.author, candidate?.account, candidate?.account_id]
    .map((value) => String(value || "").trim().toLowerCase())
    .some((value) => value === needle);
}

function idMatches(candidate: any, postId: string): boolean {
  const needle = String(postId || "").trim();
  if (!needle) return false;
  return [candidate?.post_id, candidate?.id, candidate?.content_id, candidate?.cid, candidate?.tx_id]
    .map((value) => String(value || "").trim())
    .some((value) => value === needle);
}

export async function reconcilePostVisible(args: ReconcilePostVisibleArgs): Promise<ReconcileResult | null> {
  const postId = String(args.postId || "").trim();
  const expectedBody = String(args.body || "").trim();
  const account = String(args.account || "").trim();
  const groupId = String(args.groupId || "").trim();
  if (!postId) return null;

  return firstReconcile(
    async () => {
      try {
        const raw: any = await weall.content(postId, args.base);
        const content = raw?.content || raw || null;
        if (content && idMatches(content, postId) && bodyMatches(content, expectedBody) && accountMatches(content, account)) {
          return confirmed(`Post ${postId} is visible on the canonical content surface.`);
        }
        if (content && idMatches(content, postId)) {
          return submitted(`Post ${postId} exists, but the latest rendered body is still settling.`);
        }
      } catch {
        // ignore and fall back to feed scans
      }
      return null;
    },
    async () => {
      try {
        const feed: any = groupId
          ? await weall.groupFeed(groupId, { limit: 80 }, args.base)
          : account
            ? await weall.accountFeed(account, { limit: 80 }, args.base)
            : await weall.feed({ limit: 80 }, args.base);
        const items = Array.isArray(feed?.items) ? feed.items : [];
        const matched = items.find((item: any) => idMatches(item, postId));
        if (matched && bodyMatches(matched, expectedBody) && accountMatches(matched, account)) {
          return confirmed(
            groupId
              ? `Post ${postId} is visible in the ${groupId} group feed.`
              : account
                ? `Post ${postId} is visible in the account feed.`
                : `Post ${postId} is visible in the main feed.`,
          );
        }
        if (matched) {
          return submitted(`Post ${postId} is listed, but the rendered feed item is still catching up.`);
        }
      } catch {
        // ignore
      }
      return null;
    },
  );
}
