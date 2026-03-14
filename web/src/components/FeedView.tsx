import React, { useEffect, useMemo, useState } from "react";

import { weall } from "../api/weall";
import { getAuthHeaders, getKeypair, getSession, submitSignedTx } from "../auth/session";
import { normalizeAccount } from "../auth/keys";
import { checkGates, summarizeAccountState } from "../lib/gates";
import { nav } from "../lib/router";
import MediaGallery from "./MediaGallery";

type FeedScope =
  | { kind: "public" }
  | { kind: "group"; groupId: string }
  | { kind: "account"; account: string }
  | { kind: "unknown" };

type FeedFilters = {
  visibility?: "all" | "public" | "private";
  tags?: string;
  author?: string;
};

function uniqById(items: any[]): any[] {
  const seen = new Set<string>();
  const out: any[] = [];
  for (const it of items) {
    const id = String(it?.id || it?.post_id || it?.comment_id || "");
    if (!id) {
      out.push(it);
      continue;
    }
    if (seen.has(id)) continue;
    seen.add(id);
    out.push(it);
  }
  return out;
}

function prettyMsg(e: any): string {
  const d = e?.data || e?.body || null;
  return d?.message || e?.message || "error";
}

function asArray<T = any>(v: any): T[] {
  return Array.isArray(v) ? v : [];
}

function itemId(it: any): string {
  return String(it?.post_id || it?.comment_id || it?.id || "");
}

function itemAuthor(it: any): string {
  return String(it?.author || it?.signer || it?.account || "");
}

function itemBody(it: any): string {
  return String(it?.body || it?.text || "");
}

function itemTags(it: any): string[] {
  return asArray<string>(it?.tags).map((x) => String(x));
}

function itemMedia(it: any): any[] {
  return asArray<any>(it?.media);
}

function itemVisibility(it: any): string {
  return String(it?.visibility || "public");
}

function itemNonce(it: any): string {
  const n = it?.created_nonce ?? it?.created_at_nonce;
  if (n === undefined || n === null) return "";
  return String(n);
}

function itemCreatedLabel(it: any): string {
  const nonce = itemNonce(it);
  if (nonce) return `nonce ${nonce}`;
  return "pending metadata";
}

function reactionCount(it: any, key: string): number {
  const reactions = it?.reactions;
  if (!reactions || typeof reactions !== "object") return 0;
  const raw = reactions[key];
  return Number.isFinite(Number(raw)) ? Number(raw) : 0;
}

function scopeLabel(scope: FeedScope): string {
  if (scope?.kind === "group") return `Group · ${scope.groupId}`;
  if (scope?.kind === "account") return `Account · ${scope.account}`;
  if (scope?.kind === "public") return "Public";
  return "Feed";
}

export default function FeedView({
  base,
  scope,
  title,
  defaultSort = "new",
  defaultFilters = { visibility: "all" } as FeedFilters,
  pageSize = 25,
}: {
  base: string;
  scope: FeedScope;
  title?: string;
  defaultSort?: "new" | "top" | "hot";
  defaultFilters?: FeedFilters;
  pageSize?: number;
}): JSX.Element {
  const [items, setItems] = useState<any[]>([]);
  const [sort, setSort] = useState<"new" | "top" | "hot">(defaultSort);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [nextCursor, setNextCursor] = useState<string | null>(null);

  const session = getSession();
  const viewer = session ? normalizeAccount(session.account) : null;
  const kp = viewer ? getKeypair(viewer) : null;
  const canSign = !!kp?.secretKeyB64;
  const [viewerState, setViewerState] = useState<any | null>(null);

  const [likeBusyId, setLikeBusyId] = useState<string | null>(null);
  const [likeErr, setLikeErr] = useState<string | null>(null);

  const [flagBusyId, setFlagBusyId] = useState<string | null>(null);
  const [flagErr, setFlagErr] = useState<string | null>(null);

  const filters = useMemo(() => {
    return {
      visibility: defaultFilters?.visibility ?? "all",
      tags: defaultFilters?.tags,
      author: defaultFilters?.author,
    } as FeedFilters;
  }, [defaultFilters]);

  const sortNote =
    sort === "new" ? null : "Top and Hot are reserved for future ranking logic. This view currently stays newest-first.";

  const headerTitle =
    title ||
    (scope?.kind === "group"
      ? "Group feed"
      : scope?.kind === "account"
        ? "Account feed"
        : "Public feed");

  const gateTier2 = checkGates({
    loggedIn: !!viewer,
    canSign,
    accountState: viewerState,
    requireTier: 2,
  });

  const viewerSummary = viewerState ? summarizeAccountState(viewerState) : "(state unknown)";

  async function refreshViewerState() {
    if (!viewer) {
      setViewerState(null);
      return;
    }
    try {
      const r: any = await weall.account(viewer, base);
      setViewerState(r?.state ?? null);
    } catch {
      setViewerState(null);
    }
  }

  async function loadPage(opts?: { cursor?: string | null; append?: boolean }) {
    setErr(null);
    setLoading(true);

    try {
      const headers = getAuthHeaders();
      const cursor = opts?.cursor ?? null;
      const append = Boolean(opts?.append);
      const limit = pageSize;

      let r: any;
      if (scope?.kind === "group") {
        r = await weall.groupFeed(
          scope.groupId,
          {
            limit,
            cursor,
            visibility: filters.visibility && filters.visibility !== "all" ? filters.visibility : undefined,
            tags: filters.tags,
            author: filters.author,
          },
          base,
          headers,
        );
      } else if (scope?.kind === "account") {
        r = await weall.accountFeed(
          scope.account,
          {
            limit,
            cursor,
            visibility: filters.visibility && filters.visibility !== "all" ? filters.visibility : undefined,
          },
          base,
          headers,
        );
      } else {
        r = await weall.feed(
          {
            limit,
            cursor,
            visibility: filters.visibility && filters.visibility !== "all" ? filters.visibility : undefined,
            tags: filters.tags,
            author: filters.author,
          },
          base,
          headers,
        );
      }

      const pageItems = Array.isArray(r?.items) ? r.items : [];
      const nc = r?.next_cursor ? String(r.next_cursor) : null;

      if (append) {
        setItems((prev) => uniqById([...prev, ...pageItems]));
      } else {
        setItems(pageItems);
      }
      setNextCursor(nc);
    } catch (e: any) {
      setErr(prettyMsg(e));
      if (!opts?.append) setItems([]);
      setNextCursor(null);
    } finally {
      setLoading(false);
    }
  }

  function refresh() {
    setNextCursor(null);
    loadPage({ cursor: null, append: false });
  }

  function loadMore() {
    if (!nextCursor) return;
    loadPage({ cursor: nextCursor, append: true });
  }

  useEffect(() => {
    refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scope?.kind, (scope as any)?.groupId, (scope as any)?.account, filters.visibility, filters.tags, filters.author, sort]);

  useEffect(() => {
    refreshViewerState();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [viewer]);

  async function doLike(targetId: string) {
    setLikeErr(null);
    if (!viewer) return setLikeErr("Not logged in.");
    if (!gateTier2.ok) return setLikeErr(gateTier2.reason || `Gated (${viewerSummary}).`);

    setLikeBusyId(String(targetId));
    try {
      await submitSignedTx({
        account: viewer,
        tx_type: "CONTENT_REACTION_SET",
        payload: { target_id: String(targetId), reaction: "like" },
        parent: null,
        base,
      });
      await loadPage({ cursor: null, append: false });
    } catch (e: any) {
      setLikeErr(prettyMsg(e));
    } finally {
      setLikeBusyId(null);
    }
  }

  async function doFlag(targetId: string) {
    setFlagErr(null);
    if (!viewer) return setFlagErr("Not logged in.");
    if (!gateTier2.ok) return setFlagErr(gateTier2.reason || `Gated (${viewerSummary}).`);

    const reasonRaw = window.prompt("Flag reason (optional)", "");
    if (reasonRaw === null) return;
    const reason = String(reasonRaw || "").trim();

    setFlagBusyId(String(targetId));
    try {
      await submitSignedTx({
        account: viewer,
        tx_type: "CONTENT_FLAG_SET",
        payload: { target_id: String(targetId), reason: reason || null },
        parent: null,
        base,
      });
      await loadPage({ cursor: null, append: false });
    } catch (e: any) {
      setFlagErr(prettyMsg(e));
    } finally {
      setFlagBusyId(null);
    }
  }

  const emptyTitle =
    scope?.kind === "group"
      ? "No group posts yet"
      : scope?.kind === "account"
        ? "No posts for this account yet"
        : "Nothing here yet";

  const emptyNote =
    scope?.kind === "group"
      ? "This group feed has not received visible posts yet. Once members publish here, they will appear newest-first."
      : scope?.kind === "account"
        ? "This account does not have visible posts in the selected view yet."
        : "This feed is empty for now. Once activity starts landing on-chain, posts will appear here newest-first.";

  return (
    <div className="pageStack">
      <section className="card">
        <div className="cardBody formStack">
          <div className="sectionHead">
            <div>
              <div className="eyebrow">{scopeLabel(scope)}</div>
              <h2 className="cardTitle">{headerTitle}</h2>
            </div>
            <div className="statusSummary">
              <button className="btn" onClick={refresh} disabled={loading}>
                {loading ? "Refreshing…" : "Refresh"}
              </button>
            </div>
          </div>

          <div className="grid2 formGrid">
            <label className="fieldLabel">
              Sort
              <select value={sort} onChange={(e) => setSort(e.target.value as "new" | "top" | "hot")}>
                <option value="new">Newest</option>
                <option value="top">Top</option>
                <option value="hot">Hot</option>
              </select>
            </label>

            <div className="fieldLabel">
              Participation
              <div className="statusSummary">
                <span className={`statusPill ${gateTier2.ok ? "ok" : ""}`}>
                  {gateTier2.ok ? "Tier 2 actions unlocked" : "Tier 2 required"}
                </span>
                {viewer ? <span className="statusPill mono">{viewer}</span> : <span className="statusPill">Read-only</span>}
              </div>
            </div>
          </div>

          {sortNote ? <div className="inlineError">{sortNote}</div> : null}
          {err ? <div className="inlineError">{err}</div> : null}
          {likeErr ? <div className="inlineError">{likeErr}</div> : null}
          {flagErr ? <div className="inlineError">{flagErr}</div> : null}
        </div>
      </section>

      <section className="pageStack">
        {items.length === 0 && !loading ? (
          <div className="card">
            <div className="cardBody formStack">
              <div>
                <div className="eyebrow">Empty state</div>
                <h3 className="cardTitle">{emptyTitle}</h3>
                <p className="cardDesc">{emptyNote}</p>
              </div>
              <div className="buttonRow buttonRowWide">
                <button className="btn" onClick={() => nav("/groups")}>Browse groups</button>
                <button className="btn" onClick={() => nav("/proposals")}>Open governance</button>
                <button className="btn btnPrimary" onClick={() => nav("/post")}>Create post</button>
              </div>
            </div>
          </div>
        ) : null}

        {items.map((it, index) => {
          const id = itemId(it);
          const author = itemAuthor(it);
          const body = itemBody(it);
          const tags = itemTags(it);
          const media = itemMedia(it);
          const visibility = itemVisibility(it);
          const likeCount = reactionCount(it, "like");

          return (
            <article key={id || `feed-item-${index}`} className="card">
              <div className="cardBody formStack">
                <div className="sectionHead">
                  <div>
                    <div className="statusSummary">
                      <button className="btn" onClick={() => nav(`/account/${encodeURIComponent(author)}`)} disabled={!author}>
                        {author || "unknown author"}
                      </button>
                      <span className="statusPill">{visibility}</span>
                      {it?.group_id ? (
                        <button className="btn" onClick={() => nav(`/groups/${encodeURIComponent(String(it.group_id))}`)}>
                          {String(it.group_id)}
                        </button>
                      ) : null}
                    </div>
                    <div className="cardDesc" style={{ marginTop: 8 }}>
                      {itemCreatedLabel(it)}
                    </div>
                  </div>

                  <div className="statusSummary">
                    {id ? <span className="statusPill mono">{id}</span> : null}
                  </div>
                </div>

                {body ? <div className="feedBodyText">{body}</div> : null}

                {tags.length ? (
                  <div className="milestoneList">
                    {tags.map((tag) => (
                      <span key={tag} className="miniTag">
                        #{tag}
                      </span>
                    ))}
                  </div>
                ) : null}

                <MediaGallery base={base} media={media} title="Attached media" compact />

                <div className="buttonRow buttonRowWide">
                  <button className="btn btnPrimary" onClick={() => nav(`/thread/${encodeURIComponent(id)}`)} disabled={!id}>
                    Open thread
                  </button>
                  <button className="btn" onClick={() => doLike(id)} disabled={!id || likeBusyId === id}>
                    {likeBusyId === id ? "Liking…" : `Like${likeCount ? ` · ${likeCount}` : ""}`}
                  </button>
                  <button className="btn" onClick={() => doFlag(id)} disabled={!id || flagBusyId === id}>
                    {flagBusyId === id ? "Flagging…" : "Flag"}
                  </button>
                </div>
              </div>
            </article>
          );
        })}

        {nextCursor ? (
          <div className="card">
            <div className="cardBody">
              <div className="buttonRow">
                <button className="btn btnPrimary" onClick={loadMore} disabled={loading}>
                  {loading ? "Loading…" : "Load more"}
                </button>
              </div>
            </div>
          </div>
        ) : null}
      </section>
    </div>
  );
}
