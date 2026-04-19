import React, { useEffect, useMemo, useState } from "react";

import { weall } from "../api/weall";
import { getAuthHeaders, getKeypair, getSession, submitSignedTx } from "../auth/session";
import { useSignerSubmissionBusy } from "../hooks/useSignerSubmissionBusy";
import { useAccount } from "../context/AccountContext";
import { normalizeAccount } from "../auth/keys";
import { useTxQueue } from "../hooks/useTxQueue";
import { checkGates, summarizeAccountState } from "../lib/gates";
import { nav } from "../lib/router";
import { actionableTxError, txPendingKey } from "../lib/txAction";
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
  return actionableTxError(e, "Content action failed.").msg;
}

function asArray<T = any>(v: any): T[] {
  return Array.isArray(v) ? v : [];
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => window.setTimeout(resolve, ms));
}

async function waitForDisputeForTarget(base: string, targetId: string, attempts = 8, delayMs = 300): Promise<any | null> {
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try {
      const disputesRes: any = await weall.disputes({ targetId, limit: 5 }, base);
      const items = asArray<any>(disputesRes?.items);
      const found = items.find((item) => String(item?.target_id || "") === String(targetId));
      if (found) return found;
    } catch {
      // ignore and keep polling
    }
    if (attempt < attempts - 1) await sleep(delayMs);
  }
  return null;
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

function itemMedia(it: any, mediaIndex?: Record<string, any>): any[] {
  const raw = asArray<any>(it?.media);
  if (!raw.length) return raw;

  const index = mediaIndex && typeof mediaIndex === "object" ? mediaIndex : {};
  return raw.map((entry) => {
    if (typeof entry !== "string") return entry;
    const mediaId = entry.trim();
    if (!mediaId || !mediaId.startsWith("media:")) return entry;
    const resolved = index[mediaId];
    if (!resolved || typeof resolved !== "object") return entry;
    return {
      media_id: mediaId,
      cid: resolved?.cid || resolved?.payload?.cid || resolved?.payload?.upload_ref || "",
      mime: resolved?.payload?.mime || resolved?.payload?.mime_type || resolved?.payload?.content_type || "",
      name: resolved?.payload?.name || resolved?.payload?.filename || mediaId,
      kind: resolved?.kind || resolved?.payload?.kind || "",
      declared_by: resolved?.declared_by || "",
      declared_at_nonce: resolved?.declared_at_nonce,
      payload: resolved?.payload || {},
    };
  });
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

function summarizeFeedScope(scope: FeedScope, count: number): string {
  if (scope?.kind === "group") {
    return count
      ? `Showing ${count} visible items for this group scope.`
      : "No group-scoped activity has been returned yet.";
  }
  if (scope?.kind === "account") {
    return count
      ? `Showing ${count} visible items for this account surface.`
      : "This account has no visible items in the current view.";
  }
  return count
    ? `Showing ${count} public items from the node's current feed view.`
    : "No public items are visible in the current feed view yet.";
}

function summarizeInteractionState(args: {
  viewer: string | null;
  gateOk: boolean;
  viewerSummary: string;
}): { tone: string; title: string; text: string } {
  if (!args.viewer) {
    return {
      tone: "",
      title: "Read-only mode",
      text: "You can browse public content now. Restore or create a local session before attempting reactions or flags.",
    };
  }
  if (!args.gateOk) {
    return {
      tone: "",
      title: "Interaction still gated",
      text: `The current viewer is ${args.viewerSummary}. Tier 2 participation is required before reactions and flags are expected to succeed.`,
    };
  }
  return {
    tone: "ok",
    title: "Tier 2 interaction unlocked",
    text: `The current viewer is ${args.viewerSummary}. Reactions and flags still submit protocol transactions and may finalize asynchronously.`,
  };
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
  void defaultSort;
  const tx = useTxQueue();
  const [items, setItems] = useState<any[]>([]);
  const [mediaIndex, setMediaIndex] = useState<Record<string, any>>({});
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
  const [flagInfo, setFlagInfo] = useState<{ msg: string; details?: any; ctaLabel?: string; ctaHref?: string } | null>(null);
  const { refresh: refreshAccountContext } = useAccount();

  const filters = useMemo(() => {
    return {
      visibility: defaultFilters?.visibility ?? "all",
      tags: defaultFilters?.tags,
      author: defaultFilters?.author,
    } as FeedFilters;
  }, [defaultFilters]);

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
  const signerSubmission = useSignerSubmissionBusy(viewer);
  const signerBusy = signerSubmission.busy;
  const interactionSummary = summarizeInteractionState({
    viewer,
    gateOk: gateTier2.ok,
    viewerSummary,
  });

  async function loadMediaIndexFromSnapshot() {
    try {
      const headers = getAuthHeaders();
      const r = await fetch(`${base}/v1/state/snapshot`, {
        method: "GET",
        headers: {
          Accept: "application/json",
          ...(headers || {}),
        },
      });
      if (!r.ok) throw new Error(`snapshot_http_${r.status}`);
      const body: any = await r.json();
      const media =
        body?.state?.content?.media && typeof body.state.content.media === "object"
          ? body.state.content.media
          : {};
      setMediaIndex(media);
    } catch {
      setMediaIndex({});
    }
  }

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
            visibility:
              filters.visibility && filters.visibility !== "all" ? filters.visibility : undefined,
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
            visibility:
              filters.visibility && filters.visibility !== "all" ? filters.visibility : undefined,
          },
          base,
          headers,
        );
      } else {
        r = await weall.feed(
          {
            limit,
            cursor,
            visibility:
              filters.visibility && filters.visibility !== "all" ? filters.visibility : undefined,
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
      await loadMediaIndexFromSnapshot();
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
    void loadPage({ cursor: null, append: false });
  }

  function loadMore() {
    if (!nextCursor) return;
    void loadPage({ cursor: nextCursor, append: true });
  }

  useEffect(() => {
    refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scope?.kind, (scope as any)?.groupId, (scope as any)?.account, filters.visibility, filters.tags, filters.author]);

  useEffect(() => {
    void refreshViewerState();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [viewer]);

  async function doLike(targetId: string) {
    setLikeErr(null);
    setFlagInfo(null);
    if (!viewer) return setLikeErr("Sign in first to react.");
    if (!gateTier2.ok) return setLikeErr(gateTier2.reason || `Gated (${viewerSummary}).`);

    setLikeBusyId(String(targetId));
    try {
      await tx.runTx({
        title: "React to content",
        pendingKey: txPendingKey(["content-reaction", targetId, viewer, "like"]),
        pendingMessage: "Submitting reaction transaction…",
        successMessage: "Reaction submitted. The feed will refresh after submission and final confirmation may still be pending.",
        errorMessage: (e) => prettyMsg(e),
        getTxId: (res: any) => String(res?.tx_id || res?.result?.tx_id || "") || undefined,
        task: async () =>
          submitSignedTx({
            account: viewer,
            tx_type: "CONTENT_REACTION_SET",
            payload: { target_id: String(targetId), reaction: "like" },
            parent: null,
            base,
          }),
      });
      await Promise.allSettled([loadPage({ cursor: null, append: false }), refreshAccountContext()]);
    } catch (e: any) {
      setLikeErr(prettyMsg(e));
    } finally {
      setLikeBusyId(null);
    }
  }

  async function doFlag(targetId: string) {
    setFlagErr(null);
    setFlagInfo(null);
    if (!viewer) return setFlagErr("Sign in first to flag content.");
    if (!gateTier2.ok) return setFlagErr(gateTier2.reason || `Gated (${viewerSummary}).`);

    const reasonRaw = window.prompt("Flag reason (optional)", "");
    if (reasonRaw === null) return;
    const reason = String(reasonRaw || "").trim();

    setFlagBusyId(String(targetId));
    try {
      await tx.runTx({
        title: "Flag content",
        pendingKey: txPendingKey(["content-flag", targetId, viewer]),
        pendingMessage: "Submitting flag transaction…",
        successMessage: "Flag committed. Checking whether a dispute is already visible for this content…",
        errorMessage: (e) => prettyMsg(e),
        getTxId: (res: any) => String(res?.tx_id || res?.result?.tx_id || "") || undefined,
        task: async () =>
          submitSignedTx({
            account: viewer,
            tx_type: "CONTENT_FLAG",
            payload: reason ? { target_id: String(targetId), reason } : { target_id: String(targetId) },
            parent: null,
            base,
          }),
      });
      await Promise.allSettled([loadPage({ cursor: null, append: false }), refreshAccountContext()]);
      const dispute = await waitForDisputeForTarget(base, String(targetId));
      await Promise.allSettled([loadPage({ cursor: null, append: false }), refreshAccountContext()]);
      if (dispute?.id) {
        setFlagInfo({
          msg: `Flag accepted and dispute ${String(dispute.id)} is now visible in the disputes surface.`,
          details: dispute,
          ctaLabel: "Open disputes",
          ctaHref: "/disputes",
        });
      } else {
        setFlagInfo({
          msg: "Flag accepted. Dispute escalation may still be settling in the next block; refresh the disputes page if it does not appear immediately.",
          details: { target_id: String(targetId) },
          ctaLabel: "Open disputes",
          ctaHref: "/disputes",
        });
      }
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
        : "This feed is empty for now. Once activity starts landing on-chain, posts will appear newest-first.";

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

          <div className="surfaceSummaryGrid">
            <div className="surfaceSummaryCard">
              <span className="surfaceSummaryLabel">Feed scope</span>
              <strong className="surfaceSummaryValue">{scopeLabel(scope)}</strong>
              <span className="surfaceSummaryHint">{summarizeFeedScope(scope, items.length)}</span>
            </div>
            <div className="surfaceSummaryCard">
              <span className="surfaceSummaryLabel">Ordering</span>
              <strong className="surfaceSummaryValue">Newest first</strong>
              <span className="surfaceSummaryHint">Rendered from backend ordering, not a frontend-local ranking model.</span>
            </div>
            <div className="surfaceSummaryCard">
              <span className="surfaceSummaryLabel">Viewer state</span>
              <strong className="surfaceSummaryValue mono">{viewer || "Read-only"}</strong>
              <span className="surfaceSummaryHint">{viewer ? viewerSummary : "Browse now. Restore a device session to interact."}</span>
            </div>
            <div className="surfaceSummaryCard">
              <span className="surfaceSummaryLabel">Interaction status</span>
              <strong className="surfaceSummaryValue">{interactionSummary.title}</strong>
              <span className="surfaceSummaryHint">{interactionSummary.text}</span>
            </div>
          </div>

          <div className={`calloutInfo ${interactionSummary.tone === "ok" ? "calloutSuccess" : ""}`}>
            <strong>{interactionSummary.title}</strong>
            <div style={{ marginTop: 6 }}>{interactionSummary.text}</div>
          </div>

          {err ? <div className="inlineError">{err}</div> : null}
          {likeErr ? <div className="inlineError">{likeErr}</div> : null}
          {flagErr ? <div className="inlineError">{flagErr}</div> : null}
          {flagInfo ? (
            <div className="inlineNote">
              <div>{flagInfo.msg}</div>
              <div className="buttonRow" style={{ marginTop: 8 }}>
                {flagInfo.ctaHref ? <button className="btn" onClick={() => nav(String(flagInfo.ctaHref))}>{flagInfo.ctaLabel || "Open"}</button> : null}
                <button className="btn" onClick={() => setFlagInfo(null)}>Dismiss</button>
              </div>
            </div>
          ) : null}
          {signerBusy ? (
            <div className="inlineNote">A signed action is already being submitted for this account. New reactions and flags wait for that submission to finish so signer nonces stay monotonic.</div>
          ) : null}
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
          const media = itemMedia(it, mediaIndex);
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

                <div className="actionStateRow">
                  <span className="actionStateLabel">Action truth</span>
                  <span className="actionStateText">
                    Reactions and flags submit protocol transactions. Submission can succeed before final confirmation is visible.
                  </span>
                </div>

                <div className="buttonRow buttonRowWide">
                  <button className="btn btnPrimary" onClick={() => nav(`/thread/${encodeURIComponent(id)}`)} disabled={!id}>
                    Open thread
                  </button>
                  <button className="btn" onClick={() => void doLike(id)} disabled={!id || likeBusyId === id || signerBusy}>
                    {likeBusyId === id ? "Liking…" : signerBusy ? "Waiting…" : `Like${likeCount ? ` · ${likeCount}` : ""}`}
                  </button>
                  <button className="btn" onClick={() => void doFlag(id)} disabled={!id || flagBusyId === id || signerBusy}>
                    {flagBusyId === id ? "Flagging…" : signerBusy ? "Waiting…" : "Flag"}
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
