import React, { useEffect, useMemo, useState } from "react";

import { getApiBaseUrl, weall } from "../api/weall";
import ErrorBanner from "../components/ErrorBanner";
import MediaGallery from "../components/MediaGallery";
import { nav } from "../lib/router";
import { getKeypair, getSession, submitSignedTx } from "../auth/session";
import { normalizeAccount } from "../auth/keys";
import { checkGates, summarizeAccountState } from "../lib/gates";

function prettyErr(e: any): { msg: string; details: any } | null {
  if (!e) return null;
  const details = e?.data || e?.body || e;
  const msg = details?.message || e?.message || "error";
  return { msg, details };
}

function asArray<T = any>(v: any): T[] {
  return Array.isArray(v) ? v : [];
}

export default function Content({ id }: { id: string }): JSX.Element {
  const base = useMemo(() => getApiBaseUrl(), []);
  const [data, setData] = useState<any>(null);
  const [err, setErr] = useState<{ msg: string; details: any } | null>(null);
  const [loading, setLoading] = useState<boolean>(true);

  const [viewer, setViewer] = useState<string | null>(null);
  const [canSign, setCanSign] = useState(false);
  const [viewerState, setViewerState] = useState<any | null>(null);

  const [editOpen, setEditOpen] = useState(false);
  const [editBody, setEditBody] = useState("");
  const [txBusy, setTxBusy] = useState(false);
  const [txErr, setTxErr] = useState<{ msg: string; details: any } | null>(null);

  const [flagOpen, setFlagOpen] = useState(false);
  const [flagReason, setFlagReason] = useState("");

  function refreshSession() {
    const s = getSession();
    const v = s ? normalizeAccount(s.account) : null;
    setViewer(v);
    const kp = v ? getKeypair(v) : null;
    setCanSign(!!kp?.secretKeyB64);
  }

  async function refreshViewerState() {
    if (!viewer) {
      setViewerState(null);
      return;
    }
    try {
      const r = await weall.account(viewer, base);
      setViewerState((r as any)?.state ?? null);
    } catch {
      setViewerState(null);
    }
  }

  async function load() {
    setErr(null);
    setLoading(true);
    try {
      const r = await weall.content(id, base);
      setData(r);
      const c = (r as any)?.content;
      if ((r as any)?.type === "post" && c && typeof c === "object") {
        setEditBody(String((c as any).body || ""));
      }
    } catch (e: any) {
      setErr(prettyErr(e));
      setData(null);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    refreshSession();
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id]);

  useEffect(() => {
    refreshViewerState();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [viewer]);

  const c = data?.content;
  const type = String(data?.type || "");
  const postId = String(c?.post_id || id);
  const author = normalizeAccount(String(c?.author || ""));
  const body = String(c?.body || c?.text || "");
  const tags = asArray<string>(c?.tags).map((t) => String(t)).filter(Boolean);
  const media = asArray<any>(c?.media);
  const visibility = String(c?.visibility || "public");
  const createdAt = String(c?.created_at || c?.timestamp || "");
  const groupId = String(c?.group_id || c?.scope_id || "");
  const deleted = Boolean(c?.deleted);

  const isPost = type === "post";
  const isOwner = Boolean(viewer && isPost && normalizeAccount(viewer) === author);

  const gate = checkGates({ loggedIn: !!viewer, canSign, accountState: viewerState, requireTier: 2 });

  async function doEdit() {
    setTxErr(null);
    if (!viewer) return setTxErr({ msg: "not_logged_in", details: null });
    if (!gate.ok) return setTxErr({ msg: gate.reason || "gated", details: viewerState });
    if (!isOwner) return setTxErr({ msg: "not_author", details: { author, viewer } });

    const nextBody = (editBody || "").trim();
    if (!nextBody) return setTxErr({ msg: "empty_body", details: null });

    setTxBusy(true);
    try {
      await submitSignedTx({
        account: viewer,
        tx_type: "CONTENT_POST_EDIT",
        payload: { post_id: postId, body: nextBody },
        parent: null,
        base,
      });
      setEditOpen(false);
      await load();
    } catch (e: any) {
      const parsed = prettyErr(e);
      if (parsed) setTxErr(parsed);
    } finally {
      setTxBusy(false);
    }
  }

  async function doDelete() {
    setTxErr(null);
    if (!viewer) return setTxErr({ msg: "not_logged_in", details: null });
    if (!gate.ok) return setTxErr({ msg: gate.reason || "gated", details: viewerState });
    if (!isOwner) return setTxErr({ msg: "not_author", details: { author, viewer } });
    if (!window.confirm("Delete this post? This cannot be undone.")) return;

    setTxBusy(true);
    try {
      await submitSignedTx({
        account: viewer,
        tx_type: "CONTENT_POST_DELETE",
        payload: { post_id: postId },
        parent: null,
        base,
      });
      await load();
    } catch (e: any) {
      const parsed = prettyErr(e);
      if (parsed) setTxErr(parsed);
    } finally {
      setTxBusy(false);
    }
  }

  async function doFlag() {
    setTxErr(null);
    if (!viewer) return setTxErr({ msg: "not_logged_in", details: null });
    if (!gate.ok) return setTxErr({ msg: gate.reason || "gated", details: viewerState });

    const reason = (flagReason || "").trim();

    setTxBusy(true);
    try {
      await submitSignedTx({
        account: viewer,
        tx_type: "CONTENT_FLAG",
        payload: reason ? { target_id: postId, reason } : { target_id: postId },
        parent: null,
        base,
      });
      setFlagOpen(false);
      setFlagReason("");
    } catch (e: any) {
      const parsed = prettyErr(e);
      if (parsed) setTxErr(parsed);
    } finally {
      setTxBusy(false);
    }
  }

  const viewerSummary = viewerState ? summarizeAccountState(viewerState) : "(state unknown)";

  return (
    <div className="pageStack pageNarrow">
      <section className="card heroCard">
        <div className="cardBody heroBody compactHero">
          <div className="heroSplit">
            <div>
              <div className="eyebrow">Content</div>
              <h1 className="heroTitle heroTitleSm">{isPost ? "Post detail" : "Content detail"}</h1>
              <p className="heroText">
                View the human-friendly version first, then expand the raw payload only when you need it. Declared media
                renders inline, and actions stay close to the content itself.
              </p>
            </div>
            <div className="heroInfoPanel">
              <div className="heroInfoTitle">Quick actions</div>
              <div className="heroInfoList">
                <button className="btn" onClick={() => nav("/feed")}>← Feed</button>
                {author ? <button className="btn" onClick={() => nav(`/account/${encodeURIComponent(author)}`)}>{author}</button> : null}
                {groupId ? <button className="btn" onClick={() => nav(`/groups/${encodeURIComponent(groupId)}`)}>Open group</button> : null}
                {isPost ? <button className="btn" onClick={() => nav(`/thread/${encodeURIComponent(postId)}`)}>Open thread</button> : null}
                <button className="btn" onClick={load}>Refresh</button>
              </div>
            </div>
          </div>

          <div className="statsGrid statsGridCompact">
            <div className="statCard">
              <span className="statLabel">Type</span>
              <span className="statValue">{type || "—"}</span>
            </div>
            <div className="statCard">
              <span className="statLabel">Visibility</span>
              <span className="statValue">{visibility}</span>
            </div>
            <div className="statCard">
              <span className="statLabel">Media</span>
              <span className="statValue">{media.length}</span>
            </div>
          </div>
        </div>
      </section>

      <ErrorBanner message={err?.msg} details={err?.details} onRetry={load} onDismiss={() => setErr(null)} />

      {loading ? (
        <section className="card">
          <div className="cardBody">
            <div className="emptyPanel compact">
              <strong>Loading content…</strong>
              <span>The page is fetching the latest backend payload.</span>
            </div>
          </div>
        </section>
      ) : null}

      {!loading && !data ? (
        <section className="card">
          <div className="cardBody">
            <div className="emptyPanel">
              <strong>Content not available.</strong>
              <span>This item may not exist yet, may have been removed, or the node may still be syncing.</span>
              <div className="buttonRow buttonRowWide">
                <button className="btn" onClick={load}>Try again</button>
                <button className="btn" onClick={() => nav("/feed")}>Back to feed</button>
              </div>
            </div>
          </div>
        </section>
      ) : null}

      {data ? (
        <>
          <section className="card">
            <div className="cardBody formStack">
              <div className="sectionHead">
                <div>
                  <div className="eyebrow">Viewer</div>
                  <h2 className="cardTitle">Account gates</h2>
                </div>
                <div className="statusSummary">
                  <span className={`statusPill ${gate.ok ? "ok" : ""}`}>{gate.ok ? "Tier 2 ready" : "Gated"}</span>
                  {!viewer ? <button className="btn" onClick={() => nav("/poh")}>Go to PoH</button> : <button className="btn" onClick={refreshViewerState}>Refresh gates</button>}
                </div>
              </div>

              <div className="feedMediaMeta">
                {viewer ? (
                  <>
                    <b>{viewer}</b> — <b>{viewerSummary}</b>
                  </>
                ) : (
                  <>Not logged in</>
                )}
              </div>

              {txErr ? <ErrorBanner message={txErr.msg} details={txErr.details} onDismiss={() => setTxErr(null)} /> : null}
            </div>
          </section>

          <section className="card">
            <div className="cardBody formStack">
              <div className="sectionHead">
                <div>
                  <div className="eyebrow">Summary</div>
                  <h2 className="cardTitle">Content details</h2>
                </div>
                <span className="statusPill mono">{postId}</span>
              </div>

              <div className="infoGrid">
                <div className="infoCard compact">
                  <div className="infoCardHeader">
                    <strong>Author</strong>
                  </div>
                  <div className="infoCardText">{author || "Unknown"}</div>
                </div>
                <div className="infoCard compact">
                  <div className="infoCardHeader">
                    <strong>Created</strong>
                  </div>
                  <div className="infoCardText">{createdAt || "Unknown"}</div>
                </div>
                <div className="infoCard compact">
                  <div className="infoCardHeader">
                    <strong>Group scope</strong>
                  </div>
                  <div className="infoCardText">{groupId || "No group scope"}</div>
                </div>
                <div className="infoCard compact">
                  <div className="infoCardHeader">
                    <strong>Status</strong>
                  </div>
                  <div className="infoCardText">{deleted ? "Marked deleted" : "Active"}</div>
                </div>
              </div>

              {deleted ? (
                <div className="emptyPanel compact dangerTone">
                  <strong>This post is marked deleted.</strong>
                  <span>The record still exists for transparency, but it should no longer be treated as an active post.</span>
                </div>
              ) : null}

              {body ? <div className="feedBodyText">{body}</div> : <div className="emptyPanel compact"><strong>No post body.</strong><span>This item currently has no readable text body.</span></div>}

              {tags.length ? (
                <div className="milestoneList">
                  {tags.map((tag) => (
                    <span key={tag} className="miniTag">#{tag}</span>
                  ))}
                </div>
              ) : null}
              <MediaGallery base={base} media={media} title="Attachment" />
            </div>
          </section>

          {isPost ? (
            <section className="card">
              <div className="cardBody formStack">
                <div className="sectionHead">
                  <div>
                    <div className="eyebrow">Actions</div>
                    <h2 className="cardTitle">Manage this post</h2>
                  </div>
                  <span className="statusPill">Gate: {gate.ok ? "ok" : gate.reason}</span>
                </div>

                <div className="emptyPanel compact">
                  <strong>{isOwner ? "You authored this post." : "You are viewing someone else’s post."}</strong>
                  <span>
                    {isOwner
                      ? "You can edit or delete with the original signing key on this device."
                      : "Tier 2 viewers can submit on-chain flags when something needs moderator or juror attention."}
                  </span>
                </div>

                <div className="buttonRow buttonRowWide">
                  {isOwner ? (
                    <>
                      <button className="btn" onClick={() => setEditOpen((v) => !v)} disabled={!gate.ok}>{editOpen ? "Close edit" : "Edit"}</button>
                      <button className="btn btnDanger" onClick={doDelete} disabled={!gate.ok || txBusy}>{txBusy ? "Working…" : "Delete"}</button>
                    </>
                  ) : (
                    <button className="btn" onClick={() => setFlagOpen((v) => !v)} disabled={!gate.ok}>{flagOpen ? "Close flag" : "Flag"}</button>
                  )}
                </div>

                {editOpen && isOwner ? (
                  <div className="formStack">
                    <textarea
                      className="textarea"
                      value={editBody}
                      onChange={(e) => setEditBody(e.target.value)}
                      rows={8}
                    />
                    <div className="buttonRow buttonRowWide">
                      <button className="btn btnPrimary" onClick={doEdit} disabled={!gate.ok || txBusy}>{txBusy ? "Saving…" : "Save"}</button>
                      <button className="btn" onClick={() => setEditOpen(false)} disabled={txBusy}>Cancel</button>
                    </div>
                    <div className="feedMediaMeta">Edit updates the on-chain post body and requires the original author key.</div>
                  </div>
                ) : null}

                {flagOpen && !isOwner ? (
                  <div className="formStack">
                    <input
                      className="input"
                      value={flagReason}
                      onChange={(e) => setFlagReason(e.target.value)}
                      placeholder="Reason (e.g., spam, harassment, illegal content)"
                    />
                    <div className="buttonRow buttonRowWide">
                      <button className="btn btnPrimary" onClick={doFlag} disabled={!gate.ok || txBusy}>{txBusy ? "Submitting…" : "Submit flag"}</button>
                      <button className="btn" onClick={() => setFlagOpen(false)} disabled={txBusy}>Cancel</button>
                    </div>
                    <div className="feedMediaMeta">Flags are on-chain signals. Disputes and moderation outcomes are resolved by the network.</div>
                  </div>
                ) : null}
              </div>
            </section>
          ) : null}

          <section className="card">
            <div className="cardBody formStack">
              <details className="detailsPanel">
                <summary>Backend payload</summary>
                <pre className="codePanel mono">{JSON.stringify(data, null, 2)}</pre>
              </details>
            </div>
          </section>
        </>
      ) : null}
    </div>
  );
}
