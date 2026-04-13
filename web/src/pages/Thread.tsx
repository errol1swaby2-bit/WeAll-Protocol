import React, { useEffect, useMemo, useState } from "react";

import { getApiBaseUrl, weall } from "../api/weall";
import ErrorBanner from "../components/ErrorBanner";
import { nav } from "../lib/router";
import { getKeypair, getSession, submitSignedTx } from "../auth/session";
import { useSignerSubmissionBusy } from "../hooks/useSignerSubmissionBusy";
import { normalizeAccount } from "../auth/keys";
import { useAccount } from "../context/AccountContext";
import { checkGates, summarizeAccountState } from "../lib/gates";
import MediaGallery from "../components/MediaGallery";

function prettyErr(e: any): { msg: string; details: any } {
  const details = e?.payload || e?.body || e?.data || e;
  const code = String(details?.error?.code || details?.code || "").trim();
  const reason = String(details?.error?.details?.reason || details?.reason || "").trim();
  const nested = details?.error?.details?.details;
  const nestedError = nested && typeof nested === "object" ? String(nested.error || nested.code || "").trim() : "";
  const msg = String(details?.error?.message || details?.message || e?.message || "error").trim() || "error";
  const detail = nestedError || reason || code;
  return { msg: detail && detail !== msg ? `${msg} (${detail})` : msg, details };
}

function reactionCount(it: any, key: string): number {
  const reactions = it?.reactions;
  if (!reactions || typeof reactions !== "object") return 0;
  const raw = reactions[key];
  return Number.isFinite(Number(raw)) ? Number(raw) : 0;
}

function asArray<T = any>(v: any): T[] {
  return Array.isArray(v) ? v : [];
}

export default function Thread({ id }: { id: string }): JSX.Element {
  const base = useMemo(() => getApiBaseUrl(), []);
  const [thread, setThread] = useState<any>(null);
  const [err, setErr] = useState<{ msg: string; details: any } | null>(null);

  const [viewer, setViewer] = useState<string | null>(null);
  const [canSign, setCanSign] = useState(false);
  const [viewerState, setViewerState] = useState<any | null>(null);

  const [reply, setReply] = useState("");
  const [busy, setBusy] = useState(false);
  const [txErr, setTxErr] = useState<{ msg: string; details: any } | null>(null);

  const [likeBusyId, setLikeBusyId] = useState<string | null>(null);
  const [likeErr, setLikeErr] = useState<string | null>(null);

  const [flagTargetId, setFlagTargetId] = useState<string | null>(null);
  const [flagReason, setFlagReason] = useState("");
  const { refresh: refreshAccountContext } = useAccount();

  function refreshSession() {
    const s = getSession();
    const v = s ? normalizeAccount(s.account) : null;
    setViewer(v);
    const kp = v ? getKeypair(v) : null;
    setCanSign(!!kp?.secretKeyB64);
  }

  async function refreshViewerState(nextViewer?: string | null) {
    const account = nextViewer ?? viewer;
    if (!account) {
      setViewerState(null);
      return;
    }
    try {
      const r: any = await weall.account(account, base);
      setViewerState(r?.state ?? null);
    } catch {
      setViewerState(null);
    }
  }

  async function load() {
    setErr(null);
    try {
      const r: any = await weall.thread(id, base);
      setThread(r);
    } catch (e: any) {
      setErr(prettyErr(e));
      setThread(null);
    }
  }

  useEffect(() => {
    const s = getSession();
    const v = s ? normalizeAccount(s.account) : null;
    setViewer(v);
    const kp = v ? getKeypair(v) : null;
    setCanSign(!!kp?.secretKeyB64);
    refreshViewerState(v);
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id]);

  const post = thread?.post || null;
  const comments: any[] = Array.isArray(thread?.comments)
    ? thread.comments
    : Array.isArray(thread?.items)
      ? thread.items
      : [];

  const postId = String(post?.post_id || id);
  const postAuthor = normalizeAccount(String(post?.author || ""));
  const postBody = String(post?.body || "");
  const postTags = asArray<string>(post?.tags).map((x) => String(x));
  const postMedia = asArray<any>(post?.media);
  const postVisibility = String(post?.visibility || "public");

  const gate = checkGates({ loggedIn: !!viewer, canSign, accountState: viewerState, requireTier: 2 });
  const viewerSummary = viewerState ? summarizeAccountState(viewerState) : "(state unknown)";
  const signerSubmission = useSignerSubmissionBusy(viewer);
  const signerBusy = signerSubmission.busy;

  async function likeTarget(targetId: string) {
    setTxErr(null);
    setLikeErr(null);
    if (!viewer) {
      setLikeErr("Not logged in.");
      return;
    }
    if (!gate.ok) {
      setLikeErr(gate.reason || "gated");
      return;
    }

    setLikeBusyId(String(targetId));
    try {
      await submitSignedTx({
        account: viewer,
        tx_type: "CONTENT_REACTION_SET",
        payload: { target_id: String(targetId), reaction: "like" },
        parent: null,
        base,
      });
      await Promise.allSettled([load(), refreshAccountContext()]);
    } catch (e: any) {
      const pe = prettyErr(e);
      setLikeErr(pe.msg);
    } finally {
      setLikeBusyId(null);
    }
  }

  async function submitReply() {
    setTxErr(null);
    if (!viewer) return setTxErr({ msg: "not_logged_in", details: null });
    if (!gate.ok) return setTxErr({ msg: gate.reason || "gated", details: viewerState });

    const b = reply.trim();
    if (!b) return setTxErr({ msg: "empty_reply", details: null });

    setBusy(true);
    try {
      await submitSignedTx({
        account: viewer,
        tx_type: "CONTENT_COMMENT_CREATE",
        payload: { post_id: postId, body: b },
        parent: null,
        base,
      });

      setReply("");
      await Promise.allSettled([load(), refreshAccountContext()]);
    } catch (e: any) {
      setTxErr(prettyErr(e));
    } finally {
      setBusy(false);
    }
  }

  async function deleteComment(commentId: string, commentAuthor: string) {
    setTxErr(null);
    if (!viewer) return setTxErr({ msg: "not_logged_in", details: null });
    if (!gate.ok) return setTxErr({ msg: gate.reason || "gated", details: viewerState });

    const isOwner = normalizeAccount(viewer) === normalizeAccount(commentAuthor);
    if (!isOwner) return setTxErr({ msg: "not_author", details: { commentAuthor, viewer } });

    if (!window.confirm("Delete this comment?")) return;

    setBusy(true);
    try {
      await submitSignedTx({
        account: viewer,
        tx_type: "CONTENT_COMMENT_DELETE",
        payload: { comment_id: commentId },
        parent: null,
        base,
      });
      await Promise.allSettled([load(), refreshAccountContext()]);
    } catch (e: any) {
      setTxErr(prettyErr(e));
    } finally {
      setBusy(false);
    }
  }

  async function flagTarget(targetId: string) {
    setTxErr(null);
    if (!viewer) return setTxErr({ msg: "not_logged_in", details: null });
    if (!gate.ok) return setTxErr({ msg: gate.reason || "gated", details: viewerState });

    const reason = flagReason.trim();

    setBusy(true);
    try {
      await submitSignedTx({
        account: viewer,
        tx_type: "CONTENT_FLAG",
        payload: reason ? { target_id: targetId, reason } : { target_id: targetId },
        parent: null,
        base,
      });
      setFlagTargetId(null);
      setFlagReason("");
    } catch (e: any) {
      setTxErr(prettyErr(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="pageStack pageNarrow">
      <section className="card heroCard">
        <div className="cardBody heroBody compactHero">
          <div className="heroSplit">
            <div>
              <div className="eyebrow">Thread view</div>
              <h1 className="heroTitle heroTitleSm">Conversation and replies</h1>
              <p className="heroText">
                Read the post, react if your account tier allows it, and add replies without losing the calmer visual
                posture of the rest of the app.
              </p>
            </div>

            <div className="heroInfoPanel">
              <div className="heroInfoTitle">Viewer state</div>
              <div className="heroInfoList">
                <span className={`statusPill ${viewer ? "ok" : ""}`}>{viewer || "Read-only"}</span>
                <span className={`statusPill ${gate.ok ? "ok" : ""}`}>{gate.ok ? "Tier 2 actions unlocked" : "Tier 2 required"}</span>
              </div>
            </div>
          </div>

          <div className="buttonRow buttonRowWide">
            <button className="btn" onClick={() => nav("/feed")}>
              Back to feed
            </button>
            <button className="btn" onClick={load}>
              Refresh
            </button>
            <button className="btn" onClick={() => nav(`/content/${encodeURIComponent(postId)}`)}>
              Open raw content
            </button>
          </div>
        </div>
      </section>

      <ErrorBanner message={err?.msg} details={err?.details} onRetry={load} onDismiss={() => setErr(null)} />

      {txErr ? <ErrorBanner message={txErr.msg} details={txErr.details} onDismiss={() => setTxErr(null)} /> : null}

      {likeErr ? (
        <section className="card">
          <div className="cardBody">
            <div className="inlineError">Reaction error: {likeErr}</div>
          </div>
        </section>
      ) : null}

      {signerBusy ? (
        <section className="card">
          <div className="cardBody">
            <div className="inlineNote">A signed action is already in flight for this account. The next action will wait for the current submission to finish so signer nonces do not collide.</div>
          </div>
        </section>
      ) : null}

      <section className="card">
        <div className="cardBody formStack">
          <div className="sectionHead">
            <div>
              <div className="eyebrow">Post</div>
              <h2 className="cardTitle">{postAuthor || "Unknown author"}</h2>
            </div>
            <div className="statusSummary">
              <span className="statusPill mono">{postId}</span>
              <span className="statusPill">{postVisibility}</span>
            </div>
          </div>

          <div className="cardDesc">
            Viewer: {viewer ? <span className="mono">{viewer}</span> : "not logged in"} · {viewerSummary}
          </div>

          <div className="feedBodyText">{postBody || "(empty post body)"}</div>

          {postTags.length ? (
            <div className="milestoneList">
              {postTags.map((tag) => (
                <span key={tag} className="miniTag">
                  #{tag}
                </span>
              ))}
            </div>
          ) : null}

          <MediaGallery base={base} media={postMedia} title="Attached media" />

          <div className="buttonRow buttonRowWide">
            <button
              className="btn"
              onClick={() => likeTarget(postId)}
              disabled={!gate.ok || likeBusyId === postId || signerBusy}
              title="Set reaction=like"
            >
              {likeBusyId === postId ? "Liking…" : signerBusy ? "Waiting…" : `Like${reactionCount(post, "like") ? ` · ${reactionCount(post, "like")}` : ""}`}
            </button>

            {viewer && normalizeAccount(viewer) === postAuthor ? (
              <button className="btn" onClick={() => nav(`/content/${encodeURIComponent(postId)}`)}>
                Edit / delete
              </button>
            ) : (
              <button
                className="btn"
                onClick={() => {
                  setFlagTargetId(postId);
                  setFlagReason("");
                }}
                disabled={!gate.ok || signerBusy}
              >
                {signerBusy ? "Waiting…" : "Flag"}
              </button>
            )}
          </div>

          {flagTargetId === postId ? (
            <div className="formStack">
              <label className="fieldLabel">
                Flag reason
                <input
                  value={flagReason}
                  onChange={(e) => setFlagReason(e.target.value)}
                  placeholder="Spam, harassment, illegal content, impersonation…"
                />
              </label>

              <div className="buttonRow">
                <button className="btn btnPrimary" onClick={() => flagTarget(postId)} disabled={busy || signerBusy}>
                  {busy ? "Submitting…" : "Submit flag"}
                </button>
                <button className="btn" onClick={() => setFlagTargetId(null)} disabled={busy || signerBusy}>
                  Cancel
                </button>
              </div>
            </div>
          ) : null}
        </div>
      </section>

      <section className="card">
        <div className="cardBody formStack">
          <div className="sectionHead">
            <div>
              <div className="eyebrow">Reply</div>
              <h2 className="cardTitle">Add to the thread</h2>
            </div>
            <span className={`statusPill ${gate.ok ? "ok" : ""}`}>{gate.ok ? "Ready to reply" : gate.reason || "Locked"}</span>
          </div>

          <label className="fieldLabel">
            Your reply
            <textarea
              value={reply}
              onChange={(e) => setReply(e.target.value)}
              placeholder="Write a thoughtful reply…"
              rows={6}
              disabled={busy || signerBusy}
            />
          </label>

          <div className="buttonRow buttonRowWide">
            <button className="btn btnPrimary" onClick={submitReply} disabled={!gate.ok || busy || signerBusy}>
              {busy ? "Posting…" : signerBusy ? "Waiting…" : "Post reply"}
            </button>
          </div>
        </div>
      </section>

      <section className="card">
        <div className="cardBody formStack">
          <div className="sectionHead">
            <div>
              <div className="eyebrow">Replies</div>
              <h2 className="cardTitle">{comments.length} comment{comments.length === 1 ? "" : "s"}</h2>
            </div>
          </div>

          {!comments.length ? <div className="cardDesc">No replies yet.</div> : null}

          <div className="pageStack">
            {comments.map((c: any) => {
              const cid = String(c?.comment_id || "");
              const ca = normalizeAccount(String(c?.author || ""));
              const isOwner = !!viewer && normalizeAccount(viewer) === ca;

              return (
                <article key={cid} className="card">
                  <div className="cardBody formStack">
                    <div className="sectionHead">
                      <div className="statusSummary">
                        <button className="btn" onClick={() => nav(`/account/${encodeURIComponent(ca)}`)}>
                          <span className="mono">{ca || "unknown"}</span>
                        </button>
                        <span className="statusPill mono">{cid}</span>
                      </div>

                      <div className="buttonRow">
                        <button
                          className="btn"
                          onClick={() => likeTarget(cid)}
                          disabled={!gate.ok || likeBusyId === cid || signerBusy}
                          title="Set reaction=like on this comment"
                        >
                          {likeBusyId === cid ? "Liking…" : signerBusy ? "Waiting…" : `Like${reactionCount(c, "like") ? ` · ${reactionCount(c, "like")}` : ""}`}
                        </button>

                        {isOwner ? (
                          <button className="btn" onClick={() => deleteComment(cid, ca)} disabled={!gate.ok || busy || signerBusy}>
                            Delete
                          </button>
                        ) : viewer ? (
                          <button
                            className="btn"
                            onClick={() => {
                              setFlagTargetId(cid);
                              setFlagReason("");
                            }}
                            disabled={!gate.ok || busy || signerBusy}
                          >
                            {signerBusy ? "Waiting…" : "Flag"}
                          </button>
                        ) : null}
                      </div>
                    </div>

                    <div className="feedBodyText">{String(c?.body || "")}</div>

                    {flagTargetId === cid ? (
                      <div className="formStack">
                        <label className="fieldLabel">
                          Flag reason
                          <input
                            value={flagReason}
                            onChange={(e) => setFlagReason(e.target.value)}
                            placeholder="Reason for juror review"
                          />
                        </label>
                        <div className="buttonRow">
                          <button className="btn btnPrimary" onClick={() => flagTarget(cid)} disabled={busy || signerBusy}>
                            {busy ? "Submitting…" : "Submit flag"}
                          </button>
                          <button className="btn" onClick={() => setFlagTargetId(null)} disabled={busy || signerBusy}>
                            Cancel
                          </button>
                        </div>
                      </div>
                    ) : null}
                  </div>
                </article>
              );
            })}
          </div>
        </div>
      </section>

      <section className="card">
        <div className="cardBody formStack">
          <div className="sectionHead">
            <div>
              <div className="eyebrow">Debug</div>
              <h2 className="cardTitle">Raw thread JSON</h2>
            </div>
          </div>
          <pre className="codePanel mono">{JSON.stringify(thread, null, 2)}</pre>
        </div>
      </section>
    </div>
  );
}
