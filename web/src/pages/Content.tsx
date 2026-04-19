import React, { useEffect, useMemo, useState } from "react";

import { getApiBaseUrl, weall } from "../api/weall";
import ErrorBanner from "../components/ErrorBanner";
import MediaGallery from "../components/MediaGallery";
import { useSignerSubmissionBusy } from "../hooks/useSignerSubmissionBusy";
import { nav } from "../lib/router";
import { getKeypair, getSession, submitSignedTx } from "../auth/session";
import { normalizeAccount } from "../auth/keys";
import { checkGates, summarizeAccountState } from "../lib/gates";
import { useTxQueue } from "../hooks/useTxQueue";
import { actionableTxError, txPendingKey } from "../lib/txAction";

function prettyErr(e: any): { msg: string; details: any } | null {
  if (!e) return null as any;
  return actionableTxError(e, "Content action failed.");
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

function summarizeActionReadiness(args: {
  viewer: string | null;
  gateOk: boolean;
  isOwner: boolean;
  viewerSummary: string;
}): { title: string; detail: string } {
  if (!args.viewer) {
    return {
      title: "Read-only viewer",
      detail: "You can inspect the content and attachments now. Create or restore a local session before attempting edits, deletion, or flags.",
    };
  }
  if (!args.gateOk) {
    return {
      title: "Participation still gated",
      detail: `The current viewer is ${args.viewerSummary}. Higher-trust actions may be rejected until Tier 2 participation is available.`,
    };
  }
  if (args.isOwner) {
    return {
      title: "Author controls available",
      detail: "Edits and deletion require the original author key on this device and still submit on-chain transactions rather than instant local edits.",
    };
  }
  return {
    title: "Viewer moderation action available",
    detail: "Flags submit on-chain signals for later network review. Submission is not the same as a moderation outcome.",
  };
}

export default function Content({ id }: { id: string }): JSX.Element {
  const base = useMemo(() => getApiBaseUrl(), []);
  const tx = useTxQueue();
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
  const [txInfo, setTxInfo] = useState<{ msg: string; details?: any; ctaLabel?: string; ctaHref?: string } | null>(null);

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
    void load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id]);

  useEffect(() => {
    void refreshViewerState();
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
  const moderation = data?.moderation && typeof data.moderation === "object" ? data.moderation : null;
  const linkedDisputeId = String(moderation?.dispute_id || "").trim();

  const isPost = type === "post";
  const isOwner = Boolean(viewer && isPost && normalizeAccount(viewer) === author);

  const gate = checkGates({ loggedIn: !!viewer, canSign, accountState: viewerState, requireTier: 2 });
  const viewerSummary = viewerState ? summarizeAccountState(viewerState) : "(state unknown)";
  const signerSubmission = useSignerSubmissionBusy(viewer);
  const signerBusy = signerSubmission.busy;
  const actionReadiness = summarizeActionReadiness({
    viewer,
    gateOk: gate.ok,
    isOwner,
    viewerSummary,
  });

  async function doEdit() {
    setTxErr(null);
    setTxInfo(null);
    if (!viewer) return setTxErr({ msg: "not_logged_in", details: null });
    if (!gate.ok) return setTxErr({ msg: gate.reason || "gated", details: viewerState });
    if (!isOwner) return setTxErr({ msg: "not_author", details: { author, viewer } });

    const nextBody = (editBody || "").trim();
    if (!nextBody) return setTxErr({ msg: "empty_body", details: null });

    setTxBusy(true);
    try {
      await tx.runTx({
        title: "Edit post",
        pendingKey: txPendingKey(["content-edit", postId, viewer]),
        pendingMessage: "Submitting edit transaction…",
        successMessage: "Edit submitted. Final confirmation and feed/index refresh may lag behind the initial submission.",
        errorMessage: (e) => prettyErr(e)?.msg || "error",
        getTxId: (res: any) => String(res?.tx_id || res?.result?.tx_id || "") || undefined,
        task: async () =>
          submitSignedTx({
            account: viewer,
            tx_type: "CONTENT_POST_EDIT",
            payload: { post_id: postId, body: nextBody },
            parent: null,
            base,
          }),
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
    setTxInfo(null);
    if (!viewer) return setTxErr({ msg: "not_logged_in", details: null });
    if (!gate.ok) return setTxErr({ msg: gate.reason || "gated", details: viewerState });
    if (!isOwner) return setTxErr({ msg: "not_author", details: { author, viewer } });
    if (!window.confirm("Delete this post? This cannot be undone.")) return;

    setTxBusy(true);
    try {
      await tx.runTx({
        title: "Delete post",
        pendingKey: txPendingKey(["content-delete", postId, viewer]),
        pendingMessage: "Submitting delete transaction…",
        successMessage: "Deletion submitted. Content surfaces may still reflect the old state briefly while indexes catch up.",
        errorMessage: (e) => prettyErr(e)?.msg || "error",
        getTxId: (res: any) => String(res?.tx_id || res?.result?.tx_id || "") || undefined,
        task: async () =>
          submitSignedTx({
            account: viewer,
            tx_type: "CONTENT_POST_DELETE",
            payload: { post_id: postId },
            parent: null,
            base,
          }),
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
    setTxInfo(null);
    if (!viewer) return setTxErr({ msg: "not_logged_in", details: null });
    if (!gate.ok) return setTxErr({ msg: gate.reason || "gated", details: viewerState });

    const reason = (flagReason || "").trim();

    setTxBusy(true);
    try {
      await tx.runTx({
        title: "Flag content",
        pendingKey: txPendingKey(["content-flag", postId, viewer]),
        pendingMessage: "Submitting flag transaction…",
        successMessage: "Flag committed. Checking whether the dispute is already visible in the moderation surface…",
        errorMessage: (e) => prettyErr(e)?.msg || "error",
        getTxId: (res: any) => String(res?.tx_id || res?.result?.tx_id || "") || undefined,
        task: async () =>
          submitSignedTx({
            account: viewer,
            tx_type: "CONTENT_FLAG",
            payload: reason ? { target_id: postId, reason } : { target_id: postId },
            parent: null,
            base,
          }),
      });
      setFlagOpen(false);
      setFlagReason("");
      await load();
      const dispute = linkedDisputeId
        ? { id: linkedDisputeId, target_id: postId }
        : await waitForDisputeForTarget(base, postId);
      await load();
      if (dispute?.id) {
        const disputeId = String(dispute.id);
        setTxInfo({
          msg: `Flag accepted and dispute ${disputeId} is now visible. Open it directly to continue the review flow.`,
          details: dispute,
          ctaLabel: "Open dispute",
          ctaHref: `/disputes/${encodeURIComponent(disputeId)}`,
        });
      } else {
        setTxInfo({
          msg: "Flag accepted. Dispute escalation may still be settling in the next block; reopen this page or refresh the dispute route if it does not appear immediately.",
          details: { target_id: postId },
          ctaLabel: "Open disputes",
          ctaHref: "/disputes",
        });
      }
    } catch (e: any) {
      const parsed = prettyErr(e);
      if (parsed) setTxErr(parsed);
    } finally {
      setTxBusy(false);
    }
  }

  return (
    <div className="pageStack pageNarrow">
      <section className="card heroCard">
        <div className="cardBody heroBody compactHero">
          <div className="heroSplit">
            <div>
              <div className="eyebrow">Content</div>
              <h1 className="heroTitle heroTitleSm">{isPost ? "Post detail" : "Content detail"}</h1>
              <p className="heroText">
                View the readable record first, then use author or moderation actions with explicit transaction-state expectations.
                Declared media renders inline, but final moderation or edit outcomes remain protocol-driven rather than instantaneous UI changes.
              </p>
            </div>
            <div className="heroInfoPanel">
              <div className="heroInfoTitle">Quick actions</div>
              <div className="heroInfoList">
                <button className="btn" onClick={() => nav("/feed")}>← Feed</button>
                {author ? <button className="btn" onClick={() => nav(`/account/${encodeURIComponent(author)}`)}>{author}</button> : null}
                {groupId ? <button className="btn" onClick={() => nav(`/groups/${encodeURIComponent(groupId)}`)}>Open group</button> : null}
                {isPost ? <button className="btn" onClick={() => nav(`/thread/${encodeURIComponent(postId)}`)}>Open thread</button> : null}
                <button className="btn" onClick={() => void load()}>Refresh</button>
              </div>
            </div>
          </div>

          <div className="surfaceSummaryGrid">
            <div className="surfaceSummaryCard">
              <span className="surfaceSummaryLabel">Viewer</span>
              <strong className="surfaceSummaryValue mono">{viewer || "Read-only"}</strong>
              <span className="surfaceSummaryHint">{viewer ? viewerSummary : "No local session is active on this device."}</span>
            </div>
            <div className="surfaceSummaryCard">
              <span className="surfaceSummaryLabel">Action readiness</span>
              <strong className="surfaceSummaryValue">{actionReadiness.title}</strong>
              <span className="surfaceSummaryHint">{actionReadiness.detail}</span>
            </div>
            <div className="surfaceSummaryCard">
              <span className="surfaceSummaryLabel">Visibility</span>
              <strong className="surfaceSummaryValue">{visibility}</strong>
              <span className="surfaceSummaryHint">{deleted ? "This item is marked deleted in the current payload." : "This record is visible under the current backend response."}</span>
            </div>
            <div className="surfaceSummaryCard">
              <span className="surfaceSummaryLabel">Protocol truth</span>
              <strong className="surfaceSummaryValue">Transaction-backed</strong>
              <span className="surfaceSummaryHint">Edit, delete, and flag actions submit transactions. Submission and final state should not be treated as the same event.</span>
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
                  <div className="eyebrow">Summary</div>
                  <h2 className="cardTitle">Content details</h2>
                </div>
                <span className="statusPill mono">{postId}</span>
              </div>

              <div className="infoGrid">
                <div className="infoCard compact">
                  <div className="infoCardHeader"><strong>Author</strong></div>
                  <div className="infoCardText">{author || "Unknown"}</div>
                </div>
                <div className="infoCard compact">
                  <div className="infoCardHeader"><strong>Created</strong></div>
                  <div className="infoCardText">{createdAt || "Unknown"}</div>
                </div>
                <div className="infoCard compact">
                  <div className="infoCardHeader"><strong>Group scope</strong></div>
                  <div className="infoCardText">{groupId || "No group scope"}</div>
                </div>
                <div className="infoCard compact">
                  <div className="infoCardHeader"><strong>Status</strong></div>
                  <div className="infoCardText">{deleted ? "Marked deleted" : "Active"}</div>
                </div>
              </div>

              {deleted ? (
                <div className="emptyPanel compact dangerTone">
                  <strong>This post is marked deleted.</strong>
                  <span>The record still exists for transparency, but it should no longer be treated as an active post.</span>
                </div>
              ) : null}

              {body ? (
                <div className="feedBodyText">{body}</div>
              ) : (
                <div className="emptyPanel compact">
                  <strong>No post body.</strong>
                  <span>This item currently has no readable text body.</span>
                </div>
              )}

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

          <section className="card">
            <div className="cardBody formStack">
              <div className="sectionHead">
                <div>
                  <div className="eyebrow">Viewer</div>
                  <h2 className="cardTitle">Account gates</h2>
                </div>
                <div className="statusSummary">
                  <span className={`statusPill ${gate.ok ? "ok" : ""}`}>{gate.ok ? "Tier 2 ready" : "Gated"}</span>
                  {!viewer ? (
                    <button className="btn" onClick={() => nav("/poh")}>Go to PoH</button>
                  ) : (
                    <button className="btn" onClick={refreshViewerState}>Refresh gates</button>
                  )}
                </div>
              </div>

              <div className="calloutInfo">
                <strong>{actionReadiness.title}</strong>
                <div style={{ marginTop: 6 }}>{actionReadiness.detail}</div>
              </div>

              {txErr ? <ErrorBanner message={txErr.msg} details={txErr.details} onDismiss={() => setTxErr(null)} /> : null}

              {txInfo ? (
                <div className="calloutInfo">
                  <div>{txInfo.msg}</div>
                  <div className="buttonRow" style={{ marginTop: 8 }}>
                    {txInfo.ctaHref ? <button className="btn" onClick={() => nav(String(txInfo.ctaHref))}>{txInfo.ctaLabel || "Open"}</button> : null}
                    <button className="btn" onClick={() => setTxInfo(null)}>Dismiss</button>
                  </div>
                </div>
              ) : null}
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

                <div className="surfaceSummaryGrid surfaceSummaryGridTight">
                  <div className="surfaceSummaryCard">
                    <span className="surfaceSummaryLabel">Edit</span>
                    <strong className="surfaceSummaryValue">{isOwner ? "Author-only" : "Unavailable"}</strong>
                    <span className="surfaceSummaryHint">Edits require the original author key and submit a post-edit transaction.</span>
                  </div>
                  <div className="surfaceSummaryCard">
                    <span className="surfaceSummaryLabel">Delete</span>
                    <strong className="surfaceSummaryValue">{isOwner ? "Author-only" : "Unavailable"}</strong>
                    <span className="surfaceSummaryHint">Deletion submits a transaction. Read surfaces may lag until indexes catch up.</span>
                  </div>
                  <div className="surfaceSummaryCard">
                    <span className="surfaceSummaryLabel">Flag</span>
                    <strong className="surfaceSummaryValue">{isOwner ? "Usually unnecessary" : gate.ok ? "Available" : "Blocked"}</strong>
                    <span className="surfaceSummaryHint">Flags are on-chain signals. They are not immediate moderation outcomes.</span>
                  </div>
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
                  <div className="formStack surfaceSubsection">
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
                    <div className="actionStateRow">
                      <span className="actionStateLabel">Edit truth</span>
                      <span className="actionStateText">Editing updates the on-chain post body and requires the original author key on this device.</span>
                    </div>
                  </div>
                ) : null}

                {flagOpen && !isOwner ? (
                  <div className="formStack surfaceSubsection">
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
                    <div className="actionStateRow">
                      <span className="actionStateLabel">Flag truth</span>
                      <span className="actionStateText">Flags are on-chain signals. Disputes and moderation outcomes are resolved by the network later.</span>
                    </div>
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
