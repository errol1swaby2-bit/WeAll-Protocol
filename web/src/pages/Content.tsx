import React, { useEffect, useMemo, useState } from "react";

import { getApiBaseUrl, weall } from "../api/weall";
import ErrorBanner from "../components/ErrorBanner";
import MediaGallery from "../components/MediaGallery";
import { useSignerSubmissionBusy } from "../hooks/useSignerSubmissionBusy";
import { nav } from "../lib/router";
import { getAuthHeaders, getKeypair, getSession, submitSignedTx } from "../auth/session";
import { normalizeAccount } from "../auth/keys";
import { checkGates, summarizeAccountState } from "../lib/gates";
import { useTxQueue } from "../hooks/useTxQueue";
import { useMutationRefresh } from "../hooks/useMutationRefresh";
import { useAccount } from "../context/AccountContext";
import { actionableTxError, txPendingKey } from "../lib/txAction";
import { refreshMutationSlices } from "../lib/revalidation";

function prettyErr(e: any): { msg: string; details: any } | null {
  if (!e) return null as any;
  return actionableTxError(e, "This post action could not be completed.");
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
      title: "Read-only view",
      detail: "You can read this post now. Sign in before editing, deleting, or reporting.",
    };
  }
  if (!args.gateOk) {
    return {
      title: "More actions locked",
      detail: `The current viewer is ${args.viewerSummary}. Complete live verification before higher-trust actions are available.`,
    };
  }
  if (args.isOwner) {
    return {
      title: "Author controls available",
      detail: "Edits and deletion require the original author key on this device.",
    };
  }
  return {
    title: "Report action available",
    detail: "Reports send the post for community review. Reporting does not decide the outcome by itself.",
  };
}

export default function Content({ id }: { id: string }): JSX.Element {
  const base = useMemo(() => getApiBaseUrl(), []);
  const tx = useTxQueue();
  const { refresh: refreshAccountContext } = useAccount();
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

  const [flagOpen, setReportOpen] = useState(false);
  const [flagReason, setReportReason] = useState("");

  const routeContentId = String(id || "").trim();

  useMutationRefresh({
    entityTypes: ["content", "dispute"],
    entityIds: [routeContentId],
    account: viewer,
    onRefresh: async () => {
      await load();
    },
  });

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
      const activeSession = getSession();
      const activeAccount = activeSession ? normalizeAccount(activeSession.account) : "";
      const headers = activeAccount ? getAuthHeaders(activeAccount) : undefined;
      let r: any;
      try {
        // Prefer the scoped read path when the viewer has a session so group posts
        // opened from a group feed do not fall back to the public feed and appear
        // missing merely because their visibility is `group`.
        r = headers ? await weall.contentScoped(routeContentId, base, headers) : await weall.content(routeContentId, base);
      } catch (scopedErr: any) {
        if (!headers) throw scopedErr;
        r = await weall.content(routeContentId, base);
      }
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
  const loadedPostId = String(c?.post_id || id);
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
        pendingKey: txPendingKey(["content-edit", loadedPostId, viewer]),
        pendingMessage: "Saving your edit…",
        successMessage: "Your edit was saved. Feed updates may take a moment to catch up.",
        errorMessage: (e) => prettyErr(e)?.msg || "error",
        getTxId: (res: any) => String(res?.tx_id || res?.result?.tx_id || "") || undefined,
        finality: { mutation: { entityType: "content", entityId: loadedPostId, account: viewer || undefined, routeHint: `/content/${encodeURIComponent(loadedPostId)}`, txType: "CONTENT_POST_EDIT" } },
        task: async () =>
          submitSignedTx({
            account: viewer,
            tx_type: "CONTENT_POST_EDIT",
            payload: { post_id: loadedPostId, body: nextBody },
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
        pendingKey: txPendingKey(["content-delete", loadedPostId, viewer]),
        pendingMessage: "Deleting this post…",
        successMessage: "Delete request was saved. Some views may take a moment to update.",
        errorMessage: (e) => prettyErr(e)?.msg || "error",
        getTxId: (res: any) => String(res?.tx_id || res?.result?.tx_id || "") || undefined,
        finality: { mutation: { entityType: "content", entityId: loadedPostId, account: viewer || undefined, routeHint: `/content/${encodeURIComponent(loadedPostId)}`, txType: "CONTENT_POST_DELETE" } },
        task: async () =>
          submitSignedTx({
            account: viewer,
            tx_type: "CONTENT_POST_DELETE",
            payload: { post_id: loadedPostId },
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

  async function doReport() {
    setTxErr(null);
    setTxInfo(null);
    if (!viewer) return setTxErr({ msg: "not_logged_in", details: null });
    if (!gate.ok) return setTxErr({ msg: gate.reason || "gated", details: viewerState });

    const reason = (flagReason || "").trim();

    setTxBusy(true);
    try {
      await tx.runTx({
        title: "Report content",
        pendingKey: txPendingKey(["content-flag", loadedPostId, viewer]),
        pendingMessage: "Sending your report…",
        successMessage: "Report submitted. Track confirmation in Transactions while community review visibility refreshes…",
        errorMessage: (e) => prettyErr(e)?.msg || "error",
        getTxId: (res: any) => String(res?.tx_id || res?.result?.tx_id || "") || undefined,
        finality: { mutation: { entityType: "content", entityId: loadedPostId, account: viewer || undefined, routeHint: `/content/${encodeURIComponent(loadedPostId)}`, txType: "CONTENT_FLAG" } },
        task: async () =>
          submitSignedTx({
            account: viewer,
            tx_type: "CONTENT_FLAG",
            payload: reason ? { target_id: loadedPostId, reason } : { target_id: loadedPostId },
            parent: null,
            base,
          }),
      });
      setReportOpen(false);
      setReportReason("");
      await load();
      const dispute = linkedDisputeId
        ? { id: linkedDisputeId, target_id: loadedPostId }
        : await waitForDisputeForTarget(base, loadedPostId);
      await load();
      if (dispute?.id) {
        const disputeId = String(dispute.id);
        setTxInfo({
          msg: `Report submitted and community review ${disputeId} is now visible. Track confirmation in Transactions, then open it directly to continue the review flow.`,
          details: dispute,
          ctaLabel: "Open report",
          ctaHref: `/reports/${encodeURIComponent(disputeId)}`,
        });
      } else {
        setTxInfo({
          msg: "Report submitted. Community review may still be setting up; reopen this page or refresh Reports if it does not appear immediately. Track confirmation in Transactions.",
          details: { target_id: loadedPostId },
          ctaLabel: "Open reports",
          ctaHref: "/reports",
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
                View the public-readable post first, then use author or report actions with clear transaction-status feedback.
                Media renders inline, while final review or edit outcomes may take a moment to update everywhere.
              </p>
            </div>
            <div className="heroInfoPanel">
              <div className="heroInfoTitle">Quick actions</div>
              <div className="heroInfoList">
                <button className="btn" onClick={() => nav("/feed")}>← Feed</button>
                {author ? <button className="btn" onClick={() => nav(`/account/${encodeURIComponent(author)}`)}>{author}</button> : null}
                {groupId ? <button className="btn" onClick={() => nav(`/groups/${encodeURIComponent(groupId)}`)}>Open group</button> : null}
                {isPost ? <button className="btn" onClick={() => nav(`/thread/${encodeURIComponent(loadedPostId)}`)}>Open thread</button> : null}
                <button className="btn" onClick={() => void refreshMutationSlices(load, refreshViewerState, refreshAccountContext)}>Refresh</button>
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
              <span className="surfaceSummaryLabel">Action status</span>
              <strong className="surfaceSummaryValue">Tracked by tx status</strong>
              <span className="surfaceSummaryHint">Edits, deletes, and reports show submission progress first, then this page refreshes when confirmed or visibly reconciled state catches up.</span>
            </div>
          </div>
        </div>
      </section>

      <ErrorBanner message={err?.msg} details={err?.details} onRetry={() => void refreshMutationSlices(load, refreshViewerState, refreshAccountContext)} onDismiss={() => setErr(null)} />

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
                <button className="btn" onClick={() => void refreshMutationSlices(load, refreshViewerState, refreshAccountContext)}>Try again</button>
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
                <span className="statusPill mono">{loadedPostId}</span>
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
                  <span className={`statusPill ${gate.ok ? "ok" : ""}`}>{gate.ok ? "Live verification ready" : "Needs verification"}</span>
                  {!viewer ? (
                    <button className="btn" onClick={() => nav("/verification")}>Open Account Verification</button>
                  ) : (
                    <button className="btn" onClick={() => void refreshMutationSlices(refreshViewerState, refreshAccountContext, load)}>Refresh gates</button>
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
                  <span className="statusPill">{gate.ok ? "Ready" : gate.reason}</span>
                </div>

                <div className="surfaceSummaryGrid surfaceSummaryGridTight">
                  <div className="surfaceSummaryCard">
                    <span className="surfaceSummaryLabel">Edit</span>
                    <strong className="surfaceSummaryValue">{isOwner ? "Author-only" : "Unavailable"}</strong>
                    <span className="surfaceSummaryHint">Edits require the original author key on this device and remain pending until transaction status or visible state catches up.</span>
                  </div>
                  <div className="surfaceSummaryCard">
                    <span className="surfaceSummaryLabel">Delete</span>
                    <strong className="surfaceSummaryValue">{isOwner ? "Author-only" : "Unavailable"}</strong>
                    <span className="surfaceSummaryHint">Deletion is submitted as a signed transaction. Read surfaces may take a moment to update after confirmation.</span>
                  </div>
                  <div className="surfaceSummaryCard">
                    <span className="surfaceSummaryLabel">Report</span>
                    <strong className="surfaceSummaryValue">{isOwner ? "Usually unnecessary" : gate.ok ? "Available" : "Blocked"}</strong>
                    <span className="surfaceSummaryHint">Reports start community review. They are not immediate moderation outcomes.</span>
                  </div>
                </div>

                <div className="buttonRow buttonRowWide">
                  {isOwner ? (
                    <>
                      <button className="btn" onClick={() => setEditOpen((v) => !v)} disabled={!gate.ok}>{editOpen ? "Close edit" : "Edit"}</button>
                      <button className="btn btnDanger" onClick={doDelete} disabled={!gate.ok || txBusy}>{txBusy ? "Working…" : "Delete"}</button>
                    </>
                  ) : (
                    <button className="btn" onClick={() => setReportOpen((v) => !v)} disabled={!gate.ok}>{flagOpen ? "Close flag" : "Report"}</button>
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
                      <span className="actionStateText">Editing submits a signed CONTENT_POST_EDIT transaction and requires the original author key on this device.</span>
                    </div>
                  </div>
                ) : null}

                {flagOpen && !isOwner ? (
                  <div className="formStack surfaceSubsection">
                    <input
                      className="input"
                      value={flagReason}
                      onChange={(e) => setReportReason(e.target.value)}
                      placeholder="Reason (e.g., spam, harassment, illegal content)"
                    />
                    <div className="buttonRow buttonRowWide">
                      <button className="btn btnPrimary" onClick={doReport} disabled={!gate.ok || txBusy}>{txBusy ? "Submitting…" : "Send report"}</button>
                      <button className="btn" onClick={() => setReportOpen(false)} disabled={txBusy}>Cancel</button>
                    </div>
                    <div className="actionStateRow">
                      <span className="actionStateLabel">Report status</span>
                      <span className="actionStateText">Reports are sent for community review. Review outcomes are resolved after the required account and reviewer checks pass.</span>
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
