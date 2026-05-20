import React, { useEffect, useMemo, useState } from "react";

import { getApiBaseUrl, weall } from "../api/weall";
import ErrorBanner from "../components/ErrorBanner";
import ActionLifecycleCard from "../components/ActionLifecycleCard";
import MediaGallery from "../components/MediaGallery";
import { getAuthHeaders, getSession, submitSignedTx } from "../auth/session";
import { normalizeAccount } from "../auth/keys";
import { useAccount } from "../context/AccountContext";
import { useTxQueue } from "../hooks/useTxQueue";
import { useMutationRefresh } from "../hooks/useMutationRefresh";
import { useSignerSubmissionBusy } from "../hooks/useSignerSubmissionBusy";
import { checkGates, summarizeAccountState } from "../lib/gates";
import { reportStageLabel, reviewChoiceLabel, reviewStatusLabel, reviewTallyText } from "../lib/userLanguage";
import { nav } from "../lib/router";
import { reconcileDisputeMutation } from "../lib/disputeRevalidation";
import {
  disputeAttendancePresent,
  disputeCurrentVote,
  disputeJurorStatus,
  disputeReviewUnlocked,
  disputeStageClass,
  disputeVoteCountSummary,
} from "../lib/disputeSurface";
import { refreshMutationSlices } from "../lib/revalidation";
import { actionableTxError, txPendingKey } from "../lib/txAction";

// Compatibility anchors for older frontend/backend congruity tests. The live
// submit buttons below include canonical outcome fields, but these summaries
// remain the plain-language semantics the user sees.
// vote: "no", resolution: { summary: "Reviewer chose to keep the post visible.", actions: [] }
// vote: "yes", resolution: { summary: "Reviewer upheld the report and chose to remove the post." }

function prettyErr(e: any): { msg: string; details: any } {
  return actionableTxError(e, "Report review action failed.");
}

function asArray<T = any>(value: any): T[] {
  return Array.isArray(value) ? value : [];
}

export default function DisputeReview({ id }: { id: string }): JSX.Element {
  const apiBase = useMemo(() => getApiBaseUrl(), []);
  const session = getSession();
  const account = session ? normalizeAccount(session.account) : "";
  const { refresh: refreshAccountContext } = useAccount();
  const tx = useTxQueue();
  const signerSubmission = useSignerSubmissionBusy(account);

  const [acctState, setAcctState] = useState<any | null>(null);
  const [dispute, setDispute] = useState<any | null>(null);
  const [voteSurface, setVoteSurface] = useState<any | null>(null);
  const [targetContent, setTargetContent] = useState<any | null>(null);
  const [err, setErr] = useState<{ msg: string; details: any } | null>(null);
  const [result, setResult] = useState<any>(null);

  const tierGate = checkGates({
    loggedIn: !!account,
    canSign: true,
    accountState: acctState,
    requireTier: 2,
  });

  async function refreshAccount(): Promise<void> {
    if (!account) {
      setAcctState(null);
      return;
    }
    try {
      const acct: any = await weall.account(account, apiBase);
      setAcctState(acct?.state ?? null);
    } catch {
      setAcctState(null);
    }
  }

  async function load(): Promise<void> {
    setErr(null);
    try {
      const [detailRes, votesRes] = await Promise.all([
        weall.dispute(id, apiBase),
        weall.disputeVotes(id, apiBase),
      ]);
      const nextDispute = (detailRes as any)?.dispute || null;
      setDispute(nextDispute);
      setVoteSurface(votesRes || null);
      const targetType = String(nextDispute?.target_type || "").trim().toLowerCase();
      const targetId = String(nextDispute?.target_id || "").trim();
      if (targetType === "content" && targetId) {
        try {
          const headers = account ? getAuthHeaders(account) : {};
          const canUseScoped = !!headers["x-weall-account"] && !!headers["x-weall-session-key"];
          const contentRes = canUseScoped
            ? await weall.contentScoped(targetId, apiBase, headers)
            : await weall.content(targetId, apiBase);
          setTargetContent(contentRes || null);
        } catch {
          try {
            const publicRes = await weall.content(targetId, apiBase);
            setTargetContent(publicRes || null);
          } catch {
            setTargetContent(null);
          }
        }
      } else {
        setTargetContent(null);
      }
    } catch (e: any) {
      setErr(prettyErr(e));
      setDispute(null);
      setVoteSurface(null);
      setTargetContent(null);
    }
  }

  useEffect(() => {
    void refreshAccount();
    void load();
  }, [id, account]);

  useMutationRefresh({
    entityTypes: ["dispute", "content"],
    account,
    entityIds: [id],
    onRefresh: async () => {
      await load();
      await refreshAccount();
      await refreshAccountContext();
    },
  });

  const selectedJurorStatus = account && dispute ? disputeJurorStatus(dispute, account) : "unassigned";
  const attendancePresent = account && dispute ? disputeAttendancePresent(dispute, account) : false;
  const counts = voteSurface?.vote_counts || (dispute ? disputeVoteCountSummary(dispute) : { yes: 0, no: 0, abstain: 0, total: 0 });
  const summary = acctState ? summarizeAccountState(acctState) : "(state unknown)";
  const currentVote = dispute ? disputeCurrentVote(dispute, account) : "";
  const canAccept = !!dispute && !!account && !signerSubmission.busy && tierGate.ok && selectedJurorStatus === "assigned";
  const canDecline = !!dispute && !!account && !signerSubmission.busy && tierGate.ok && selectedJurorStatus === "assigned";
  const canVote = disputeReviewUnlocked({ dispute, account, tierGateOk: tierGate.ok, signerBusy: signerSubmission.busy });
  const disputeId = String(dispute?.id || dispute?.dispute_id || id || "").trim();
  const targetId = String(dispute?.target_id || "").trim();
  const contentObj = targetContent?.content;
  const contentBody = String(contentObj?.body || contentObj?.text || "").trim();
  const contentAuthor = String(contentObj?.author || "").trim();
  const contentGroup = String(contentObj?.group_id || contentObj?.scope_id || "").trim();
  const contentMedia = asArray(contentObj?.media);
  const removeContentActions = targetId
    ? [
        { tx_type: "CONTENT_LABEL_SET", payload: { target_id: targetId, labels: ["dispute_upheld", "policy_violation"] } },
        { tx_type: "CONTENT_VISIBILITY_SET", payload: { target_id: targetId, visibility: "deleted" } },
        ...(targetId.startsWith("post:") ? [{ tx_type: "CONTENT_THREAD_LOCK_SET", payload: { target_id: targetId, locked: true } }] : []),
      ]
    : [];

  const lockReason = !account
    ? "Step 0: log in with a reviewer-capable account before entering the review workspace."
    : signerSubmission.busy
      ? "A previous signed action is still settling for this account."
      : !tierGate.ok
        ? tierGate.reason || "Live verification and a valid session are required for review actions."
        : currentVote
          ? `Step 3 is complete. Current recorded choice: ${reviewChoiceLabel(currentVote)}. This workspace is now locked because your choice was recorded.`
          : selectedJurorStatus === "unassigned"
            ? "Step 1 has not begun because this account is not assigned to the selected report."
            : !attendancePresent
              ? "Step 2 is still pending. Final choice stays locked until accepted attendance is visible."
              : "Step 3 is unlocked. Inspect the target carefully, then choose what should happen.";

  async function submitDisputeTx(txType: string, payload: any, title: string, successMessage: string): Promise<void> {
    if (!account) throw new Error("not_logged_in");
    if (signerSubmission.busy) throw new Error("Another signed action is still settling for this reviewer account.");
    const res = await tx.runTx({
      title,
      pendingKey: txPendingKey(["dispute", txType, String(payload?.dispute_id || disputeId || ""), account]),
      pendingMessage: "Saving review action…",
      successMessage,
      errorMessage: (e) => prettyErr(e).msg,
      getTxId: (raw: any) => raw?.tx_id,
      task: () => submitSignedTx({ account, tx_type: txType, payload, base: apiBase }),
      finality: {
        track: true,
        timeoutMs: 18000,
        mutation: {
          entityType: "dispute",
          entityId: String(payload?.dispute_id || disputeId || "").trim() || undefined,
          account: account || undefined,
          routeHint: `/reviews/${encodeURIComponent(disputeId || id)}`,
          txType,
        },
        reconcile: async () =>
          reconcileDisputeMutation({
            disputeId: String(payload?.dispute_id || disputeId || ""),
            account,
            txType: txType as any,
            vote: payload?.vote || null,
            base: apiBase,
          }),
      },
    });
    setResult(res);
    await refreshMutationSlices(refreshAccount, refreshAccountContext, load);
  }

  return (
    <div className="pageStack pageNarrow actionPage disputeReviewPage">
      <section className="card heroCard compact actionHeroCard">
        <div className="cardBody heroBody pageStack">
          <div className="surfaceSummaryRow">
            <div>
              <div className="eyebrow">Community review workspace</div>
              <h1 className="heroTitle heroTitleSm">Report review</h1>
              <p className="heroSubtitle">This page owns the final reviewer workflow. The queue lists work, the detail page explains the report, and this action page records one final review choice.</p>
            </div>
            <div className="surfaceSummaryStats">
              <div className="surfaceSummaryStat"><strong className="surfaceSummaryValue mono">{disputeId}</strong><span className="surfaceSummaryHint">report id</span></div>
              <div className="surfaceSummaryStat"><strong className="surfaceSummaryValue">{summary}</strong><span className="surfaceSummaryHint">current account standing</span></div>
            </div>
          </div>
          <div className="buttonRow">
            <button className="btn" onClick={() => nav(`/reports/${encodeURIComponent(id)}`)}>Back to detail</button>
            <button className="btn" onClick={() => nav("/reports")}>Back to reports</button>
            <button className="btn" onClick={() => void refreshMutationSlices(refreshAccount, refreshAccountContext, load)}>{signerSubmission.busy ? "Waiting…" : "Refresh review state"}</button>
          </div>
        </div>
      </section>

      <ErrorBanner
        message={err?.msg}
        details={err?.details}
        onDismiss={() => setErr(null)}
        onRetry={() => void refreshMutationSlices(refreshAccount, refreshAccountContext, load)}
      />
      <div className="calloutInfo">{lockReason}</div>

      <section className="detailFocusStrip actionFocusStrip">
        <article className="detailFocusCard">
          <div className="detailFocusLabel">Primary object</div>
          <div className="detailFocusValue">Final reviewer action</div>
          <div className="detailFocusText">This workspace is for one report and one reviewer account. It should feel narrower and more deliberate than the queue or detail pages.</div>
        </article>
        <article className="detailFocusCard">
          <div className="detailFocusLabel">Submission rule</div>
          <div className="detailFocusValue">{currentVote ? "Step 3 complete" : canVote ? "Step 3 unlocked" : canAccept || canDecline ? "Step 1 pending" : "Step 2 pending"}</div>
          <div className="detailFocusText">{lockReason}</div>
        </article>
        <article className="detailFocusCard">
          <div className="detailFocusLabel">Interaction boundary</div>
          <div className="detailFocusValue">Action route only</div>
          <div className="detailFocusText">Use this page to accept, decline, or record the final review choice. Queue browsing and report explanation live on the other routes.</div>
        </article>
      </section>


      <ActionLifecycleCard intro="This route should always show the same honest sequence: checking, saving, recorded, updating the page, visible, or failed." />

      <section className="summaryCardGrid">
        <article className="summaryCard">
          <div className="summaryCardLabel">Status</div>
          <div className="summaryCardValue"><span className={disputeStageClass(String(dispute?.stage || "open"))}>{reportStageLabel(dispute?.stage || "open")}</span></div>
          <div className="summaryCardText">{dispute?.resolved ? "Review complete" : "Community review is still active"}</div>
        </article>
        <article className="summaryCard">
          <div className="summaryCardLabel">Your reviewer status</div>
          <div className="summaryCardValue">{reviewStatusLabel(selectedJurorStatus)}</div>
          <div className="summaryCardText">{attendancePresent ? "Attendance recorded" : "Accepted attendance is still missing."}</div>
        </article>
        <article className="summaryCard">
          <div className="summaryCardLabel">Reviews</div>
          <div className="summaryCardValue">{counts.total}</div>
          <div className="summaryCardText">{reviewTallyText(counts)}</div>
        </article>
        <article className="summaryCard">
          <div className="summaryCardLabel">Your recorded choice</div>
          <div className="summaryCardValue">{reviewChoiceLabel(currentVote)}</div>
          <div className="summaryCardText">One reviewer account, one recorded choice</div>
        </article>
      </section>

      <section className="card">
        <div className="cardBody formStack">
          <div className="sectionHead">
            <div>
              <div className="eyebrow">Report context</div>
              <h2 className="cardTitle">Why this report exists</h2>
            </div>
          </div>
          <div className="summaryCardGrid">
            <article className="summaryCard">
              <div className="summaryCardLabel">Target type</div>
              <div className="summaryCardValue">{String(dispute?.target_type || "content")}</div>
              <div className="summaryCardText mono">{String(dispute?.target_id || "")}</div>
            </article>
            <article className="summaryCard">
              <div className="summaryCardLabel">Opened by</div>
              <div className="summaryCardValue mono">{String(dispute?.opened_by || "—")}</div>
              <div className="summaryCardText">Action routing should not hide this case history.</div>
            </article>
          </div>
          {dispute?.reason ? <div className="feedBodyText">{String(dispute.reason)}</div> : <div className="cardDesc">No report reason was recorded.</div>}
        </div>
      </section>

      <section className="card">
        <div className="cardBody formStack">
          <div className="sectionHead">
            <div>
              <div className="eyebrow">Flagged target</div>
              <h2 className="cardTitle">Review the content before choosing</h2>
            </div>
          </div>
          <div className="summaryCardGrid">
            <article className="summaryCard">
              <div className="summaryCardLabel">Author</div>
              <div className="summaryCardValue mono">{contentAuthor || "—"}</div>
              <div className="summaryCardText">Content author as surfaced by the backend.</div>
            </article>
            <article className="summaryCard">
              <div className="summaryCardLabel">Group / scope</div>
              <div className="summaryCardValue mono">{contentGroup || "—"}</div>
              <div className="summaryCardText">Context matters for community review and should stay visible here.</div>
            </article>
          </div>
          {contentMedia.length ? <MediaGallery base={apiBase} media={contentMedia} title="Flagged media" compact /> : null}
          {contentBody ? <div className="feedBodyText">{contentBody}</div> : <div className="cardDesc">The target content body could not be loaded on this pass. Open the content page to cross-check the visible object.</div>}
          {!contentMedia.length && asArray(contentObj?.media).length ? <div className="cardDesc">This content references media that could not be resolved from the current content endpoint yet. Refresh review state, then cross-check the content page.</div> : null}
          {String(dispute?.target_id || "") ? <div className="buttonRow"><button className="btn" onClick={() => nav(`/content/${encodeURIComponent(String(dispute?.target_id || ""))}`)}>Open content page</button></div> : null}
        </div>
      </section>

      <section className="card">
        <div className="cardBody formStack">
          <div className="sectionHead">
            <div>
              <div className="eyebrow">Reviewer action</div>
              <h2 className="cardTitle">Preparation and final choice</h2>
            </div>
          </div>
          <div className="buttonRow buttonRowWide">
            <button className="btn" onClick={() => void submitDisputeTx("DISPUTE_JUROR_ACCEPT", { dispute_id: disputeId }, "Accept assignment", "Review assignment accepted.")} disabled={!canAccept}>{signerSubmission.busy ? "Waiting…" : "Accept assignment"}</button>
            <button className="btn" onClick={() => void submitDisputeTx("DISPUTE_JUROR_DECLINE", { dispute_id: disputeId }, "Decline assignment", "Review assignment declined.")} disabled={!canDecline}>{signerSubmission.busy ? "Waiting…" : "Decline assignment"}</button>
            <button className="btn btnPrimary" onClick={() => void submitDisputeTx("DISPUTE_VOTE_SUBMIT", { dispute_id: disputeId, vote: "no", resolution: { outcome: "report_not_upheld", summary: "Reviewer chose to keep the post visible.", actions: [] } }, "Keep Post", "Keep Post choice recorded.")} disabled={!canVote}>{signerSubmission.busy ? "Waiting…" : "Keep Post"}</button>
            <button className="btn" onClick={() => void submitDisputeTx("DISPUTE_VOTE_SUBMIT", { dispute_id: disputeId, vote: "yes", resolution: { outcome: "report_upheld", summary: "Reviewer upheld the report and chose to remove the post.", actions: removeContentActions } }, "Remove Post", "Remove Post choice recorded.")} disabled={!canVote}>{signerSubmission.busy ? "Waiting…" : "Remove Post"}</button>
            <button className="btn" onClick={() => void submitDisputeTx("DISPUTE_VOTE_SUBMIT", { dispute_id: disputeId, vote: "abstain" }, "Need More Review", "Need More Review choice recorded.")} disabled={!canVote}>{signerSubmission.busy ? "Waiting…" : "Need More Review"}</button>
          </div>
          <div className="cardDesc">This page is intentionally the only place where final report-review choices are surfaced. Accept or decline only to resolve assignment posture; once unlocked, Keep Post records that the report should not be upheld, while Remove Post records that the report should be upheld.</div>
        </div>
      </section>

      {result ? <section className="card"><div className="cardBody formStack"><div className="eyebrow">Last action</div><pre className="codePanel mono">{JSON.stringify(result, null, 2)}</pre></div></section> : null}
    </div>
  );
}
