import React, { useEffect, useMemo, useState } from "react";

import { getApiBaseUrl, weall } from "../api/weall";
import ErrorBanner from "../components/ErrorBanner";
import ActionLifecycleCard from "../components/ActionLifecycleCard";
import { getSession, submitSignedTx } from "../auth/session";
import { normalizeAccount } from "../auth/keys";
import { useAccount } from "../context/AccountContext";
import { useTxQueue } from "../hooks/useTxQueue";
import { useMutationRefresh } from "../hooks/useMutationRefresh";
import { useSignerSubmissionBusy } from "../hooks/useSignerSubmissionBusy";
import { checkGates, summarizeAccountState } from "../lib/gates";
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

function prettyErr(e: any): { msg: string; details: any } {
  return actionableTxError(e, "Dispute review action failed.");
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
    requireTier: 3,
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
      const [detailRes, votesRes] = await Promise.all([weall.dispute(id, apiBase), weall.disputeVotes(id, apiBase)]);
      const nextDispute = (detailRes as any)?.dispute || null;
      setDispute(nextDispute);
      setVoteSurface(votesRes || null);
      const targetType = String(nextDispute?.target_type || "").trim().toLowerCase();
      const targetId = String(nextDispute?.target_id || "").trim();
      if (targetType === "content" && targetId) {
        try {
          const contentRes = await weall.content(targetId, apiBase);
          setTargetContent(contentRes || null);
        } catch {
          setTargetContent(null);
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
  const contentObj = targetContent?.content;
  const contentBody = String(contentObj?.body || contentObj?.text || "").trim();
  const contentAuthor = String(contentObj?.author || "").trim();
  const contentGroup = String(contentObj?.group_id || contentObj?.scope_id || "").trim();

  const lockReason = !account
    ? "Step 0: log in with a juror-capable account before entering the review workspace."
    : signerSubmission.busy
      ? "A previous signed action is still settling for this account."
      : !tierGate.ok
        ? tierGate.reason || "Tier 3 and signer posture are required for juror review actions."
        : currentVote
          ? `Step 3 is complete. Current signer vote: ${currentVote.toUpperCase()}. This workspace is now locked for one-shot voting.`
          : selectedJurorStatus === "unassigned"
            ? "Step 1 has not begun because this account is not assigned to the selected dispute."
            : !attendancePresent
              ? "Step 2 is still pending. Final voting stays locked until accepted attendance is visible in authoritative dispute state."
              : "Step 3 is unlocked. Inspect the target carefully, then cast one final vote.";

  async function submitDisputeTx(txType: string, payload: any, title: string, successMessage: string): Promise<void> {
    if (!account) throw new Error("not_logged_in");
    if (signerSubmission.busy) throw new Error("Another signed action is still settling for this juror account.");
    const res = await tx.runTx({
      title,
      pendingKey: txPendingKey(["dispute", txType, String(payload?.dispute_id || id || ""), account]),
      pendingMessage: "Submitting dispute action…",
      successMessage,
      errorMessage: (e) => prettyErr(e).msg,
      getTxId: (raw: any) => raw?.tx_id,
      task: () => submitSignedTx({ account, tx_type: txType, payload, base: apiBase }),
      finality: {
        track: true,
        timeoutMs: 18000,
        mutation: {
          entityType: "dispute",
          entityId: String(payload?.dispute_id || id || "").trim() || undefined,
          account: account || undefined,
          routeHint: `/disputes/${encodeURIComponent(id)}/review`,
          txType,
        },
        reconcile: async () =>
          reconcileDisputeMutation({
            disputeId: String(payload?.dispute_id || id || ""),
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
              <div className="eyebrow">Juror action workspace</div>
              <h1 className="heroTitle heroTitleSm">Dispute review</h1>
              <p className="heroSubtitle">This page owns the final juror workflow. The queue lists work, the detail page explains the case, and this action page performs the one-shot review decision.</p>
            </div>
            <div className="surfaceSummaryStats">
              <div className="surfaceSummaryStat"><strong className="surfaceSummaryValue mono">{String(dispute?.id || id)}</strong><span className="surfaceSummaryHint">dispute id</span></div>
              <div className="surfaceSummaryStat"><strong className="surfaceSummaryValue">{summary}</strong><span className="surfaceSummaryHint">current account standing</span></div>
            </div>
          </div>
          <div className="buttonRow">
            <button className="btn" onClick={() => nav(`/disputes/${encodeURIComponent(id)}`)}>Back to detail</button>
            <button className="btn" onClick={() => nav("/disputes")}>Back to disputes</button>
            <button className="btn" onClick={() => void refreshMutationSlices(refreshAccount, refreshAccountContext, load)}>{signerSubmission.busy ? "Waiting for signer…" : "Refresh review state"}</button>
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
          <div className="detailFocusValue">Final juror action</div>
          <div className="detailFocusText">This workspace is for one dispute and one signer. It should feel narrower and more deliberate than the queue or detail surfaces.</div>
        </article>
        <article className="detailFocusCard">
          <div className="detailFocusLabel">Submission rule</div>
          <div className="detailFocusValue">{currentVote ? "Step 3 complete" : canVote ? "Step 3 unlocked" : canAccept || canDecline ? "Step 1 pending" : "Step 2 pending"}</div>
          <div className="detailFocusText">{lockReason}</div>
        </article>
        <article className="detailFocusCard">
          <div className="detailFocusLabel">Interaction boundary</div>
          <div className="detailFocusValue">Action route only</div>
          <div className="detailFocusText">Use this page to accept, decline, or cast the final vote. Queue browsing and case explanation live on the other routes.</div>
        </article>
      </section>


      <ActionLifecycleCard intro="This route should always show the same honest sequence: validating, submitting, recorded, reconciling, visible confirmed, or failed." />

      <section className="summaryCardGrid">
        <article className="summaryCard">
          <div className="summaryCardLabel">Stage</div>
          <div className="summaryCardValue"><span className={disputeStageClass(String(dispute?.stage || "open"))}>{String(dispute?.stage || "open")}</span></div>
          <div className="summaryCardText">resolved: {String(!!dispute?.resolved)}</div>
        </article>
        <article className="summaryCard">
          <div className="summaryCardLabel">Your juror status</div>
          <div className="summaryCardValue">{selectedJurorStatus}</div>
          <div className="summaryCardText">{attendancePresent ? "Attendance recorded" : "Accepted attendance is still missing from authoritative dispute state."}</div>
        </article>
        <article className="summaryCard">
          <div className="summaryCardLabel">Votes</div>
          <div className="summaryCardValue">{counts.total}</div>
          <div className="summaryCardText">YES {counts.yes} · NO {counts.no} · ABSTAIN {counts.abstain}</div>
        </article>
        <article className="summaryCard">
          <div className="summaryCardLabel">Current signer vote</div>
          <div className="summaryCardValue">{currentVote ? currentVote.toUpperCase() : "None"}</div>
          <div className="summaryCardText">One signer, one recorded vote</div>
        </article>
      </section>

      <section className="card">
        <div className="cardBody formStack">
          <div className="sectionHead">
            <div>
              <div className="eyebrow">Flag context</div>
              <h2 className="cardTitle">Why this dispute exists</h2>
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
          {dispute?.reason ? <div className="feedBodyText">{String(dispute.reason)}</div> : <div className="cardDesc">No dispute reason was recorded.</div>}
        </div>
      </section>

      <section className="card">
        <div className="cardBody formStack">
          <div className="sectionHead">
            <div>
              <div className="eyebrow">Flagged target</div>
              <h2 className="cardTitle">Review the content before voting</h2>
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
              <div className="summaryCardText">Context matters for juror review and should stay visible here.</div>
            </article>
          </div>
          {contentBody ? <div className="feedBodyText">{contentBody}</div> : <div className="cardDesc">The target content body could not be loaded on this pass. Open the content page to cross-check the visible object.</div>}
          {String(dispute?.target_id || "") ? <div className="buttonRow"><button className="btn" onClick={() => nav(`/content/${encodeURIComponent(String(dispute?.target_id || ""))}`)}>Open content page</button></div> : null}
        </div>
      </section>

      <section className="card">
        <div className="cardBody formStack">
          <div className="sectionHead">
            <div>
              <div className="eyebrow">Juror action</div>
              <h2 className="cardTitle">Preparation and final vote</h2>
            </div>
          </div>
          <div className="buttonRow buttonRowWide">
            <button className="btn" onClick={() => void submitDisputeTx("DISPUTE_JUROR_ACCEPT", { dispute_id: dispute.id }, "Accept dispute", "Dispute accepted.")} disabled={!canAccept}>{signerSubmission.busy ? "Waiting…" : "Accept assignment"}</button>
            <button className="btn" onClick={() => void submitDisputeTx("DISPUTE_JUROR_DECLINE", { dispute_id: dispute.id }, "Decline dispute", "Dispute declined.")} disabled={!canDecline}>{signerSubmission.busy ? "Waiting…" : "Decline assignment"}</button>
            <button className="btn btnPrimary" onClick={() => void submitDisputeTx("DISPUTE_VOTE_SUBMIT", { dispute_id: dispute.id, vote: "yes" }, "Vote yes", "YES vote submitted.")} disabled={!canVote}>{signerSubmission.busy ? "Waiting…" : "Vote yes"}</button>
            <button className="btn" onClick={() => void submitDisputeTx("DISPUTE_VOTE_SUBMIT", { dispute_id: dispute.id, vote: "no" }, "Vote no", "NO vote submitted.")} disabled={!canVote}>{signerSubmission.busy ? "Waiting…" : "Vote no"}</button>
            <button className="btn" onClick={() => void submitDisputeTx("DISPUTE_VOTE_SUBMIT", { dispute_id: dispute.id, vote: "abstain" }, "Vote abstain", "Abstain vote submitted.")} disabled={!canVote}>{signerSubmission.busy ? "Waiting…" : "Vote abstain"}</button>
          </div>
          <div className="cardDesc">This page is intentionally the only place where final dispute votes are surfaced. Accept or decline only to resolve assignment posture; once unlocked, the one-shot vote is the dominant action.</div>
        </div>
      </section>

      {result ? <section className="card"><div className="cardBody formStack"><div className="eyebrow">Last action</div><pre className="codePanel mono">{JSON.stringify(result, null, 2)}</pre></div></section> : null}
    </div>
  );
}
