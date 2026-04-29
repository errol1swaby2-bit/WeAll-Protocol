import React, { useEffect, useMemo, useState } from "react";

import { getApiBaseUrl, weall } from "../api/weall";
import ErrorBanner from "../components/ErrorBanner";
import { getSession, submitSignedTx } from "../auth/session";
import { normalizeAccount } from "../auth/keys";
import { checkGates, summarizeAccountState } from "../lib/gates";
import { nav } from "../lib/router";
import { useAccount } from "../context/AccountContext";
import { useTxQueue } from "../hooks/useTxQueue";
import { useMutationRefresh } from "../hooks/useMutationRefresh";
import { useSignerSubmissionBusy } from "../hooks/useSignerSubmissionBusy";
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
  return actionableTxError(e, "Dispute action failed.");
}

function asRecord(value: any): Record<string, any> {
  return value && typeof value === "object" && !Array.isArray(value) ? value : {};
}

function fmtNonce(v: any): string {
  const n = Number(v);
  return Number.isFinite(n) && n > 0 ? String(Math.floor(n)) : "—";
}


function disputeActionHint(args: {
  account: string;
  tierGateOk: boolean;
  tierGateReason: string;
  jurorStatus: string;
  attendancePresent: boolean;
  signerBusy: boolean;
  currentVote: string;
}): string {
  const { account, tierGateOk, tierGateReason, jurorStatus, attendancePresent, signerBusy, currentVote } = args;
  if (!account) return "Log in to take dispute actions.";
  if (signerBusy) return "Another signed action is still settling for this account.";
  if (!tierGateOk) return tierGateReason || "Tier 3 access and a local signer are required for juror actions.";
  if (jurorStatus === "unassigned") return "This dispute is visible, but your account is not assigned as a juror on it.";
  if (jurorStatus === "declined") return "You declined this juror assignment. No further actions are available from this account.";
  if (jurorStatus === "assigned") return "Step 1 of 3: respond to the assignment here. Final voting stays on the dedicated review page.";
  if ((jurorStatus === "accepted" || jurorStatus === "review") && !attendancePresent) return "Step 2 of 3: accepted attendance must appear in authoritative dispute state before the final vote unlocks.";
  if (currentVote) return `Step 3 of 3 is complete. Your recorded dispute vote is ${currentVote.toUpperCase()}, and this signer is now locked for further voting.`;
  return "Step 3 of 3: inspect the flagged content and reason here, then continue into the dedicated review workspace for the final vote.";
}

export default function DisputeDetail({ id }: { id: string }): JSX.Element {
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
    account: account,
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
  const reviewUnlocked = disputeReviewUnlocked({ dispute, account, tierGateOk: tierGate.ok, signerBusy: signerSubmission.busy });
  const hint = disputeActionHint({
    account,
    tierGateOk: tierGate.ok,
    tierGateReason: tierGate.reason || "",
    jurorStatus: selectedJurorStatus,
    attendancePresent,
    signerBusy: signerSubmission.busy,
    currentVote,
  });
  const contentObj = targetContent?.content;
  const contentBody = String(contentObj?.body || contentObj?.text || "").trim();
  const contentAuthor = String(contentObj?.author || "").trim();
  const contentGroup = String(contentObj?.group_id || contentObj?.scope_id || "").trim();

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
          routeHint: `/disputes/${encodeURIComponent(id)}`,
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
    <div className="pageStack pageNarrow detailPage disputeDetailPage">
      <section className="card heroCard compact detailHeroCard">
        <div className="cardBody heroBody pageStack">
          <div className="surfaceSummaryRow">
            <div>
              <div className="eyebrow">Juror review</div>
              <h1 className="heroTitle heroTitleSm">Dispute detail</h1>
              <p className="heroSubtitle">Inspect the case, verify the flagged content, and handle assignment posture here. Final juror voting stays in the dedicated review workspace.</p>
            </div>
            <div className="surfaceSummaryStats">
              <div className="surfaceSummaryStat"><strong className="surfaceSummaryValue mono">{String(dispute?.id || id)}</strong><span className="surfaceSummaryHint">dispute id</span></div>
              <div className="surfaceSummaryStat"><strong className="surfaceSummaryValue">{summary}</strong><span className="surfaceSummaryHint">current account standing</span></div>
            </div>
          </div>
          <div className="buttonRow">
            <button className="btn" onClick={() => nav("/disputes")}>Back to disputes</button>
            <button className="btn" onClick={() => void refreshMutationSlices(refreshAccount, refreshAccountContext, load)}>{signerSubmission.busy ? "Waiting for signer…" : "Refresh dispute"}</button>
            {String(dispute?.target_id || "") ? (
              <button className="btn" onClick={() => nav(`/content/${encodeURIComponent(String(dispute?.target_id || ""))}`)}>Open content page</button>
            ) : null}
          </div>
        </div>
      </section>

      <ErrorBanner message={err?.msg} details={err?.details} onDismiss={() => setErr(null)} onRetry={() => void refreshMutationSlices(refreshAccount, refreshAccountContext, load)} />

      {signerSubmission.busy ? <div className="calloutInfo">Another signed action is still settling. Juror actions stay serialized so signer nonces remain monotonic.</div> : null}

      <section className="detailFocusStrip">
        <article className="detailFocusCard">
          <div className="detailFocusLabel">Primary object</div>
          <div className="detailFocusValue">Dispute detail</div>
          <div className="detailFocusText">Inspect the case, confirm the target, and resolve assignment posture before moving into the final review workspace.</div>
        </article>
        <article className="detailFocusCard">
          <div className="detailFocusLabel">Next action</div>
          <div className="detailFocusValue">{currentVote ? "Review already recorded" : reviewUnlocked ? "Open review workspace" : canAccept || canDecline ? "Resolve assignment" : "Refresh and inspect"}</div>
          <div className="detailFocusText">{hint}</div>
        </article>
        <article className="detailFocusCard">
          <div className="detailFocusLabel">Current route rule</div>
          <div className="detailFocusValue">No final vote here</div>
          <div className="detailFocusText">This page explains the case. Final juror voting is intentionally isolated to the review action route.</div>
        </article>
      </section>

      <section className="summaryCardGrid">
        <article className="summaryCard">
          <div className="summaryCardLabel">Stage</div>
          <div className="summaryCardValue"><span className={disputeStageClass(String(dispute?.stage || "open"))}>{String(dispute?.stage || "open")}</span></div>
          <div className="summaryCardText">resolved: {String(!!dispute?.resolved)}</div>
        </article>
        <article className="summaryCard">
          <div className="summaryCardLabel">Your juror status</div>
          <div className="summaryCardValue">{selectedJurorStatus}</div>
          <div className="summaryCardText">{attendancePresent ? "Attendance recorded" : "Attendance not yet recorded"}</div>
        </article>
        <article className="summaryCard">
          <div className="summaryCardLabel">Votes</div>
          <div className="summaryCardValue">{counts.total}</div>
          <div className="summaryCardText">YES {counts.yes} · NO {counts.no} · ABSTAIN {counts.abstain}</div>
        </article>
        <article className="summaryCard">
          <div className="summaryCardLabel">Current signer vote</div>
          <div className="summaryCardValue">{currentVote ? currentVote.toUpperCase() : "None"}</div>
          <div className="summaryCardText">Final vote status should remain visible here even though this page no longer owns vote submission.</div>
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
              <div className="summaryCardText">nonce {fmtNonce(dispute?.opened_at_nonce)}</div>
            </article>
          </div>
          {dispute?.reason ? <div className="feedBodyText">{String(dispute.reason)}</div> : <div className="cardDesc">No dispute reason was recorded.</div>}
          <div className="calloutInfo">{hint}</div>
        </div>
      </section>

      <section className="grid2">
        <article className="card">
          <div className="cardBody formStack">
            <div className="sectionHead">
              <div>
                <div className="eyebrow">Flagged content</div>
                <h2 className="cardTitle">Review the target before voting</h2>
              </div>
            </div>
            {targetContent ? (
              <>
                <div className="summaryCardGrid">
                  <article className="summaryCard">
                    <div className="summaryCardLabel">Author</div>
                    <div className="summaryCardValue mono">{contentAuthor || "(unknown)"}</div>
                    <div className="summaryCardText">target id {String(dispute?.target_id || "")}</div>
                  </article>
                  <article className="summaryCard">
                    <div className="summaryCardLabel">Scope</div>
                    <div className="summaryCardValue">{contentGroup ? "Group" : "Public"}</div>
                    <div className="summaryCardText mono">{contentGroup || "public feed"}</div>
                  </article>
                </div>
                {contentBody ? <div className="feedBodyText">{contentBody}</div> : <div className="cardDesc">The flagged content is available but has no body text.</div>}
              </>
            ) : (
              <div className="cardDesc">This dispute target is not currently resolvable through the content endpoint. The dispute record is still authoritative for assignment and voting.</div>
            )}
          </div>
        </article>

        <article className="card">
          <div className="cardBody formStack">
            <div className="sectionHead">
              <div>
                <div className="eyebrow">Juror next step</div>
                <h2 className="cardTitle">Detail explains the case. Review owns the final action.</h2>
              </div>
            </div>
            <div className="infoCard">
              <div className="feedMediaTitle">Assigned jurors</div>
              <div className="milestoneList">
                {Object.entries(asRecord(dispute?.jurors)).sort((a, b) => String(a[0]).localeCompare(String(b[0]))).map(([juror, rec]) => (
                  <span key={juror} className="miniTag">{juror}: {String((rec as any)?.status || "assigned")}{asRecord((rec as any)?.attendance).present ? " · present" : ""}</span>
                ))}
              </div>
            </div>
            <div className="buttonRow buttonRowWide">
              <button className="btn" onClick={() => void submitDisputeTx("DISPUTE_JUROR_ACCEPT", { dispute_id: id }, "Accept dispute", "Dispute accepted.")} disabled={!canAccept}>{signerSubmission.busy ? "Waiting…" : "Accept assignment"}</button>
              <button className="btn" onClick={() => void submitDisputeTx("DISPUTE_JUROR_DECLINE", { dispute_id: id }, "Decline dispute", "Dispute declined.")} disabled={!canDecline}>{signerSubmission.busy ? "Waiting…" : "Decline assignment"}</button>
              <button className="btn btnPrimary" onClick={() => nav(`/disputes/${encodeURIComponent(String(dispute?.id || id))}/review`)} disabled={!reviewUnlocked && !currentVote}>{currentVote ? "Open recorded review" : reviewUnlocked ? "Open review workspace" : "Review locked"}</button>
            </div>
            <div className="cardDesc">Queue pages list work, detail pages explain the case, and the dedicated review page owns the final vote controls. Use this page to resolve assignment posture and verify the target before moving forward.</div>
            {currentVote ? <div className="statusPill ok">Vote already recorded for this signer</div> : null}
          </div>
        </article>
      </section>

      {result ? (
        <section className="card">
          <div className="cardBody formStack">
            <div className="eyebrow">Last action</div>
            <pre className="codePanel mono">{JSON.stringify(result, null, 2)}</pre>
          </div>
        </section>
      ) : null}
    </div>
  );
}
