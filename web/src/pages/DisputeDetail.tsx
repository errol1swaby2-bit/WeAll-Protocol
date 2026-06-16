import React, { useEffect, useMemo, useState } from "react";

import { getApiBaseUrl, weall } from "../api/weall";
import ErrorBanner from "../components/ErrorBanner";
import ProcedureTimeline from "../components/ProcedureTimeline";
import { getAuthHeaders, getSession, submitSignedTx } from "../auth/session";
import { normalizeAccount } from "../auth/keys";
import { checkGates, summarizeAccountState } from "../lib/gates";
import { nav } from "../lib/router";
import { useAccount } from "../context/AccountContext";
import { useTxQueue } from "../hooks/useTxQueue";
import { useMutationRefresh } from "../hooks/useMutationRefresh";
import { useSignerSubmissionBusy } from "../hooks/useSignerSubmissionBusy";
import { reconcileDisputeMutation } from "../lib/disputeRevalidation";
import { reportStageLabel, reviewChoiceLabel, reviewStatusLabel, reviewTallyText } from "../lib/userLanguage";
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
import { currentProcedureHeight, disputeDeadlineHeight, targetBlockIntervalMs } from "../lib/procedureClock";

function prettyErr(e: any): { msg: string; details: any } {
  return actionableTxError(e, "Report action failed.");
}

function asRecord(value: any): Record<string, any> {
  return value && typeof value === "object" && !Array.isArray(value) ? value : {};
}

function fmtNonce(v: any): string {
  const n = Number(v);
  return Number.isFinite(n) && n > 0 ? String(Math.floor(n)) : "—";
}


function sameAccount(a: any, b: any): boolean {
  const av = String(a || "").trim();
  const bv = String(b || "").trim();
  if (!av || !bv) return false;
  return av === bv || av.replace(/^@/, "") === bv.replace(/^@/, "");
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
  if (!account) return "Log in to take report actions.";
  if (signerBusy) return "Another signed action is still saving for this account.";
  if (!tierGateOk) return tierGateReason || "Complete live verification and keep this device signed in before reviewing reports.";
  if (jurorStatus === "unassigned") return "This report is visible, but you were not selected to review it.";
  if (jurorStatus === "declined") return "You declined this review assignment. No further actions are available from this account.";
  if (jurorStatus === "assigned") return "Step 1 of 3: respond to the assignment here. Final choices stay on the dedicated review page.";
  if ((jurorStatus === "accepted" || jurorStatus === "review") && !attendancePresent) return "Step 2 of 3: accepted attendance must appear before the final review choice unlocks.";
  if (currentVote) return `Step 3 of 3 is complete. Your recorded review choice is ${reviewChoiceLabel(currentVote)}, and this account cannot review it again.`;
  return "Step 3 of 3: inspect the reported content and reason here, then continue into the dedicated review workspace for the final choice.";
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
  const [appealReason, setAppealReason] = useState("");

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
      const headers = account ? getAuthHeaders(account) : undefined;
      const [detailRes, votesRes] = await Promise.all([
        weall.dispute(id, apiBase, headers),
        weall.disputeVotes(id, apiBase, headers),
      ]);
      const nextDispute = (detailRes as any)?.dispute || null;
      setDispute(nextDispute);
      setVoteSurface(votesRes || null);
      const targetType = String(nextDispute?.target_type || "").trim().toLowerCase();
      const targetId = String(nextDispute?.target_id || "").trim();
      if (targetType === "content" && targetId) {
        try {
          const contentRes = headers
            ? await weall.contentScoped(targetId, apiBase, headers)
            : await weall.content(targetId, apiBase);
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
  const disputeProcedureHeight = currentProcedureHeight(dispute);
  const disputeDeadline = disputeDeadlineHeight(dispute);
  const disputeIntervalMs = targetBlockIntervalMs(dispute);
  const appealCount = Array.isArray(dispute?.appeals) ? dispute.appeals.length : 0;
  const disputeStage = String(dispute?.stage || "open").toLowerCase();
  const appealWindowOpen = disputeStage === "appeal_window" || disputeStage === "appealed" || disputeStage === "appeal_review";
  const appealDeadlinePassed = Number(dispute?.appeal_deadline_height || 0) > 0 && disputeProcedureHeight > Number(dispute?.appeal_deadline_height || 0);
  const appealEligibility = asRecord(dispute?.appeal_eligibility);
  const targetOwner = String(appealEligibility?.target_owner || dispute?.target_owner || contentAuthor || "").trim();
  const appealActorEligible =
    appealEligibility?.can_file === true ||
    (!!account && !!targetOwner && sameAccount(account, targetOwner));
  const canFileAppeal = !!dispute && !!account && tierGate.ok && !signerSubmission.busy && appealWindowOpen && !appealDeadlinePassed && appealActorEligible;

  const detailCtaLabel = currentVote
    ? "Open recorded review"
    : reviewUnlocked
      ? "Continue review workspace"
      : canAccept || canDecline
        ? "Continue to assignment response"
        : selectedJurorStatus === "unassigned"
          ? "Inspect report only"
          : "Refresh and inspect";
  const detailCtaDisabled = selectedJurorStatus === "unassigned" && !reviewUnlocked && !currentVote && !(canAccept || canDecline);

  async function submitDisputeTx(txType: string, payload: any, title: string, successMessage: string): Promise<void> {
    if (!account) throw new Error("not_logged_in");
    if (signerSubmission.busy) throw new Error("Another signed action is still settling for this reviewer account.");
    const res = await tx.runTx({
      title,
      pendingKey: txPendingKey(["dispute", txType, String(payload?.dispute_id || id || ""), account]),
      pendingMessage: "Saving report action…",
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
          routeHint: `/reports/${encodeURIComponent(id)}`,
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


  async function fileAppeal(): Promise<void> {
    const reason = appealReason.trim();
    if (!reason) {
      setErr({ msg: "Write an appeal reason before filing.", details: null });
      return;
    }
    try {
      await submitDisputeTx(
        "DISPUTE_APPEAL",
        { dispute_id: String(dispute?.id || id), reason },
        "File appeal",
        "Appeal filed. Finalization remains held while the appeal is pending.",
      );
      setAppealReason("");
    } catch (e: any) {
      setErr(prettyErr(e));
    }
  }

  return (
    <div className="pageStack pageNarrow detailPage disputeDetailPage">
      <section className="card heroCard compact detailHeroCard">
        <div className="cardBody heroBody pageStack">
          <div className="surfaceSummaryRow">
            <div>
              <div className="eyebrow">Community review</div>
              <h1 className="heroTitle heroTitleSm">Report detail</h1>
              <p className="heroSubtitle">Inspect the report and review the flagged content here. Assignment response and final reviewer choices stay in the dedicated review workspace.</p>
            </div>
            <div className="surfaceSummaryStats">
              <div className="surfaceSummaryStat"><strong className="surfaceSummaryValue mono">{String(dispute?.id || id)}</strong><span className="surfaceSummaryHint">report id</span></div>
              <div className="surfaceSummaryStat"><strong className="surfaceSummaryValue">{summary}</strong><span className="surfaceSummaryHint">current account standing</span></div>
            </div>
          </div>
          <div className="buttonRow">
            <button className="btn" onClick={() => nav("/reports")}>Back to reports</button>
            <button className="btn" onClick={() => void refreshMutationSlices(refreshAccount, refreshAccountContext, load)}>{signerSubmission.busy ? "Waiting…" : "Refresh report"}</button>
            {String(dispute?.target_id || "") ? (
              <button className="btn" onClick={() => nav(`/content/${encodeURIComponent(String(dispute?.target_id || ""))}`)}>Open content page</button>
            ) : null}
          </div>
        </div>
      </section>

      <ErrorBanner message={err?.msg} details={err?.details} onDismiss={() => setErr(null)} onRetry={() => void refreshMutationSlices(refreshAccount, refreshAccountContext, load)} />

      {signerSubmission.busy ? <div className="calloutInfo">Another signed action is still settling. Review actions stay read-only until the current action finishes.</div> : null}


      <ProcedureTimeline
        title="Review and appeal timeline"
        stage={String(dispute?.stage || "open")}
        currentHeight={disputeProcedureHeight}
        deadlineHeight={disputeDeadline}
        targetBlockIntervalMs={disputeIntervalMs}
        nextAction={String(dispute?.stage || "").toLowerCase() === "appeal_window" ? "Appeals are open until the deadline block. Sanctions should not finalize before that window closes." : hint}
      >
        <div className="summaryCardGrid">
          <article className="summaryCard">
            <div className="summaryCardLabel">Appeal deadline</div>
            <div className="summaryCardValue mono">{Number(dispute?.appeal_deadline_height || 0) || "—"}</div>
            <div className="summaryCardText">Serious outcomes remain reviewable until this block when appeal mode is active.</div>
          </article>
          <article className="summaryCard">
            <div className="summaryCardLabel">Appeals filed</div>
            <div className="summaryCardValue mono">{appealCount}</div>
            <div className="summaryCardText">Appeal records are backend state, not frontend-only notes.</div>
          </article>
        </div>
      </ProcedureTimeline>

      {(appealActorEligible || appealCount > 0) ? (
      <section className="card">
        <div className="cardBody formStack">
          <div className="sectionHead">
            <div>
              <div className="eyebrow">Appeal</div>
              <h2 className="cardTitle">{appealActorEligible ? "File an appeal during the appeal window" : "Appeal history"}</h2>
            </div>
            <div className="statusSummary">
              <span className={`statusPill ${appealWindowOpen && !appealDeadlinePassed && appealActorEligible ? "ok" : ""}`}>
                {appealActorEligible
                  ? (appealWindowOpen && !appealDeadlinePassed ? "Appeal filing open" : "Appeal filing closed")
                  : "Creator-only action"}
              </span>
            </div>
          </div>
          <div className="cardDesc">
            Appeals are signed protocol actions for the affected content creator. Reviewers can inspect appeal history, but reviewer accounts do not get the filing control unless they also created the content.
          </div>

          {appealActorEligible ? (
            <>
              <label className="fieldLabel">
                Appeal reason
                <textarea
                  rows={4}
                  value={appealReason}
                  onChange={(e) => setAppealReason(e.target.value)}
                  placeholder="Explain what was missed, why the outcome should be reviewed, or what new evidence should be considered."
                  disabled={!appealWindowOpen || appealDeadlinePassed || signerSubmission.busy}
                />
              </label>

              <div className="buttonRow">
                <button className="btn btnPrimary" onClick={() => void fileAppeal()} disabled={!canFileAppeal || !appealReason.trim()}>
                  File appeal
                </button>
                {!tierGate.ok ? <span className="statusPill warn">{tierGate.reason || "Live verification required"}</span> : null}
                {appealDeadlinePassed ? <span className="statusPill warn">Appeal deadline has passed</span> : null}
              </div>
            </>
          ) : null}

          {Array.isArray(dispute?.appeals) && dispute.appeals.length > 0 ? (
            <div className="pageStack">
              {dispute.appeals.map((appeal: any, idx: number) => (
                <article key={String(appeal?.appeal_id || idx)} className="summaryCard">
                  <div className="summaryCardLabel mono">{String(appeal?.by || "unknown")}</div>
                  <div className="summaryCardValue">Appeal #{idx + 1}</div>
                  <div className="summaryCardText">Block {Number(appeal?.height || 0) || "—"}</div>
                  <div className="feedBodyText">{String(appeal?.payload?.reason || appeal?.reason || appeal?.payload?.note || appeal?.note || "")}</div>
                </article>
              ))}
            </div>
          ) : (
            <div className="cardDesc">No appeal has been filed on this report yet.</div>
          )}
        </div>
      </section>
      ) : null}

      <section className="detailFocusStrip">
        <article className="detailFocusCard">
          <div className="detailFocusLabel">Primary object</div>
          <div className="detailFocusValue">Report detail</div>
          <div className="detailFocusText">Inspect the report and confirm the target before moving into the final review workspace when this account has an assignment.</div>
        </article>
        <article className="detailFocusCard">
          <div className="detailFocusLabel">Next action</div>
          <div className="detailFocusValue">{detailCtaLabel}</div>
          <div className="detailFocusText">{hint}</div>
        </article>
        <article className="detailFocusCard">
          <div className="detailFocusLabel">Current route rule</div>
          <div className="detailFocusValue">No final vote here</div>
          <div className="detailFocusText">This page explains the case. Final reviewer choices are intentionally isolated to the review action route.</div>
        </article>
      </section>

      <section className="summaryCardGrid">
        <article className="summaryCard">
          <div className="summaryCardLabel">Status</div>
          <div className="summaryCardValue"><span className={disputeStageClass(String(dispute?.stage || "open"))}>{reportStageLabel(dispute?.stage || "open")}</span></div>
          <div className="summaryCardText">{dispute?.resolved ? "Review complete" : "Community review is still active"}</div>
        </article>
        <article className="summaryCard">
          <div className="summaryCardLabel">Your reviewer status</div>
          <div className="summaryCardValue">{reviewStatusLabel(selectedJurorStatus)}</div>
          <div className="summaryCardText">{attendancePresent ? "Attendance recorded" : "Attendance not yet recorded"}</div>
        </article>
        <article className="summaryCard">
          <div className="summaryCardLabel">Reviews</div>
          <div className="summaryCardValue">{counts.total}</div>
          <div className="summaryCardText">{reviewTallyText(counts)}</div>
        </article>
        <article className="summaryCard">
          <div className="summaryCardLabel">Your recorded choice</div>
          <div className="summaryCardValue">{reviewChoiceLabel(currentVote)}</div>
          <div className="summaryCardText">Final choice status stays visible here; selected reviewers make choices in the review workspace.</div>
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
              <div className="summaryCardText">Report submission record</div>
            </article>
          </div>
          {dispute?.reason ? <div className="feedBodyText">{String(dispute.reason)}</div> : <div className="cardDesc">No report reason was recorded.</div>}
          <div className="calloutInfo">{hint}</div>
        </div>
      </section>

      <section className="grid2">
        <article className="card">
          <div className="cardBody formStack">
            <div className="sectionHead">
              <div>
                <div className="eyebrow">Flagged content</div>
                <h2 className="cardTitle">Review the target before choosing</h2>
              </div>
            </div>
            {targetContent ? (
              <>
                <div className="summaryCardGrid">
                  <article className="summaryCard">
                    <div className="summaryCardLabel">Author</div>
                    <div className="summaryCardValue mono">{contentAuthor || "(unknown)"}</div>
                    <div className="summaryCardText">reported content reference</div>
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
              <div className="cardDesc">This report target is not currently visible through the content endpoint. The report record is still authoritative for assignment and review status.</div>
            )}
          </div>
        </article>

        <article className="card">
          <div className="cardBody formStack">
            <div className="sectionHead">
              <div>
                <div className="eyebrow">Reviewer next step</div>
                <h2 className="cardTitle">Detail explains the report. Review owns the final action.</h2>
              </div>
            </div>
            <div className="infoCard">
              <div className="feedMediaTitle">Assigned reviewers</div>
              <div className="milestoneList">
                {Object.entries(asRecord(dispute?.jurors)).sort((a, b) => String(a[0]).localeCompare(String(b[0]))).map(([juror, rec]) => (
                  <span key={juror} className="miniTag">{juror}: {reviewStatusLabel(String((rec as any)?.status || "assigned"))}{asRecord((rec as any)?.attendance).present ? " · present" : ""}</span>
                ))}
              </div>
            </div>
            <div className="buttonRow buttonRowWide">
              <button className="btn btnPrimary" disabled={detailCtaDisabled} onClick={() => nav(`/reviews/${encodeURIComponent(String(dispute?.id || id))}`)}>{detailCtaLabel}</button>
              <button className="btn" onClick={() => nav("/reviews")}>Back to Review Center</button>
            </div>
            <div className="cardDesc">Report detail explains what happened and which content is involved. The dedicated review workspace owns assignment acceptance, decline, and final choices so this page does not submit review transactions by accident.</div>
            {currentVote ? <div className="statusPill ok">Review choice already recorded for this account</div> : null}
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
