import React, { useEffect, useMemo, useState } from "react";

import { getApiBaseUrl, weall } from "../api/weall";
import ErrorBanner from "../components/ErrorBanner";
import RequirementList from "../components/RequirementList";
import MediaGallery from "../components/MediaGallery";
import { getAuthHeaders, getSession, submitSignedTx } from "../auth/session";
import { normalizeAccount } from "../auth/keys";
import { checkGates, summarizeAccountState } from "../lib/gates";
import { reportStageLabel, reviewChoiceLabel, reviewStatusLabel, reviewTallyText } from "../lib/userLanguage";
import { disputeAttendancePresent, disputeCurrentVote, disputeJurorStatus, disputeVoteCountSummary } from "../lib/disputeSurface";
import { nav } from "../lib/router";
import { useAccount } from "../context/AccountContext";
import { useTxQueue } from "../hooks/useTxQueue";
import { useSignerSubmissionBusy } from "../hooks/useSignerSubmissionBusy";
import { refreshMutationSlices } from "../lib/revalidation";
import { liveRoomDescriptorText, liveRoomTransportNotice, liveRoomUrlFromCommitment } from "../lib/liveRoom";
import { REVIEW_CENTER_LABEL, REVIEW_LANES, reviewLaneStatusFromTruth, reviewLaneStatusPillClass, type ReviewLaneId } from "../lib/reviewLanes";

function prettyErr(e: any): { msg: string; details: any } {
  const details = e?.body || e?.data || e;
  const msg = details?.message || e?.error?.message || e?.message || "error";
  return { msg, details };
}

function asRecord(value: any): Record<string, any> {
  return value && typeof value === "object" && !Array.isArray(value) ? value : {};
}

function initialReviewTab(): "async" | "live" {
  if (typeof window === "undefined") return "async";
  const raw = String(window.location.hash || "");
  const query = raw.includes("?") ? raw.slice(raw.indexOf("?") + 1) : "";
  const lane = new URLSearchParams(query).get("lane");
  return lane === "poh_live_review" ? "live" : "async";
}

function fmtTs(v: any): string {
  const n = Number(v);
  if (!Number.isFinite(n) || n <= 0) return "—";
  try {
    return new Date(n).toLocaleString();
  } catch {
    return String(v);
  }
}

function extractEvidenceMedia(evidence: any): any[] {
  if (!evidence || typeof evidence !== "object") return [];
  const out: any[] = [];

  const pushItem = (item: any, label?: string) => {
    if (!item) return;
    if (typeof item === "string") {
      const raw = item.trim();
      if (!raw) return;
      if (raw.startsWith("ipfs://")) out.push({ cid: raw.slice("ipfs://".length), kind: "video", name: label || raw });
      else if (/^https?:\/\//i.test(raw)) out.push({ url: raw, kind: "video", name: label || raw });
      return;
    }
    if (typeof item === "object") out.push({ label, kind: "video", ...item });
  };

  const pushCid = (cid: string, kind = "file", extra: any = {}) => {
    const c = String(cid || "").trim();
    if (!c) return;
    out.push({ cid: c, kind, name: extra.name || c, ...extra });
  };

  if (typeof evidence.video_cid === "string") pushCid(evidence.video_cid, "video", evidence);
  if (typeof evidence.evidence_cid === "string") pushCid(evidence.evidence_cid, "video", evidence);
  if (typeof evidence.cid === "string") pushCid(evidence.cid, "file", evidence);
  if (typeof evidence.gateway_url === "string") pushItem({ url: evidence.gateway_url, name: evidence.name || "Verification evidence", mime: evidence.mime || "video/webm" });
  if (typeof evidence.public_evidence_id === "string") pushItem(evidence.public_evidence_id, "Public evidence");
  if (typeof evidence.uri === "string") pushItem(evidence.uri, "Evidence URI");

  if (Array.isArray(evidence.media)) {
    for (const item of evidence.media) pushItem(item);
  }
  if (Array.isArray(evidence.public_evidence_ids)) {
    for (const item of evidence.public_evidence_ids) pushItem(item, "Public evidence");
  }
  if (evidence.evidence_commitments && typeof evidence.evidence_commitments === "object") {
    for (const [id, item] of Object.entries(evidence.evidence_commitments)) pushItem(item, String(id));
  }
  if (evidence.reviewable_evidence && typeof evidence.reviewable_evidence === "object") {
    for (const [id, item] of Object.entries(evidence.reviewable_evidence)) pushItem(item, String(id));
  }

  const seen = new Set<string>();
  return out.filter((item) => {
    const key = String(item?.cid || item?.url || item?.gateway_url || item?.uri || item?.raw || JSON.stringify(item));
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function statusTone(statusRaw: any): "done" | "active" | "todo" {
  const s = String(statusRaw || "").toLowerCase();
  if (["complete", "completed", "finalized", "approved", "passed", "closed"].includes(s)) {
    return "done";
  }
  if (["open", "pending", "assigned", "accepted", "scheduled", "review", "in_progress"].includes(s)) {
    return "active";
  }
  return "todo";
}

function reportStageNeedsReviewerAction(stageRaw: any): boolean {
  const stage = String(stageRaw || "open").trim().toLowerCase() || "open";
  return ["open", "assigned", "review", "juror_review", "voting", "in_review"].includes(stage);
}

function reportNeedsCurrentReviewer(item: any, account: string): boolean {
  const targetType = String(item?.target_type || "content").trim().toLowerCase();
  if (targetType !== "content") return false;
  if (disputeCurrentVote(item, account)) return false;
  if (!reportStageNeedsReviewerAction(item?.stage || item?.status)) return false;
  const status = disputeJurorStatus(item, account);
  return status !== "unassigned" && status !== "declined";
}

function SectionCard({
  eyebrow,
  title,
  children,
  right,
}: {
  eyebrow: string;
  title: string;
  children: React.ReactNode;
  right?: React.ReactNode;
}): JSX.Element {
  return (
    <article className="card">
      <div className="cardBody formStack">
        <div className="sectionHead">
          <div>
            <div className="eyebrow">{eyebrow}</div>
            <h2 className="cardTitle">{title}</h2>
          </div>
          {right}
        </div>
        {children}
      </div>
    </article>
  );
}

export default function JurorDashboard(): JSX.Element {
  const apiBase = useMemo(() => getApiBaseUrl(), []);
  const session = getSession();
  const account = session ? normalizeAccount(session.account) : "";
  const { refresh: refreshAccountContext } = useAccount();
  const tx = useTxQueue();
  const signerSubmission = useSignerSubmissionBusy(account);

  const [acctState, setAcctState] = useState<any | null>(null);
  const [reviewerStatus, setReviewerStatus] = useState<any | null>(null);
  const [asyncCases, setAsyncCases] = useState<any[]>([]);
  const [liveCases, setLiveCases] = useState<any[]>([]);
  const [liveSessions, setLiveSessions] = useState<any[]>([]);
  const [contentReports, setContentReports] = useState<any[]>([]);
  const [reportContent, setReportContent] = useState<Record<string, any>>({});
  const [expanded, setExpanded] = useState<Record<string, any>>({});
  const [participants, setParticipants] = useState<Record<string, any[]>>({});
  const [tab, setTab] = useState<"async" | "live">(() => initialReviewTab());
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<{ msg: string; details: any } | null>(null);
  const [result, setResult] = useState<any | null>(null);

  const gate = checkGates({
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

  async function loadQueues(): Promise<void> {
    if (!account) return;

    setBusy(true);
    setErr(null);

    try {
      const headers = getAuthHeaders(account);
      const [t2, live, sess, currentDisputesRes, fallbackDisputesRes, reviewerStatusRes] = await Promise.all([
        weall.pohAsyncJurorCases(account, apiBase, headers).catch(() => ({ cases: [] })),
        weall.pohLiveAssigned(account, apiBase, headers).catch(() => ({ cases: [] })),
        weall.pohLiveSessions(apiBase, headers).catch(() => ({ sessions: [] })),
        weall.disputesCurrent(apiBase, headers).catch(() => ({ items: [] })),
        weall.disputes({ limit: 200, includeSummary: true } as any, apiBase, headers).catch(() => ({ items: [] })),
        weall.accountReviewerStatus(account, apiBase, headers).catch(() => ({ reviewer: null })),
        refreshAccount(),
      ]);

      setAsyncCases(Array.isArray(t2?.cases) ? t2.cases : []);
      setLiveCases(Array.isArray(live?.cases) ? live.cases : []);
      setLiveSessions(Array.isArray(sess?.sessions) ? sess.sessions : []);
      setReviewerStatus(reviewerStatusRes?.reviewer ?? null);

      const backendCurrentReports = Array.isArray(currentDisputesRes?.items) ? currentDisputesRes.items : [];
      const fallbackReports = Array.isArray(fallbackDisputesRes?.items) ? fallbackDisputesRes.items : [];
      const assignedReports = (backendCurrentReports.length > 0 ? backendCurrentReports : fallbackReports)
        .filter((item: any) => reportNeedsCurrentReviewer(item, account));
      setContentReports(assignedReports);

      const previews: Record<string, any> = {};
      await Promise.all(assignedReports.slice(0, 12).map(async (item: any) => {
        const id = String(item?.id || item?.dispute_id || "").trim();
        const targetType = String(item?.target_type || "").trim().toLowerCase();
        const targetId = String(item?.target_id || "").trim();
        if (!id || targetType !== "content" || !targetId) return;
        try {
          previews[id] = await weall.contentScoped(targetId, apiBase, headers);
        } catch {
          previews[id] = null;
        }
      }));
      setReportContent(previews);
    } catch (e: any) {
      setErr(prettyErr(e));
    } finally {
      setBusy(false);
    }
  }

  async function loadCase(kind: "async" | "live", caseId: string): Promise<void> {
    if (!account || !caseId) return;

    setBusy(true);
    setErr(null);

    try {
      const headers = getAuthHeaders(account);
      const detail =
        kind === "async"
          ? await weall.pohAsyncCase(caseId, apiBase, headers)
          : await weall.pohLiveCase(caseId, apiBase, headers);

      setExpanded((prev) => ({ ...prev, [caseId]: detail }));

      if (kind === "live") {
        const sessionRec = sessionForCase(caseId);
        const sessionId = String(sessionRec?.session_id || "");
        if (sessionId) {
          const partRes = await weall
            .pohLiveSessionParticipants(sessionId, apiBase, headers)
            .catch(() => ({ participants: [] }));
          setParticipants((prev) => ({
            ...prev,
            [sessionId]: Array.isArray(partRes?.participants) ? partRes.participants : [],
          }));
        }
      }
    } catch (e: any) {
      setErr(prettyErr(e));
    } finally {
      setBusy(false);
    }
  }

  function sessionForCase(caseId: string): any | null {
    for (const s of liveSessions) {
      if (String(s?.case_id || "") === String(caseId)) return s;
    }
    return null;
  }

  function viewLiveVerificationStatus(caseId: string): void {
    if (!caseId) return;
    nav(`/verification/live/${encodeURIComponent(caseId)}?mode=status`);
  }

  function joinLiveRoom(caseId: string): void {
    if (!caseId) return;
    // Reviewers stay in the PoH verification feed until they intentionally
    // accept the call. Accepting records the chain action, then transports the
    // reviewer directly into the WebRTC verification room.
    nav(`/verification/live/${encodeURIComponent(caseId)}`);
  }

  async function refreshJurorSurface(): Promise<void> {
    await refreshMutationSlices(loadQueues, refreshAccountContext);
  }

  async function submitSkeletonTx(
    skel: any,
    title: string,
    successMessage: string,
  ): Promise<void> {
    if (!account) throw new Error("not_logged_in");
    if (signerSubmission.busy) throw new Error("Another signed action is still settling for this reviewer account.");
    if (!skel?.tx) throw new Error("invalid_tx_skeleton");

    const r = await tx.runTx({
      title,
      pendingMessage: "Saving review action…",
      successMessage,
      errorMessage: (e) => prettyErr(e).msg,
      getTxId: (res: any) => res?.result?.tx_id,
      task: async () => {
        const txSkel = skel.tx;
        const payload = { ...(txSkel.payload || {}) };

        if (typeof payload.ts_ms === "number" && payload.ts_ms === 0) {
          payload.ts_ms = Date.now();
        }

        const res = await submitSignedTx({
          account,
          tx_type: String(txSkel.tx_type || ""),
          payload,
          parent: txSkel.parent ?? null,
          base: apiBase,
        });

        return res;
      },
    });

    setResult(r);
    await refreshAccount();
    await refreshAccountContext();
    await loadQueues();
  }

  async function asyncAccept(caseId: string): Promise<void> {
    const headers = getAuthHeaders(account);
    const skel = await weall.pohAsyncTxJurorAccept({ case_id: caseId }, apiBase, headers);
    await submitSkeletonTx(skel, "Accept async verification case", "Async verification case accepted.");
  }

  async function asyncDecline(caseId: string): Promise<void> {
    const headers = getAuthHeaders(account);
    const skel = await weall.pohAsyncTxJurorDecline({ case_id: caseId }, apiBase, headers);
    await submitSkeletonTx(skel, "Decline async verification case", "Async verification case declined.");
  }

  async function asyncReview(caseId: string, verdict: "approve" | "reject"): Promise<void> {
    const note = window.prompt("Optional note", "") || "";
    const headers = getAuthHeaders(account);
    const body: any = { case_id: caseId, verdict };
    if (note.trim()) body.note = note.trim();
    const skel = await weall.pohAsyncTxReview(body, apiBase, headers);
    await submitSkeletonTx(
      skel,
      "Submit async verification decision",
      verdict === "approve" ? "Async verification approved." : "Async verification rejected.",
    );
  }

  async function liveAccept(caseId: string): Promise<void> {
    const headers = getAuthHeaders(account);
    const skel = await weall.pohLiveTxJurorAccept({ case_id: caseId }, apiBase, headers);
    await submitSkeletonTx(skel, "Accept live verification call", "Live verification call accepted. Opening the WebRTC room…");
    joinLiveRoom(caseId);
  }

  async function liveDecline(caseId: string): Promise<void> {
    const headers = getAuthHeaders(account);
    const skel = await weall.pohLiveTxJurorDecline({ case_id: caseId }, apiBase, headers);
    await submitSkeletonTx(skel, "Decline live verification case", "Live verification case declined.");
  }

  async function liveAttendance(caseId: string, attended: boolean): Promise<void> {
    const headers = getAuthHeaders(account);
    const skel = await weall.pohLiveTxAttendance(
      { case_id: caseId, juror_id: account, attended },
      apiBase,
      headers,
    );
    await submitSkeletonTx(
      skel,
      "Record live verification attendance",
      attended ? "Attendance marked present." : "Attendance marked absent.",
    );
  }

  async function liveVerdict(caseId: string, verdict: "pass" | "fail"): Promise<void> {
    const note = window.prompt("Optional verdict note", "") || "";
    const headers = getAuthHeaders(account);
    const body: any = { case_id: caseId, verdict };
    if (note.trim()) body.note = note.trim();
    const skel = await weall.pohLiveTxVerdict(body, apiBase, headers);
    await submitSkeletonTx(
      skel,
      "Submit live verification decision",
      verdict === "pass" ? "Live verification approved." : "Live verification rejected.",
    );
  }

  useEffect(() => {
    void loadQueues();
  }, [account]);

  const tier = Number(acctState?.poh_tier ?? 0);
  const accountSummary = acctState ? summarizeAccountState(acctState) : "(state unknown)";
  const reviewerTruth = asRecord(reviewerStatus);
  const reviewerLaneTruth = asRecord(reviewerTruth.lanes);
  const reviewerLaneStatus = (laneId: string) => reviewLaneStatusFromTruth(reviewerLaneTruth[laneId]);
  const reviewerLaneActive = (laneId: string): boolean => reviewerLaneStatus(laneId).active;
  const assignedContentReports = contentReports.filter((item) => reportNeedsCurrentReviewer(item, account));
  const laneCount = (laneId: ReviewLaneId): number => {
    if (laneId === "content_review") return assignedContentReports.length;
    if (laneId === "dispute_review") return contentReports.length;
    if (laneId === "poh_async_review") return asyncCases.length;
    if (laneId === "poh_live_review") return liveCases.length;
    return 0;
  };
  const openLane = (laneId: ReviewLaneId): void => {
    if (laneId === "dispute_review") {
      nav("/reports");
      return;
    }
    if (laneId === "poh_async_review") {
      setTab("async");
      nav("/reviews?lane=poh_async_review");
      return;
    }
    if (laneId === "poh_live_review") {
      setTab("live");
      nav("/reviews?lane=poh_live_review");
      return;
    }
    nav("/reviews");
  };
  const showing = tab === "async" ? asyncCases : liveCases;
  const livePendingSessions = liveSessions.filter((session: any) => {
    const caseId = String(session?.case_id || "").trim();
    if (!caseId) return false;
    return !liveCases.some((liveCase: any) => String(liveCase?.case_id || liveCase?.id || "").trim() === caseId);
  });

  return (
    <div className="pageStack">
      <section className="card heroCard">
        <div className="cardBody heroBody compactHero">
          <div className="heroSplit">
            <div>
              <div className="eyebrow">{REVIEW_CENTER_LABEL}</div>
              <h1 className="heroTitle heroTitleSm">Choose the correct review lane</h1>
              <p className="heroText">
                Content reports, dispute juror work, PoH async review, and PoH live review stay separated here. Tier-2 human status is eligibility, not consent to every reviewer duty.
              </p>
            </div>

            <div className="heroInfoPanel">
              <div className="heroInfoTitle">Reviewer readiness</div>
              <div className="heroInfoList">
                <span className={`statusPill ${account ? "ok" : ""}`}>
                  {account ? "Session present" : "No session"}
                </span>
                <span className={`statusPill ${tier >= 2 ? "ok" : ""}`}>
                  {tier >= 2 ? "Trusted Verified Person" : "Live verification needed"}
                </span>
                <span className={`statusPill ${gate.ok ? "ok" : ""}`}>
                  {gate.ok ? "Reviewer-ready" : "Locked"}
                </span>
                <span className={`statusPill ${assignedContentReports.length ? "ok" : ""}`}>
                  {assignedContentReports.length} content report{assignedContentReports.length === 1 ? "" : "s"}
                </span>
                <span className="statusPill">{accountSummary}</span>
              </div>
            </div>
          </div>

          <div className="heroActions">
            <button className="btn btnPrimary" onClick={() => openLane("content_review")}>
              Content review lane
            </button>
            <button className="btn" onClick={() => openLane("dispute_review")}>
              Reports and disputes
            </button>
            <button className={`btn ${tab === "async" ? "btnPrimary" : ""}`} onClick={() => openLane("poh_async_review")}>
              PoH async lane
            </button>
            <button className={`btn ${tab === "live" ? "btnPrimary" : ""}`} onClick={() => openLane("poh_live_review")}>
              PoH live lane
            </button>
            <button className="btn" onClick={() => void refreshJurorSurface()} disabled={busy || signerSubmission.busy || !account}>
              {busy ? "Refreshing…" : signerSubmission.busy ? "Waiting…" : "Refresh"}
            </button>
            <button className="btn" onClick={() => nav("/verification")}>
              Open Account Verification
            </button>
          </div>
        </div>
      </section>

      {signerSubmission.busy ? (
        <div className="calloutInfo">
          Another signed action for this reviewer account is still settling. Review decisions stay read-only until the current action finishes.
        </div>
      ) : null}

      <SectionCard
        eyebrow="Review Center"
        title="Lane-separated responsibilities"
        right={<span className={`statusPill ${REVIEW_LANES.some((lane) => reviewerLaneActive(lane.id)) ? "ok" : ""}`}>{REVIEW_LANES.filter((lane) => reviewerLaneActive(lane.id)).length} active lane(s)</span>}
      >
        <p className="cardDesc">
          The generic combined case surface has been normalized into explicit lanes. Content disputes are not silently mixed with PoH reviews, and every action below names its backend source and consent boundary.
        </p>
        <div className="summaryCardGrid">
          {REVIEW_LANES.map((lane) => {
            const status = reviewerLaneStatus(lane.id);
            const count = laneCount(lane.id);
            return (
              <article key={lane.id} className="summaryCard">
                <div className="summaryCardLabel">{lane.label}</div>
                <div className="summaryCardValue">{count}</div>
                <div className="summaryCardText">{lane.purpose}</div>
                <div className="progressList compact" style={{ marginTop: 10 }}>
                  <div className="progressRow">
                    <span>Opt-in boundary</span>
                    <span className={reviewLaneStatusPillClass(status)}>{status.label}</span>
                  </div>
                  <div className="progressRow">
                    <span>Backend truth source</span>
                    <span className="miniMuted">{lane.source}</span>
                  </div>
                  <div className="progressRow">
                    <span>Time limit / penalty</span>
                    <span className="miniMuted">{lane.timeLimit}</span>
                  </div>
                </div>
                <p className="summaryCardHint">{lane.consentBoundary}</p>
                <div className="buttonRow" style={{ marginTop: 10 }}>
                  <button className={lane.id === "content_review" ? "btn btnPrimary" : "btn"} onClick={() => openLane(lane.id)}>
                    Open {lane.shortLabel}
                  </button>
                </div>
              </article>
            );
          })}
        </div>
      </SectionCard>

      <ErrorBanner
        message={err?.msg}
        details={err?.details}
        onRetry={() => void refreshJurorSurface()}
        onDismiss={() => setErr(null)}
      />


      <SectionCard
        eyebrow="Flagged content"
        title="Assigned content reviews"
        right={<span className={`statusPill ${assignedContentReports.length ? "ok" : ""}`}>{assignedContentReports.length} report{assignedContentReports.length === 1 ? "" : "s"}</span>}
      >
        {assignedContentReports.length === 0 ? (
          <div className="cardDesc">No flagged content is assigned to you right now. When a report is assigned, the target content and review route appear here first.</div>
        ) : (
          <div className="pageStack">
            {assignedContentReports.map((item) => {
              const reportId = String(item?.id || item?.dispute_id || "").trim();
              const targetId = String(item?.target_id || "").trim();
              const contentRes = reportId ? reportContent[reportId] : null;
              const content = contentRes?.content || contentRes || null;
              const body = String(content?.body || content?.text || "").trim();
              const author = String(content?.author || "").trim();
              const vote = disputeCurrentVote(item, account);
              const status = disputeJurorStatus(item, account);
              const present = disputeAttendancePresent(item, account);
              const counts = disputeVoteCountSummary(item);
              return (
                <article key={reportId || targetId} className="card">
                  <div className="cardBody formStack">
                    <div className="sectionHead">
                      <div>
                        <div className="eyebrow">Assigned report</div>
                        <h3 className="cardTitle">{String(item?.reason || "Flagged content review")}</h3>
                        <div className="cardDesc mono">{reportId}</div>
                      </div>
                      <div className="statusSummary">
                        <span className="statusPill">{reportStageLabel(item?.stage)}</span>
                        <span className={`statusPill ${vote ? "ok" : ""}`}>{vote ? `Recorded: ${reviewChoiceLabel(vote)}` : reviewStatusLabel(status)}</span>
                      </div>
                    </div>
                    <div className="summaryCardGrid">
                      <article className="summaryCard"><div className="summaryCardLabel">Flagged content</div><div className="summaryCardValue mono">{targetId || "—"}</div><div className="summaryCardText">Open the content or the focused review workspace before choosing.</div></article>
                      <article className="summaryCard"><div className="summaryCardLabel">Author</div><div className="summaryCardValue mono">{author || "(unknown)"}</div><div className="summaryCardText">Reported content author</div></article>
                      <article className="summaryCard"><div className="summaryCardLabel">Review readiness</div><div className="summaryCardValue">{vote ? "Complete" : present ? "Ready" : status === "assigned" ? "Accept first" : "Needs check-in"}</div><div className="summaryCardText">{vote ? `Your choice is ${reviewChoiceLabel(vote)}.` : present ? "Final choice is available from the review workspace." : "Open the review workspace to accept and check in."}</div></article>
                      <article className="summaryCard"><div className="summaryCardLabel">Current review tally</div><div className="summaryCardValue">{counts.total}</div><div className="summaryCardText">{reviewTallyText(counts)}</div></article>
                    </div>
                    <div className="infoCard">
                      <div className="feedMediaTitle">Content preview</div>
                      {body ? <div className="feedBodyText">{body}</div> : <div className="cardDesc">The content endpoint did not return body text yet. The report assignment is still visible and actionable.</div>}
                    </div>
                    <div className="buttonRow">
                      <button className="btn btnPrimary" onClick={() => nav(`/reviews/${encodeURIComponent(reportId)}`)} disabled={!reportId}>Open review workspace</button>
                      <button className="btn" onClick={() => nav(`/reports/${encodeURIComponent(reportId)}`)} disabled={!reportId}>Open report detail</button>
                      {targetId ? <button className="btn" onClick={() => nav(`/content/${encodeURIComponent(targetId)}`)}>Open content</button> : null}
                    </div>
                  </div>
                </article>
              );
            })}
          </div>
        )}
      </SectionCard>

      {!account ? (
        <div className="card">
          <div className="cardBody formStack">
            <div className="emptyPanel">
              <strong>No local session is active.</strong>
              <span>Restore your session in Settings or Account Verification before using reviewer actions.</span>
              <div className="buttonRow">
                <button className="btn btnPrimary" onClick={() => nav("/settings")}>
                  Open settings
                </button>
              </div>
            </div>
          </div>
        </div>
      ) : null}

      {!gate.ok && account ? (
        <div className="card">
          <div className="cardBody formStack">
            <div className="emptyPanel">
              <strong>Reviewer actions are locked.</strong>
              <span>{gate.reason}</span>
              <RequirementList requirements={gate.requirements} />
            </div>
          </div>
        </div>
      ) : null}

      <SectionCard
        eyebrow={tab === "async" ? "Async Verification" : "Live Verification"}
        title={tab === "async" ? "Assigned async verification reviews" : "Assigned live verification cases"}
        right={<span className={`statusPill ${showing.length ? "ok" : ""}`}>{showing.length} case(s)</span>}
      >
        {showing.length === 0 ? (
          tab === "live" && livePendingSessions.length > 0 ? (
            <div className="pageStack">
              <div className="calloutInfo">
                Live verification request/session records are visible, but no reviewer assignment has reached this queue yet. Live room transport is only available after a live PoH reviewer assignment is active. Keep the genesis block loop and downstream sync running.
              </div>
              {livePendingSessions.map((session: any) => {
                const caseId = String(session?.case_id || "").trim();
                return (
                  <article key={String(session?.session_id || caseId)} className="card">
                    <div className="cardBody formStack">
                      <div className="sectionHead">
                        <div>
                          <div className="eyebrow">Pending live session</div>
                          <h3 className="cardTitle">{caseId || "(missing case id)"}</h3>
                        </div>
                        <span className="statusPill">{String(session?.status || "requested")}</span>
                      </div>
                      <p className="cardDesc">
                        The live room/session exists, but this account has not been assigned as a reviewer yet.
                      </p>
                      <div className="buttonRow">
                        <button className="btn" onClick={() => caseId && viewLiveVerificationStatus(caseId)} disabled={!caseId}>
                          View verification status
                        </button>
                        <button className="btn" onClick={() => void refreshJurorSurface()}>
                          Refresh queue
                        </button>
                      </div>
                    </div>
                  </article>
                );
              })}
            </div>
          ) : (
            <div className="cardDesc">No assigned cases right now.</div>
          )
        ) : (
          <div className="pageStack">
            {showing.map((c) => {
              const caseId = String(c?.case_id || c?.id || "");
              const detail = expanded[caseId]?.case || expanded[caseId] || null;
              const evidence = detail || c || {};
              const evidenceMedia = extractEvidenceMedia(evidence);
              const sessionRec = tab === "live" ? sessionForCase(caseId) : null;
              const sessionId = String(sessionRec?.session_id || "");
              const sessionParticipants = sessionId ? participants[sessionId] || [] : [];

              return (
                <article key={caseId || Math.random()} className="card">
                  <div className="cardBody formStack">
                    <div className="sectionHead">
                      <div>
                        <div className="eyebrow">Case</div>
                        <h3 className="cardTitle">{caseId || "(missing case id)"}</h3>
                      </div>
                      <div className="statusSummary">
                        <span className={`statusPill ${statusTone(c?.status) === "done" ? "ok" : ""}`}>
                          {String(c?.status || "unknown")}
                        </span>
                        {c?.outcome ? <span className="statusPill">{String(c.outcome)}</span> : null}
                      </div>
                    </div>

                    <div className="statsGrid statsGridCompact">
                      <div className="statCard">
                        <span className="statLabel">Applicant</span>
                        <span className="statValue mono">{String(c?.account_id || c?.applicant || "—")}</span>
                      </div>
                      <div className="statCard">
                        <span className="statLabel">Opened</span>
                        <span className="statValue">{fmtTs(c?.created_ts_ms || c?.init_ts_ms)}</span>
                      </div>
                      <div className="statCard">
                        <span className="statLabel">Finalized</span>
                        <span className="statValue">{fmtTs(c?.finalized_ts_ms)}</span>
                      </div>
                    </div>

                    {tab === "async" ? (
                      <div className="buttonRow buttonRowWide">
                        <button className="btn" onClick={() => void loadCase("async", caseId)} disabled={busy || !caseId}>
                          Load details
                        </button>
                        <button className="btn" onClick={() => void asyncAccept(caseId)} disabled={busy || signerSubmission.busy || !gate.ok}>
                          {signerSubmission.busy ? "Waiting…" : "Accept"}
                        </button>
                        <button className="btn" onClick={() => void asyncDecline(caseId)} disabled={busy || signerSubmission.busy || !gate.ok}>
                          {signerSubmission.busy ? "Waiting…" : "Decline"}
                        </button>
                        <button className="btn btnPrimary" onClick={() => void asyncReview(caseId, "approve")} disabled={busy || signerSubmission.busy || !gate.ok}>
                          {signerSubmission.busy ? "Waiting…" : "Approve"}
                        </button>
                        <button className="btn" onClick={() => void asyncReview(caseId, "reject")} disabled={busy || signerSubmission.busy || !gate.ok}>
                          {signerSubmission.busy ? "Waiting…" : "Reject"}
                        </button>
                      </div>
                    ) : (
                      <div className="buttonRow buttonRowWide">
                        <button className="btn" onClick={() => void loadCase("live", caseId)} disabled={busy || !caseId}>
                          Load details
                        </button>
                        <button className="btn btnPrimary" onClick={() => void liveAccept(caseId)} disabled={busy || signerSubmission.busy || !gate.ok}>
                          {signerSubmission.busy ? "Waiting…" : "Accept review and join call"}
                        </button>
                        <button className="btn" onClick={() => void liveDecline(caseId)} disabled={busy || signerSubmission.busy || !gate.ok}>
                          {signerSubmission.busy ? "Waiting…" : "Decline"}
                        </button>
                        <button className="btn" onClick={() => void liveAttendance(caseId, true)} disabled={busy || signerSubmission.busy || !gate.ok}>
                          {signerSubmission.busy ? "Waiting…" : "Mark attended"}
                        </button>
                        <button className="btn" onClick={() => void liveAttendance(caseId, false)} disabled={busy || signerSubmission.busy || !gate.ok}>
                          {signerSubmission.busy ? "Waiting…" : "Mark absent"}
                        </button>
                        <button className="btn btnPrimary" onClick={() => void liveVerdict(caseId, "pass")} disabled={busy || signerSubmission.busy || !gate.ok}>
                          {signerSubmission.busy ? "Waiting…" : "Approve"}
                        </button>
                        <button className="btn" onClick={() => void liveVerdict(caseId, "fail")} disabled={busy || signerSubmission.busy || !gate.ok}>
                          {signerSubmission.busy ? "Waiting…" : "Reject"}
                        </button>
                      </div>
                    )}

                    {evidenceMedia.length ? (
                      <MediaGallery base={apiBase} media={evidenceMedia} />
                    ) : null}

                    {tab === "live" && sessionRec ? (
                      <div className="infoCard">
                        <div className="feedMediaTitle">Live session</div>
                        <div className="feedMediaMeta mono">
                          {String(sessionRec?.session_id || "(missing session id)")}
                        </div>
                        <div className="feedMediaMeta">
                          status: {String(sessionRec?.status || "unknown")} • created: {fmtTs(sessionRec?.created_ts_ms)}
                        </div>
                        {(() => {
                          const roomCommitment = sessionRec?.room_commitment || c?.room_commitment;
                          const joinUrl = String(sessionRec?.join_url || "").trim() || liveRoomUrlFromCommitment(roomCommitment);
                          const p2pDescriptor = liveRoomDescriptorText(roomCommitment);
                          return (
                            <>
                              <div className="buttonRow" style={{ marginTop: 10 }}>
                                <button className="btn btnPrimary" onClick={() => joinLiveRoom(caseId)} disabled={!caseId}>
                                  Open WebRTC room
                                </button>
                                {joinUrl ? (
                                  <a className="btn" href={joinUrl} target="_blank" rel="noreferrer">
                                    Open self-hosted transport
                                  </a>
                                ) : (
                                  <span className="miniMuted">Decentralized P2P room descriptor ready; no centralized room URL is required.</span>
                                )}
                              </div>
                              {p2pDescriptor ? (
                                <details className="advancedDetails">
                                  <summary>P2P room descriptor</summary>
                                  <pre className="jsonBlock">{p2pDescriptor}</pre>
                                </details>
                              ) : null}
                            </>
                          );
                        })()}
                        <div className="feedMediaMeta">{liveRoomTransportNotice()}</div>
                      </div>
                    ) : null}

                    {tab === "live" && sessionParticipants.length ? (
                      <div className="infoCard">
                        <div className="feedMediaTitle">Participants</div>
                        <div className="milestoneList">
                          {sessionParticipants.map((p, idx) => (
                            <span key={`${String(p?.account_id || p?.juror_id || idx)}`} className="miniTag">
                              {String(p?.account_id || p?.juror_id || p?.role || "participant")}
                            </span>
                          ))}
                        </div>
                      </div>
                    ) : null}

                    {detail ? (
                      <details className="detailsPanel">
                        <summary>Advanced case detail</summary>
                        <pre className="codePanel mono">{JSON.stringify(detail, null, 2)}</pre>
                      </details>
                    ) : null}
                  </div>
                </article>
              );
            })}
          </div>
        )}
      </SectionCard>

      {result ? (
        <SectionCard eyebrow="Last action" title="Latest action result">
          <pre className="codePanel mono">{JSON.stringify(result, null, 2)}</pre>
        </SectionCard>
      ) : null}
    </div>
  );
}
