export type ReviewLaneId = "content_review" | "dispute_review" | "poh_async_review" | "poh_live_review";

export type ReviewLane = {
  id: ReviewLaneId;
  label: string;
  shortLabel: string;
  purpose: string;
  source: string;
  workSurface: string;
  actionSurface: string;
  txTypes: string[];
  timeLimit: string;
  withdrawalRule: string;
  consentBoundary: string;
};

export const REVIEW_CENTER_LABEL = "Review Center";

export const REVIEW_LANES: ReviewLane[] = [
  {
    id: "content_review",
    label: "Content review",
    shortLabel: "Content",
    purpose: "View assigned flagged-content context separately from final dispute juror voting authority.",
    source: "/v1/disputes/current plus scoped content preview (context surface only)",
    workSurface: "/reviews",
    actionSurface: "/reports/:id or /reviews/:id after dispute_review authority is active",
    txTypes: ["READ_ONLY_CONTEXT", "DISPUTE_REVIEW_REQUIRED_FOR_ACCEPT_OR_VOTE"],
    timeLimit: "Content-context cards inherit any dispute deadline shown by the backend; final accept/vote authority belongs to the dispute_review lane.",
    withdrawalRule: "Withdrawal reputation rules apply only after a dispute juror assignment is accepted under the dispute_review lane.",
    consentBoundary: "Tier-2 human status is eligibility only; content_review can surface context but does not grant dispute juror accept/vote authority.",
  },
  {
    id: "dispute_review",
    label: "Dispute juror review",
    shortLabel: "Disputes",
    purpose: "Review active content disputes and vote inside the dispute window.",
    source: "/v1/disputes/eligible and /v1/disputes/current",
    workSurface: "/reports",
    actionSurface: "/reviews/:id",
    txTypes: ["DISPUTE_JUROR_ACCEPT", "DISPUTE_JUROR_DECLINE", "DISPUTE_JUROR_WITHDRAW", "DISPUTE_VOTE_SUBMIT", "DISPUTE_APPEAL"],
    timeLimit: "Dispute windows are shown from backend procedure/deadline fields when available.",
    withdrawalRule: "Withdrawal and reputation consequences are classified by canonical dispute state, not by local UI guesses.",
    consentBoundary: "Dispute juror work requires explicit dispute_review lane opt-in and assignment; public report visibility is not consent.",
  },
  {
    id: "poh_async_review",
    label: "PoH async review",
    shortLabel: "PoH async",
    purpose: "Review proof-of-humanity async evidence for assigned applicants.",
    source: "/v1/poh/async/juror-cases and /v1/poh/async/case/:id",
    workSurface: "/reviews?lane=poh_async_review",
    actionSurface: "/reviews?lane=poh_async_review",
    txTypes: ["POH_ASYNC_JUROR_ACCEPT", "POH_ASYNC_JUROR_DECLINE", "POH_ASYNC_REVIEW"],
    timeLimit: "Async review timing is displayed from the assigned case surface when the backend provides it.",
    withdrawalRule: "Decline/withdraw controls stay inside the PoH async lane and do not affect content review wording.",
    consentBoundary: "PoH async review requires explicit poh_async_review lane opt-in; it is not bundled with content disputes.",
  },
  {
    id: "poh_live_review",
    label: "PoH live review",
    shortLabel: "PoH live",
    purpose: "Participate in live proof-of-humanity sessions and submit attendance/verdicts.",
    source: "/v1/poh/live/assigned, /v1/poh/live/sessions, and live room status routes",
    workSurface: "/reviews?lane=poh_live_review",
    actionSurface: "/verification/live/:caseId",
    txTypes: ["POH_LIVE_JUROR_ACCEPT", "POH_LIVE_JUROR_DECLINE", "POH_LIVE_ATTENDANCE", "POH_LIVE_VERDICT"],
    timeLimit: "Live sessions use backend session/case status; the WebRTC room is transport only.",
    withdrawalRule: "Decline/attendance/verdict actions are live-lane specific and do not unlock content dispute voting.",
    consentBoundary: "PoH live review requires explicit poh_live_review lane opt-in plus assignment; live transport is non-authoritative.",
  },
];

export function reviewLaneById(id: string): ReviewLane | undefined {
  return REVIEW_LANES.find((lane) => lane.id === id);
}


export type ReviewLaneStatus = {
  active: boolean;
  optedIn: boolean;
  paused: boolean;
  label: "Active" | "Paused" | "Opted in" | "Not opted in";
  tone: "ok" | "warning" | "";
  canOptIn: boolean;
  canOptOut: boolean;
};

export function reviewLaneStatusFromTruth(raw: unknown): ReviewLaneStatus {
  const rec = raw && typeof raw === "object" && !Array.isArray(raw) ? (raw as Record<string, any>) : {};
  const statusText = String(rec.status || "").toLowerCase();
  const active = rec.active === true || statusText === "active" || statusText === "activated" || statusText === "enabled";
  const explicitOptedInStatus = statusText === "opted_in" || statusText === "opted_in_inactive" || statusText === "opted_in_pending" || statusText === "pending_activation";
  const optedIn = rec.opted_in === true || active || explicitOptedInStatus;
  const paused = rec.paused === true || rec.suspended === true || rec.disabled === true || !!rec.paused_at_nonce || statusText === "paused" || statusText === "suspended";
  if (active) {
    return { active: true, optedIn: true, paused: false, label: "Active", tone: "ok", canOptIn: false, canOptOut: true };
  }
  if (optedIn && paused) {
    return { active: false, optedIn: true, paused: true, label: "Paused", tone: "warning", canOptIn: false, canOptOut: true };
  }
  if (optedIn) {
    return { active: false, optedIn: true, paused: false, label: "Opted in", tone: "warning", canOptIn: false, canOptOut: true };
  }
  return { active: false, optedIn: false, paused: false, label: "Not opted in", tone: "", canOptIn: true, canOptOut: false };
}

export function reviewLaneStatusPillClass(status: ReviewLaneStatus): string {
  return `statusPill ${status.tone}`.trim();
}
