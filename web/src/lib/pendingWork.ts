import {
  governanceProposalStageOf,
  governanceProposalTitleOf,
  normalizeGovernanceProposalList,
  type GovernanceProposal,
} from "./governance";
import { voteForAccount } from "./accountSurface";
import { disputeAttendancePresent, disputeCurrentVote, disputeJurorStatus } from "./disputeSurface";

export type PendingWorkKind = "decision" | "report" | "membership";
export type PendingWorkEmphasis = "assigned" | "available";
export type PendingWorkUrgency = "high" | "medium" | "low";

export type PendingWorkItem = {
  id: string;
  kind: PendingWorkKind;
  label: string;
  detail: string;
  href: string;
  emphasis: PendingWorkEmphasis;
  urgency: PendingWorkUrgency;
  assigned: boolean;
  available: boolean;
  stage: string;
  sortKey: string;
  source: string;
};

export type PendingWorkSummary = {
  items: PendingWorkItem[];
  counts: {
    total: number;
    assigned: number;
    available: number;
    decisions: number;
    reports: number;
    /** Backward-compatible internal aliases for existing summary consumers. */
    proposals: number;
    disputes: number;
    memberships: number;
  };
};

function asRecord(value: unknown): Record<string, any> {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, any>) : {};
}

function toArray<T>(value: unknown): T[] {
  return Array.isArray(value) ? (value as T[]) : [];
}

function normalizeStage(value: unknown, fallback = "unknown"): string {
  const stage = String(value || fallback).trim().toLowerCase();
  return stage || fallback;
}

function accountVoteOf(voteMap: Record<string, any>, account: string): string {
  if (!account) return "";
  return String(voteForAccount(voteMap, account)?.vote || "").trim().toLowerCase();
}

function decisionVoteWindow(proposal: GovernanceProposal): "early_input" | "final" {
  const explicit = String(proposal.vote_window || "").trim().toLowerCase();
  if (explicit === "poll") return "early_input";
  if (explicit === "final") return "final";
  const stage = governanceProposalStageOf(proposal);
  if (stage === "poll" || stage === "draft" || stage === "revision" || stage === "validation") return "early_input";
  return "final";
}

function decisionVoteWindowOpen(stage: string): boolean {
  return ["poll", "voting", "vote"].includes(stage);
}

function decisionCurrentVote(proposal: GovernanceProposal, account: string): string {
  const window = decisionVoteWindow(proposal);
  if (window === "early_input") return accountVoteOf(proposal.poll_votes, account);
  return accountVoteOf(proposal.votes, account);
}

function decisionUrgency(stage: string, hasCurrentVote: boolean): PendingWorkUrgency {
  if (hasCurrentVote) return "low";
  if (["vote", "voting", "poll", "queued", "finalizing", "closed", "tallied"].includes(stage)) return "high";
  if (["draft", "revision", "validation", "open"].includes(stage)) return "medium";
  return "low";
}

function decisionDetail(stage: string, hasCurrentVote: boolean, voteWindow: "early_input" | "final"): string {
  const stageLabel = stage.replace(/_/g, " ");
  if (hasCurrentVote) {
    return `Your ${voteWindow === "early_input" ? "early input" : "vote"} is already recorded · ${stageLabel}`;
  }
  if (voteWindow === "early_input") {
    return `Decision needs your early input · ${stageLabel}`;
  }
  return `Decision needs your vote · ${stageLabel}`;
}

function reportCurrentStatus(dispute: Record<string, any>, account: string): string {
  return disputeJurorStatus(dispute, account);
}

function reportStageNeedsReviewerAction(stage: string): boolean {
  return ["open", "assigned", "review", "juror_review", "voting", "in_review"].includes(stage);
}

function reportUrgency(reviewerStatus: string, attendancePresent: boolean, vote: string): PendingWorkUrgency {
  if ((reviewerStatus === "accepted" || reviewerStatus === "review") && attendancePresent && !vote) return "high";
  if (reviewerStatus === "assigned") return "high";
  if ((reviewerStatus === "accepted" || reviewerStatus === "review") && !attendancePresent) return "medium";
  if (reviewerStatus === "unassigned") return "low";
  return "low";
}

function reportDetail(reviewerStatus: string, attendancePresent: boolean, vote: string, stage: string): string {
  const stageLabel = stage.replace(/_/g, " ");
  if (vote) return `Your review choice is already recorded · ${stageLabel}`;
  if (reviewerStatus === "assigned") return `Review assignment waiting for your response · ${stageLabel}`;
  if ((reviewerStatus === "accepted" || reviewerStatus === "review") && !attendancePresent) return `Check-in is still required before your final review choice · ${stageLabel}`;
  if ((reviewerStatus === "accepted" || reviewerStatus === "review") && attendancePresent) return `Ready for your review choice · ${stageLabel}`;
  return `Available report context · ${stageLabel}`;
}

function membershipPhaseOf(raw: Record<string, any>): string {
  return normalizeStage(raw.phase || raw.status, "pending");
}

function membershipUrgency(phase: string): PendingWorkUrgency {
  if (["pending", "review", "awaiting_decision"].includes(phase)) return "medium";
  return "low";
}

function urgencyWeight(value: PendingWorkUrgency): number {
  if (value === "high") return 0;
  if (value === "medium") return 1;
  return 2;
}

function emphasisWeight(assigned: boolean): number {
  return assigned ? 0 : 1;
}

export function derivePendingWork(args: {
  account: string;
  proposalsRaw: unknown;
  disputesRaw: unknown;
  membershipsRaw?: unknown;
  maxItems?: number;
}): PendingWorkSummary {
  const account = String(args.account || "").trim();
  const maxItems = Math.max(1, Number(args.maxItems || 6));

  const decisionItems = normalizeGovernanceProposalList(toArray<any>(asRecord(args.proposalsRaw).items))
    .map((proposal): PendingWorkItem | null => {
      const id = String(proposal.id || proposal.proposal_id || "").trim();
      if (!id) return null;
      const stage = governanceProposalStageOf(proposal);
      const voteWindow = decisionVoteWindow(proposal);
      const currentVote = decisionCurrentVote(proposal, account);
      const voteOpen = decisionVoteWindowOpen(stage);
      if (!voteOpen || currentVote) return null;
      const assigned = !!account;
      const urgency = decisionUrgency(stage, !!currentVote);
      return {
        id,
        kind: "decision",
        label: governanceProposalTitleOf(proposal),
        detail: decisionDetail(stage, false, voteWindow),
        href: `/decisions/${encodeURIComponent(id)}`,
        emphasis: assigned ? "assigned" : "available",
        urgency,
        assigned,
        available: true,
        stage,
        sortKey: `${String(9_999_999 - Number(proposal.updated_at_height || proposal.created_at_height || 0)).padStart(8, "0")}:${id}`,
        source: voteWindow === "early_input" ? "decision-early-input" : "decision-vote",
      };
    })
    .filter((item): item is PendingWorkItem => !!item);

  const reportItems = toArray<any>(asRecord(args.disputesRaw).items)
    .map((raw, index): PendingWorkItem | null => {
      const dispute = asRecord(raw);
      const id = String(dispute.id || dispute.case_id || dispute.dispute_id || dispute.tx_id || `dispute-${index}`).trim();
      if (!id) return null;
      const stage = normalizeStage(dispute.stage || dispute.status, "open");
      const label = String(dispute.title || dispute.reason || `Report ${index + 1}`).trim() || `Report ${index + 1}`;
      const reviewerStatus = reportCurrentStatus(dispute, account);
      const attendancePresent = disputeAttendancePresent(dispute, account);
      const vote = disputeCurrentVote(dispute, account);
      if (vote || !reportStageNeedsReviewerAction(stage)) return null;
      const assigned = reviewerStatus !== "unassigned" && reviewerStatus !== "declined";
      if (account && !assigned) return null;
      const available = assigned || !account;
      const urgency = reportUrgency(reviewerStatus, attendancePresent, vote);
      return {
        id,
        kind: "report",
        label,
        detail: reportDetail(reviewerStatus, attendancePresent, vote, stage),
        href: assigned ? `/reviews/${encodeURIComponent(id)}` : `/reports/${encodeURIComponent(id)}`,
        emphasis: assigned ? "assigned" : "available",
        urgency,
        assigned,
        available,
        stage,
        sortKey: `${String(index).padStart(4, "0")}:${id}`,
        source: reviewerStatus === "assigned" ? "report-assigned" : reviewerStatus === "accepted" || reviewerStatus === "review" ? "report-review" : "report-open",
      };
    })
    .filter((item): item is PendingWorkItem => !!item)
    .filter((item) => item.available);

  const membershipItems = toArray<any>(asRecord(args.membershipsRaw).items ?? args.membershipsRaw)
    .map((raw, index): PendingWorkItem | null => {
      const item = asRecord(raw);
      const id = String(item.group_id || item.id || item.membership_id || `membership-${index}`).trim();
      if (!id) return null;
      const phase = membershipPhaseOf(item);
      return {
        id,
        kind: "membership",
        label: String(item.group_name || item.title || item.name || `Membership ${index + 1}`).trim() || `Membership ${index + 1}`,
        detail: `Membership posture: ${phase.replace(/_/g, " ")}` ,
        href: `/groups/${encodeURIComponent(id)}`,
        emphasis: "assigned",
        urgency: membershipUrgency(phase),
        assigned: true,
        available: true,
        stage: phase,
        sortKey: `${String(index).padStart(4, "0")}:${id}`,
        source: "membership-review",
      };
    })
    .filter((item): item is PendingWorkItem => !!item);

  const rankedItems = [...decisionItems, ...reportItems, ...membershipItems]
    .sort((a, b) => {
      const urgencyDelta = urgencyWeight(a.urgency) - urgencyWeight(b.urgency);
      if (urgencyDelta !== 0) return urgencyDelta;
      const emphasisDelta = emphasisWeight(a.assigned) - emphasisWeight(b.assigned);
      if (emphasisDelta !== 0) return emphasisDelta;
      const kindDelta = a.kind.localeCompare(b.kind);
      if (kindDelta !== 0) return kindDelta;
      return a.sortKey.localeCompare(b.sortKey);
    });

  const items = rankedItems.slice(0, maxItems);

  return {
    items,
    counts: {
      total: rankedItems.length,
      assigned: rankedItems.filter((item) => item.assigned).length,
      available: rankedItems.filter((item) => item.available).length,
      decisions: rankedItems.filter((item) => item.kind === "decision").length,
      reports: rankedItems.filter((item) => item.kind === "report").length,
      proposals: rankedItems.filter((item) => item.kind === "decision").length,
      disputes: rankedItems.filter((item) => item.kind === "report").length,
      memberships: rankedItems.filter((item) => item.kind === "membership").length,
    },
  };
}
