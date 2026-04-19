import {
  governanceProposalStageOf,
  governanceProposalTitleOf,
  normalizeGovernanceProposalList,
  type GovernanceProposal,
} from "./governance";

export type PendingWorkKind = "proposal" | "dispute" | "membership";
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
  return String(asRecord(voteMap)[account]?.vote || "").trim().toLowerCase();
}

function proposalVoteWindow(proposal: GovernanceProposal): "poll" | "final" {
  const explicit = String(proposal.vote_window || "").trim().toLowerCase();
  if (explicit === "poll") return "poll";
  if (explicit === "final") return "final";
  const stage = governanceProposalStageOf(proposal);
  if (stage === "poll" || stage === "draft" || stage === "revision" || stage === "validation") return "poll";
  return "final";
}

function proposalCurrentVote(proposal: GovernanceProposal, account: string): string {
  const window = proposalVoteWindow(proposal);
  if (window === "poll") return accountVoteOf(proposal.poll_votes, account);
  return accountVoteOf(proposal.votes, account);
}

function proposalUrgency(stage: string, hasCurrentVote: boolean): PendingWorkUrgency {
  if (hasCurrentVote) return "low";
  if (["vote", "voting", "poll", "queued", "finalizing", "closed", "tallied"].includes(stage)) return "high";
  if (["draft", "revision", "validation", "open"].includes(stage)) return "medium";
  return "low";
}

function proposalDetail(stage: string, hasCurrentVote: boolean, voteWindow: "poll" | "final"): string {
  const stageLabel = stage.replace(/_/g, " ");
  if (hasCurrentVote) {
    return `Already recorded on ${voteWindow === "poll" ? "poll" : "vote"} surface · ${stageLabel}`;
  }
  if (voteWindow === "poll") {
    return `Awaiting poll input · ${stageLabel}`;
  }
  return `Awaiting governance vote · ${stageLabel}`;
}

function jurorRecord(dispute: Record<string, any>, account: string): Record<string, any> {
  const jurors = asRecord(dispute?.jurors);
  const assignedJurors = asRecord(dispute?.assigned_jurors);
  return asRecord(jurors[account] || assignedJurors[account]);
}

function disputeCurrentStatus(dispute: Record<string, any>, account: string): string {
  if (!account) return "unassigned";
  return normalizeStage(jurorRecord(dispute, account)?.status, "unassigned");
}

function disputeAttendancePresent(dispute: Record<string, any>, account: string): boolean {
  return !!asRecord(jurorRecord(dispute, account)?.attendance).present;
}

function disputeCurrentVote(dispute: Record<string, any>, account: string): string {
  return String(asRecord(asRecord(dispute?.votes)[account])?.vote || "").trim().toLowerCase();
}

function disputeUrgency(jurorStatus: string, attendancePresent: boolean, vote: string): PendingWorkUrgency {
  if ((jurorStatus === "accepted" || jurorStatus === "review") && attendancePresent && !vote) return "high";
  if (jurorStatus === "assigned") return "high";
  if ((jurorStatus === "accepted" || jurorStatus === "review") && !attendancePresent) return "medium";
  if (jurorStatus === "unassigned") return "low";
  return "low";
}

function disputeDetail(jurorStatus: string, attendancePresent: boolean, vote: string, stage: string): string {
  const stageLabel = stage.replace(/_/g, " ");
  if (vote) return `Your vote is already recorded · ${stageLabel}`;
  if (jurorStatus === "assigned") return `Assignment waiting for response · ${stageLabel}`;
  if ((jurorStatus === "accepted" || jurorStatus === "review") && !attendancePresent) return `Attendance still required · ${stageLabel}`;
  if ((jurorStatus === "accepted" || jurorStatus === "review") && attendancePresent) return `Ready for juror vote · ${stageLabel}`;
  return `Available dispute context · ${stageLabel}`;
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

  const proposalItems = normalizeGovernanceProposalList(toArray<any>(asRecord(args.proposalsRaw).items))
    .map((proposal): PendingWorkItem | null => {
      const id = String(proposal.id || proposal.proposal_id || "").trim();
      if (!id) return null;
      const stage = governanceProposalStageOf(proposal);
      const voteWindow = proposalVoteWindow(proposal);
      const currentVote = proposalCurrentVote(proposal, account);
      const assigned = !currentVote && !!account;
      const urgency = proposalUrgency(stage, !!currentVote);
      return {
        id,
        kind: "proposal",
        label: governanceProposalTitleOf(proposal),
        detail: proposalDetail(stage, !!currentVote, voteWindow),
        href: `/proposal/${encodeURIComponent(id)}`,
        emphasis: assigned ? "assigned" : "available",
        urgency,
        assigned,
        available: !currentVote,
        stage,
        sortKey: `${String(9_999_999 - Number(proposal.updated_at_height || proposal.created_at_height || 0)).padStart(8, "0")}:${id}`,
        source: currentVote ? "proposal-voted" : voteWindow === "poll" ? "proposal-poll" : "proposal-vote",
      };
    })
    .filter((item): item is PendingWorkItem => !!item)
    .filter((item) => item.available || item.assigned);

  const disputeItems = toArray<any>(asRecord(args.disputesRaw).items)
    .map((raw, index): PendingWorkItem | null => {
      const dispute = asRecord(raw);
      const id = String(dispute.id || dispute.case_id || dispute.dispute_id || dispute.tx_id || `dispute-${index}`).trim();
      if (!id) return null;
      const stage = normalizeStage(dispute.stage || dispute.status, "open");
      const label = String(dispute.title || dispute.reason || `Dispute ${index + 1}`).trim() || `Dispute ${index + 1}`;
      const jurorStatus = disputeCurrentStatus(dispute, account);
      const attendancePresent = disputeAttendancePresent(dispute, account);
      const vote = disputeCurrentVote(dispute, account);
      const assigned = jurorStatus !== "unassigned" && jurorStatus !== "declined";
      const available = assigned || !account;
      const urgency = disputeUrgency(jurorStatus, attendancePresent, vote);
      return {
        id,
        kind: "dispute",
        label,
        detail: disputeDetail(jurorStatus, attendancePresent, vote, stage),
        href: `/disputes/${encodeURIComponent(id)}`,
        emphasis: assigned ? "assigned" : "available",
        urgency,
        assigned,
        available,
        stage,
        sortKey: `${String(index).padStart(4, "0")}:${id}`,
        source: jurorStatus === "assigned" ? "dispute-assigned" : jurorStatus === "accepted" || jurorStatus === "review" ? "dispute-review" : "dispute-open",
      };
    })
    .filter((item): item is PendingWorkItem => !!item)
    .filter((item) => item.available);

  const items = [...proposalItems, ...disputeItems]
    .sort((a, b) => {
      const urgencyDelta = urgencyWeight(a.urgency) - urgencyWeight(b.urgency);
      if (urgencyDelta !== 0) return urgencyDelta;
      const emphasisDelta = emphasisWeight(a.assigned) - emphasisWeight(b.assigned);
      if (emphasisDelta !== 0) return emphasisDelta;
      const kindDelta = a.kind.localeCompare(b.kind);
      if (kindDelta !== 0) return kindDelta;
      return a.sortKey.localeCompare(b.sortKey);
    })
    .slice(0, maxItems);

  return {
    items,
    counts: {
      total: items.length,
      assigned: items.filter((item) => item.assigned).length,
      available: items.filter((item) => item.available).length,
      proposals: items.filter((item) => item.kind === "proposal").length,
      disputes: items.filter((item) => item.kind === "dispute").length,
      memberships: items.filter((item) => item.kind === "membership").length,
    },
  };
}
