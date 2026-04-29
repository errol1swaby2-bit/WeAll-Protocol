import { weall } from "../api/weall";
import { voteForAccount } from "./accountSurface";

export type GovernanceVoteCounts = {
  yes: number;
  no: number;
  abstain: number;
};

export type GovernanceProposalSummary = {
  total: number;
  active: number;
  by_stage: Record<string, number>;
};

export type GovernanceProposal = {
  id: string;
  proposal_id: string;
  title: string;
  body: string;
  creator: string;
  stage: string;
  status: string;
  poll_counts: GovernanceVoteCounts;
  counts: GovernanceVoteCounts;
  poll_votes: Record<string, any>;
  votes: Record<string, any>;
  created_at_height: number;
  updated_at_height: number;
  has_actions: boolean;
  execution_count: number;
  counts_current: GovernanceVoteCounts;
  vote_window: "poll" | "final";
  is_active: boolean;
  raw: any;
};

function asRecord(value: unknown): Record<string, any> {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, any>) : {};
}

function asStage(value: unknown): string {
  return String(value || "unknown").trim().toLowerCase() || "unknown";
}

function countVoteMap(value: unknown): GovernanceVoteCounts {
  const map = asRecord(value);
  let yes = 0;
  let no = 0;
  let abstain = 0;
  for (const signer of Object.keys(map).sort()) {
    const rec = asRecord(map[signer]);
    const vote = String(rec.vote || "").trim().toLowerCase();
    if (vote === "yes") yes += 1;
    else if (vote === "no") no += 1;
    else if (vote) abstain += 1;
  }
  return { yes, no, abstain };
}

export function governanceProposalIdOf(value: any): string {
  return String(value?.proposal_id || value?.id || "").trim();
}

export function governanceProposalStageOf(value: any): string {
  return asStage(value?.stage || value?.status);
}

export function governanceProposalTitleOf(value: any): string {
  return String(value?.title || governanceProposalIdOf(value) || "Untitled proposal").trim();
}

export function governanceProposalBodyOf(value: any): string {
  return String(value?.body || value?.description || "").trim();
}

export function governanceProposalCountsOf(value: any): GovernanceVoteCounts {
  const stage = governanceProposalStageOf(value);
  const pollCountsRaw = asRecord(value?.poll_counts);
  const finalCountsRaw = asRecord(value?.counts);
  const currentCountsRaw = asRecord(value?.counts_current);
  const pollVotes = asRecord(value?.poll_votes);
  const finalVotes = asRecord(value?.votes);
  const normalizedPollCounts = Object.keys(pollCountsRaw).length
    ? { yes: Number(pollCountsRaw.yes || 0), no: Number(pollCountsRaw.no || 0), abstain: Number(pollCountsRaw.abstain || 0) }
    : countVoteMap(pollVotes);
  const normalizedFinalCounts = Object.keys(finalCountsRaw).length
    ? { yes: Number(finalCountsRaw.yes || 0), no: Number(finalCountsRaw.no || 0), abstain: Number(finalCountsRaw.abstain || 0) }
    : countVoteMap(finalVotes);
  const finalTotal = normalizedFinalCounts.yes + normalizedFinalCounts.no + normalizedFinalCounts.abstain;
  const pollTotal = normalizedPollCounts.yes + normalizedPollCounts.no + normalizedPollCounts.abstain;
  const currentRawTotal = Number(currentCountsRaw.yes || 0) + Number(currentCountsRaw.no || 0) + Number(currentCountsRaw.abstain || 0);

  if (stage === "poll") return normalizedPollCounts;
  if (currentRawTotal > 0) {
    return {
      yes: Number(currentCountsRaw.yes || 0),
      no: Number(currentCountsRaw.no || 0),
      abstain: Number(currentCountsRaw.abstain || 0),
    };
  }
  if (finalTotal > 0) return normalizedFinalCounts;
  if (pollTotal > 0) return normalizedPollCounts;
  return normalizedFinalCounts;
}

export function normalizeGovernanceProposalSummary(value: any): GovernanceProposalSummary {
  const raw = asRecord(value);
  const byStageRaw = asRecord(raw.by_stage);
  const by_stage: Record<string, number> = {};
  for (const key of Object.keys(byStageRaw).sort()) {
    by_stage[String(key)] = Number(byStageRaw[key] || 0);
  }
  return {
    total: Number(raw.total || 0),
    active: Number(raw.active || 0),
    by_stage,
  };
}

export function normalizeGovernanceProposal(value: any): GovernanceProposal {
  const raw = asRecord(value);
  const proposal_id = governanceProposalIdOf(raw);
  const stage = governanceProposalStageOf(raw);
  const poll_votes = asRecord(raw.poll_votes);
  const votes = asRecord(raw.votes);
  const poll_counts = Object.keys(asRecord(raw.poll_counts)).length ? {
    yes: Number(raw.poll_counts?.yes || 0),
    no: Number(raw.poll_counts?.no || 0),
    abstain: Number(raw.poll_counts?.abstain || 0),
  } : countVoteMap(poll_votes);
  const counts = Object.keys(asRecord(raw.counts)).length ? {
    yes: Number(raw.counts?.yes || 0),
    no: Number(raw.counts?.no || 0),
    abstain: Number(raw.counts?.abstain || 0),
  } : countVoteMap(votes);
  const explicitCurrent = Object.keys(asRecord(raw.counts_current)).length ? {
    yes: Number(raw.counts_current?.yes || 0),
    no: Number(raw.counts_current?.no || 0),
    abstain: Number(raw.counts_current?.abstain || 0),
  } : null;
  const counts_current = explicitCurrent && (explicitCurrent.yes || explicitCurrent.no || explicitCurrent.abstain)
    ? explicitCurrent
    : ((stage === "poll" || !(counts.yes || counts.no || counts.abstain)) && (poll_counts.yes || poll_counts.no || poll_counts.abstain) ? poll_counts : counts);

  return {
    id: proposal_id,
    proposal_id,
    title: governanceProposalTitleOf(raw),
    body: governanceProposalBodyOf(raw),
    creator: String(raw.creator || "").trim(),
    stage,
    status: stage,
    poll_counts,
    counts,
    poll_votes,
    votes,
    created_at_height: Number(raw.created_at_height || 0),
    updated_at_height: Number(raw.updated_at_height || raw.created_at_height || 0),
    has_actions: !!(Array.isArray(raw.actions) && raw.actions.length),
    execution_count: Array.isArray(raw.executions) ? raw.executions.length : Number(raw.execution_count || 0),
    counts_current,
    vote_window:
      String(
        raw.vote_window || ((poll_counts.yes || poll_counts.no || poll_counts.abstain) && !(counts.yes || counts.no || counts.abstain) ? "poll" : stage === "poll" ? "poll" : "final"),
      )
        .trim()
        .toLowerCase() === "poll"
        ? "poll"
        : "final",
    is_active: raw.is_active === undefined ? isGovernanceProposalActive(stage) : !!raw.is_active,
    raw,
  };
}

export function normalizeGovernanceProposalList(items: any[]): GovernanceProposal[] {
  return (Array.isArray(items) ? items : []).map(normalizeGovernanceProposal);
}

export function isGovernanceProposalActive(stageRaw: unknown): boolean {
  const stage = asStage(stageRaw);
  return ["draft", "poll", "voting", "open", "queued", "finalizing", "revision", "validation", "vote", "closed", "tallied"].includes(stage);
}

export function sortGovernanceProposals(items: GovernanceProposal[], mode: string): GovernanceProposal[] {
  const copy = [...items];
  if (mode === "updated_desc") {
    copy.sort((a, b) => b.updated_at_height - a.updated_at_height || b.created_at_height - a.created_at_height || a.id.localeCompare(b.id));
    return copy;
  }
  if (mode === "votes_desc") {
    copy.sort((a, b) => {
      const ac = governanceProposalCountsOf(a);
      const bc = governanceProposalCountsOf(b);
      const at = ac.yes + ac.no + ac.abstain;
      const bt = bc.yes + bc.no + bc.abstain;
      return bt - at || b.updated_at_height - a.updated_at_height || a.id.localeCompare(b.id);
    });
    return copy;
  }
  if (mode === "stage") {
    copy.sort((a, b) => a.stage.localeCompare(b.stage) || b.updated_at_height - a.updated_at_height || a.id.localeCompare(b.id));
    return copy;
  }
  copy.sort((a, b) => b.created_at_height - a.created_at_height || b.updated_at_height - a.updated_at_height || a.id.localeCompare(b.id));
  return copy;
}

export async function loadGovernanceProposalList(base: string, limit = 200): Promise<GovernanceProposal[]> {
  const res: any = await weall.proposals({ limit }, base);
  return normalizeGovernanceProposalList(Array.isArray(res?.items) ? res.items : []);
}

export async function loadGovernanceProposalSurface(
  base: string,
  args?: { limit?: number; activeOnly?: boolean; includeSummary?: boolean; stage?: string },
): Promise<{ items: GovernanceProposal[]; summary: GovernanceProposalSummary | null }> {
  const res: any = await weall.proposals(
    {
      limit: args?.limit ?? 200,
      activeOnly: !!args?.activeOnly,
      includeSummary: !!args?.includeSummary,
      stage: args?.stage,
    },
    base,
  );
  return {
    items: normalizeGovernanceProposalList(Array.isArray(res?.items) ? res.items : []),
    summary: res?.summary ? normalizeGovernanceProposalSummary(res.summary) : null,
  };
}

export async function loadActiveGovernanceProposals(
  base: string,
  limit = 200,
): Promise<{ items: GovernanceProposal[]; summary: GovernanceProposalSummary | null }> {
  return loadGovernanceProposalSurface(base, { limit, activeOnly: true, includeSummary: true });
}

export async function reconcileProposalVisible(proposalId: string, base: string): Promise<{ phase: "confirmed" | "submitted" | "failed" | "unknown"; detail?: string } | null> {
  if (!proposalId) return null;
  try {
    const raw = await weall.proposal(proposalId, base);
    const proposal = normalizeGovernanceProposal((raw as any)?.proposal || raw);
    if (proposal.id) {
      return {
        phase: "confirmed",
        detail: `Proposal ${proposalId} is visible on the governance surface.`,
      };
    }
  } catch {
    // ignore and fall back to list scan
  }

  try {
    const items = await loadGovernanceProposalList(base, 200);
    if (items.some((item) => item.id === proposalId)) {
      return {
        phase: "confirmed",
        detail: `Proposal ${proposalId} is listed in governance.`,
      };
    }
  } catch {
    // ignore
  }

  return null;
}

export async function reconcileProposalVote(args: {
  proposalId: string;
  account: string;
  choice: "yes" | "no" | "abstain";
  base: string;
}): Promise<{ phase: "confirmed" | "submitted" | "failed" | "unknown"; detail?: string } | null> {
  if (!args.proposalId || !args.account) return null;
  try {
    const raw: any = await weall.proposalVotes(args.proposalId, args.base);
    const stage = governanceProposalStageOf(raw?.stage);
    const voteMap = asRecord((stage === "poll" ? raw?.poll_votes : raw?.votes) || raw?.votes || raw?.poll_votes);
    const current = String(voteForAccount(voteMap, args.account)?.vote || "").trim().toLowerCase();
    if (current === args.choice) {
      return {
        phase: "confirmed",
        detail: `Proposal ${args.proposalId} now records your ${args.choice.toUpperCase()} vote.`,
      };
    }
  } catch {
    // ignore
  }
  return null;
}

export async function reconcileProposalWithdrawal(args: {
  proposalId: string;
  base: string;
}): Promise<{ phase: "confirmed" | "submitted" | "failed" | "unknown"; detail?: string } | null> {
  if (!args.proposalId) return null;
  try {
    const raw: any = await weall.proposal(args.proposalId, args.base);
    const proposal = normalizeGovernanceProposal(raw?.proposal || raw);
    if (proposal.stage === "withdrawn") {
      return {
        phase: "confirmed",
        detail: `Proposal ${args.proposalId} is now withdrawn on the governance surface.`,
      };
    }
    if (proposal.id) {
      return {
        phase: "submitted",
        detail: `Proposal ${args.proposalId} is visible, but withdrawal is still settling through the lifecycle surface.`,
      };
    }
  } catch {
    // ignore
  }
  return null;
}

export async function reconcileProposalEdit(args: {
  proposalId: string;
  title?: string;
  body?: string;
  base: string;
}): Promise<{ phase: "confirmed" | "submitted" | "failed" | "unknown"; detail?: string } | null> {
  if (!args.proposalId) return null;
  const title = String(args.title || "").trim();
  const body = String(args.body || "").trim();
  try {
    const raw: any = await weall.proposal(args.proposalId, args.base);
    const proposal = normalizeGovernanceProposal(raw?.proposal || raw);
    if (proposal.id && (!title || proposal.title === title) && (!body || proposal.body === body)) {
      return {
        phase: "confirmed",
        detail: `Proposal ${args.proposalId} now reflects the latest edited content.`,
      };
    }
    if (proposal.id) {
      return {
        phase: "submitted",
        detail: `Proposal ${args.proposalId} is visible, but the edited content is still settling.`,
      };
    }
  } catch {
    // ignore
  }
  return null;
}
