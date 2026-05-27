export type ProcedureClockInput = {
  currentHeight?: unknown;
  deadlineHeight?: unknown;
  targetBlockIntervalMs?: unknown;
};

export type ProcedureClockDisplay = {
  currentHeight: number;
  deadlineHeight: number;
  blocksRemaining: number;
  estimatedMsRemaining: number;
  estimatedLabel: string;
  hasDeadline: boolean;
};

function asPositiveInt(value: unknown, fallback = 0): number {
  const n = Number(value);
  if (!Number.isFinite(n) || n < 0) return fallback;
  return Math.floor(n);
}

export function estimateProcedureClock(input: ProcedureClockInput): ProcedureClockDisplay {
  const currentHeight = asPositiveInt(input.currentHeight, 0);
  const deadlineHeight = asPositiveInt(input.deadlineHeight, 0);
  const intervalMs = asPositiveInt(input.targetBlockIntervalMs, 20_000) || 20_000;
  const hasDeadline = deadlineHeight > 0;
  const blocksRemaining = hasDeadline ? Math.max(0, deadlineHeight - currentHeight) : 0;
  const estimatedMsRemaining = blocksRemaining * intervalMs;
  return {
    currentHeight,
    deadlineHeight,
    blocksRemaining,
    estimatedMsRemaining,
    estimatedLabel: formatEstimatedDuration(estimatedMsRemaining),
    hasDeadline,
  };
}

export function formatEstimatedDuration(ms: number): string {
  const seconds = Math.max(0, Math.round(ms / 1000));
  if (seconds <= 0) return "now or next finalized block";
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const secs = seconds % 60;
  if (hours > 0) return `about ${hours}h ${minutes}m`;
  if (minutes > 0) return `about ${minutes}m ${secs}s`;
  return `about ${secs}s`;
}

export function proposalDeadlineHeight(proposal: any): number {
  const stage = String(proposal?.stage || "").toLowerCase();
  const rules = proposal?.rules && typeof proposal.rules === "object" ? proposal.rules : {};
  const fieldByStage: Record<string, [string, string]> = {
    draft: ["draft_at_height", "draft_period_blocks"],
    poll: ["poll_opened_at_height", "poll_period_blocks"],
    revision: ["revision_opened_at_height", "revision_period_blocks"],
    validation: ["validation_opened_at_height", "validation_period_blocks"],
    voting: ["voting_opened_at_height", "voting_period_blocks"],
    vote: ["voting_opened_at_height", "voting_period_blocks"],
    closed: ["closed_at_height", "execute_delay_blocks"],
    tallied: ["tallied_at_height", "execute_delay_blocks"],
    executed: ["executed_at_height", "finalize_delay_blocks"],
  };
  const pair = fieldByStage[stage];
  if (!pair) return asPositiveInt(proposal?.deadline_height || proposal?.next_deadline_height, 0);
  const start = asPositiveInt(proposal?.[pair[0]], 0);
  const window = asPositiveInt(rules?.[pair[1]], 0);
  if (start > 0 && window > 0) return start + window;
  return asPositiveInt(proposal?.deadline_height || proposal?.next_deadline_height, 0);
}

export function disputeDeadlineHeight(dispute: any): number {
  return asPositiveInt(
    dispute?.appeal_deadline_height ||
      dispute?.review_deadline_height ||
      dispute?.evidence_deadline_height ||
      dispute?.deadline_height ||
      dispute?.next_deadline_height,
    0,
  );
}

export function currentProcedureHeight(record: any): number {
  return asPositiveInt(
    record?.current_procedure_height ||
      record?.finalized_height ||
      record?.current_height ||
      record?.height ||
      record?.updated_at_height ||
      record?.created_at_height,
    0,
  );
}

export function targetBlockIntervalMs(record: any): number {
  const clock = record?.constitutional_clock && typeof record.constitutional_clock === "object" ? record.constitutional_clock : {};
  return asPositiveInt(record?.target_block_interval_ms || clock?.target_block_interval_ms, 20_000) || 20_000;
}
