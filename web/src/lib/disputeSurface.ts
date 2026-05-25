import { accountVariants, recordForAccount, voteForAccount } from "./accountSurface";

function asRecord(value: unknown): Record<string, any> {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, any>) : {};
}

function selfScopedJurorRecord(src: Record<string, any>, account: string): Record<string, any> | null {
  const variants = new Set(accountVariants(account));
  for (const key of ["current_juror", "viewer_juror", "juror_self"]) {
    const rec = asRecord(src[key]);
    if (!Object.keys(rec).length) continue;
    const recAccount = String(rec.account || rec.juror || rec.juror_id || "").trim();
    if (!recAccount || variants.has(recAccount)) return rec;
  }
  return null;
}

function listContainsAccount(list: unknown, account: string): string {
  if (!Array.isArray(list)) return "";
  const variants = new Set(accountVariants(account));
  for (const raw of list) {
    const candidate = String(raw || "").trim();
    if (candidate && variants.has(candidate)) return candidate;
  }
  return "";
}

export function disputeJurorRecord(dispute: unknown, account: string): Record<string, any> {
  const src = asRecord(dispute);
  const scoped = selfScopedJurorRecord(src, account);
  const jurors = recordForAccount(src.jurors, account);
  const assignedJurors = recordForAccount(src.assigned_jurors, account);
  const eligible = listContainsAccount(src.eligible_juror_ids, account);
  if (scoped || jurors || assignedJurors) return asRecord(scoped || jurors || assignedJurors);
  if (eligible) return { account: eligible, juror: eligible, status: "assigned", source: "eligible_juror_ids" };

  // Controlled bootstrap report escalation can produce a SYSTEM dispute before
  // the follow-up assignment receipt is visible in the read model. Keep global
  // juror maps redacted, but let a signed reviewer attempt the accept action
  // when the report is explicitly in the single-reviewer bootstrap shape. The
  // backend apply layer remains authoritative and will reject unauthorized txs.
  const stage = String(src.stage || src.status || "").trim().toLowerCase();
  const disputeId = String(src.id || src.dispute_id || "").trim();
  const openedBy = String(src.opened_by || "").trim().toUpperCase();
  const requiredVotes = Number(src.required_votes || 0);
  const eligibleCount = Number(src.eligible_validator_count || 0);
  const bootstrapSingleReviewer =
    (stage === "juror_review" || stage === "open" || stage === "assigned") &&
    (openedBy === "SYSTEM" || disputeId.startsWith("dispute:SYSTEM:")) &&
    (requiredVotes <= 1 || eligibleCount <= 1);
  if (bootstrapSingleReviewer) {
    return { account, juror: account, status: "assigned", source: "bootstrap_single_reviewer_fallback" };
  }

  return {};
}

export function disputeJurorStatus(dispute: unknown, account: string): string {
  if (!String(account || "").trim()) return "unassigned";
  return String(disputeJurorRecord(dispute, account).status || "unassigned").trim().toLowerCase() || "unassigned";
}

export function disputeAttendancePresent(dispute: unknown, account: string): boolean {
  return !!asRecord(disputeJurorRecord(dispute, account).attendance).present;
}

export function disputeCurrentVote(dispute: unknown, account: string): string {
  return String(voteForAccount(asRecord(dispute).votes, account)?.vote || "").trim().toLowerCase();
}

export function disputeVoteCountSummary(dispute: unknown): { yes: number; no: number; abstain: number; total: number } {
  const votes = asRecord(asRecord(dispute).votes);
  let yes = 0;
  let no = 0;
  let abstain = 0;
  for (const key of Object.keys(votes).sort()) {
    const vote = String(asRecord(votes[key]).vote || "").trim().toLowerCase();
    if (vote === "yes") yes += 1;
    else if (vote === "no") no += 1;
    else if (vote) abstain += 1;
  }
  return { yes, no, abstain, total: yes + no + abstain };
}

export function disputeReviewUnlocked(args: {
  dispute: unknown;
  account: string;
  tierGateOk: boolean;
  signerBusy: boolean;
}): boolean {
  const { dispute, account, tierGateOk, signerBusy } = args;
  const jurorStatus = disputeJurorStatus(dispute, account);
  return !!dispute && !!String(account || "").trim() && !signerBusy && tierGateOk && (jurorStatus === "accepted" || jurorStatus === "review") && disputeAttendancePresent(dispute, account) && !disputeCurrentVote(dispute, account);
}

export function disputeStageClass(stage: string): string {
  const s = String(stage || "").toLowerCase();
  if (["resolved", "closed", "finalized"].includes(s)) return "statusPill ok";
  if (["open", "review", "voting", "assigned", "juror_review"].includes(s)) return "statusPill";
  return "statusPill";
}
