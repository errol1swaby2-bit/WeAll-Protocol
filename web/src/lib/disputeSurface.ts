import { recordForAccount, voteForAccount } from "./accountSurface";

function asRecord(value: unknown): Record<string, any> {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, any>) : {};
}

export function disputeJurorRecord(dispute: unknown, account: string): Record<string, any> {
  const src = asRecord(dispute);
  const jurors = recordForAccount(src.jurors, account);
  const assignedJurors = recordForAccount(src.assigned_jurors, account);
  return asRecord(jurors || assignedJurors);
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
