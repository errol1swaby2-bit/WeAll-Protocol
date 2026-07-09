import { weall } from "../api/weall";
import { getAuthHeaders } from "../auth/session";
import { confirmed, firstReconcile, submitted, type ReconcileResult } from "./revalidation";

type DisputeMutationType = "DISPUTE_JUROR_ACCEPT" | "DISPUTE_JUROR_DECLINE" | "DISPUTE_JUROR_ATTENDANCE" | "DISPUTE_VOTE_SUBMIT";

type ReconcileDisputeMutationArgs = {
  disputeId: string;
  account: string;
  txType: DisputeMutationType;
  vote?: "yes" | "no" | "abstain" | null;
  base: string;
};

function accountVariants(value: string): string[] {
  const raw = String(value || "").trim();
  if (!raw) return [];
  const base = raw.startsWith("@") ? raw.slice(1) : raw;
  return Array.from(new Set([raw, base ? `@${base}` : "", base].filter(Boolean)));
}

function accountRecord(source: any, account: string): any {
  if (!source || typeof source !== "object") return null;
  for (const variant of accountVariants(account)) {
    const rec = (source as Record<string, any>)[variant];
    if (rec !== undefined) return rec;
  }
  return null;
}

function normalizeStatus(value: unknown): string {
  return String(value || "").trim().toLowerCase();
}

function acceptedInDispute(dispute: any, account: string): boolean {
  const rec =
    accountRecord(dispute?.current_juror, account) ||
    accountRecord(dispute?.viewer_juror, account) ||
    accountRecord(dispute?.juror_self, account) ||
    accountRecord(dispute?.jurors, account) ||
    accountRecord(dispute?.assigned_jurors, account) ||
    accountRecord(dispute?.juror_assignments, account);
  return [rec?.status, rec?.state, rec?.phase, rec?.decision].map(normalizeStatus).some((status) =>
    ["accepted", "present", "attended", "review", "completed"].includes(status),
  );
}

function declinedInDispute(dispute: any, account: string): boolean {
  const rec =
    accountRecord(dispute?.current_juror, account) ||
    accountRecord(dispute?.viewer_juror, account) ||
    accountRecord(dispute?.juror_self, account) ||
    accountRecord(dispute?.jurors, account) ||
    accountRecord(dispute?.assigned_jurors, account) ||
    accountRecord(dispute?.juror_assignments, account);
  return [rec?.status, rec?.state, rec?.phase, rec?.decision].map(normalizeStatus).includes("declined");
}

function attendanceMarked(dispute: any, account: string): boolean {
  const rec =
    accountRecord(dispute?.current_juror, account) ||
    accountRecord(dispute?.viewer_juror, account) ||
    accountRecord(dispute?.juror_self, account) ||
    accountRecord(dispute?.juror_attendance, account) ||
    accountRecord(dispute?.attendance, account) ||
    accountRecord(dispute?.jurors, account);
  const attendance = rec && typeof rec.attendance === "object" && rec.attendance ? rec.attendance : null;
  return rec?.present === true || rec?.attended === true || attendance?.present === true || ["present", "attended", "completed"].includes(normalizeStatus(rec?.status));
}

function voteRecorded(votesRaw: any, account: string, expectedVote: string): boolean {
  const rec = accountRecord(votesRaw?.votes, account) || accountRecord(votesRaw, account);
  return normalizeStatus(rec?.vote) === normalizeStatus(expectedVote);
}

function scopedHeaders(account: string): HeadersInit | undefined {
  try {
    return getAuthHeaders(account);
  } catch {
    return undefined;
  }
}

export async function reconcileDisputeMutation(args: ReconcileDisputeMutationArgs): Promise<ReconcileResult | null> {
  const disputeId = String(args.disputeId || "").trim();
  const account = String(args.account || "").trim();
  if (!disputeId || !account) return null;
  const headers = scopedHeaders(account);

  return firstReconcile(
    async () => {
      const raw: any = await weall.dispute(disputeId, args.base, headers);
      const dispute = raw?.dispute || raw || null;
      if (!dispute) return null;

      if (args.txType === "DISPUTE_JUROR_ACCEPT") {
        if (acceptedInDispute(dispute, account)) {
          return confirmed(`Dispute ${disputeId} now shows your juror acceptance.`);
        }
        return submitted(`Dispute ${disputeId} is visible, but juror acceptance is still settling.`);
      }

      if (args.txType === "DISPUTE_JUROR_DECLINE") {
        if (declinedInDispute(dispute, account)) {
          return confirmed(`Dispute ${disputeId} now shows your juror decline.`);
        }
        return submitted(`Dispute ${disputeId} is visible, but juror decline is still settling.`);
      }

      if (args.txType === "DISPUTE_JUROR_ATTENDANCE") {
        if (attendanceMarked(dispute, account)) {
          return confirmed(`Dispute ${disputeId} now shows your attendance.`);
        }
        return submitted(`Dispute ${disputeId} is visible, but attendance is still settling.`);
      }

      return null;
    },
    args.txType === "DISPUTE_VOTE_SUBMIT"
      ? async () => {
          const votesRaw: any = await weall.disputeVotes(disputeId, args.base, headers);
          if (voteRecorded(votesRaw, account, String(args.vote || ""))) {
            return confirmed(`Dispute ${disputeId} now records your ${String(args.vote || "").toUpperCase()} vote.`);
          }
          return submitted(`Dispute ${disputeId} is visible, but the juror vote surface is still settling.`);
        }
      : null,
  );
}
