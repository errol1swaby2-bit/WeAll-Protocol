export type VerificationLevel = "basic" | "verified" | "trusted";

export type TrustedResponsibilityKey =
  | "community_reviewer"
  | "group_moderator"
  | "network_helper"
  | "storage_helper"
  | "network_operator"
  | "validator"
  | "creator"
  | "treasury_signer"
  | "emissary";

export type TrustedResponsibility = {
  key: TrustedResponsibilityKey | string;
  label: string;
  description: string;
  requires: string;
};

export const VERIFICATION_LABELS: Record<VerificationLevel, string> = {
  basic: "Basic Account",
  verified: "Verified Person",
  trusted: "Trusted Verified Person",
};

export const VERIFICATION_SUMMARIES: Record<VerificationLevel, string> = {
  basic: "You can browse, set up your profile, and start account verification.",
  verified: "You completed a basic human review. You can join groups, message people, and take part in basic community activity.",
  trusted: "You completed a live community review. You can create posts, vote in community decisions, report harmful content, and apply for trusted responsibilities.",
};

export const TRUSTED_RESPONSIBILITIES: TrustedResponsibility[] = [
  {
    key: "community_reviewer",
    label: "Community Reviewer",
    description: "Help review reported posts and verification requests when selected.",
    requires: VERIFICATION_LABELS.trusted,
  },
  {
    key: "group_moderator",
    label: "Group Moderator",
    description: "Help a group manage members, rules, and reported content.",
    requires: VERIFICATION_LABELS.trusted,
  },
  {
    key: "network_helper",
    label: "Network Helper",
    description: "Support network services after the account and service role are approved.",
    requires: VERIFICATION_LABELS.trusted,
  },
  {
    key: "storage_helper",
    label: "Storage Helper",
    description: "Help keep community media and records available after approval.",
    requires: VERIFICATION_LABELS.trusted,
  },
  {
    key: "network_operator",
    label: "Network Operator",
    description: "Run approved infrastructure in advanced/operator mode.",
    requires: VERIFICATION_LABELS.trusted,
  },
];

export function normalizeVerificationTier(value: unknown): number {
  const n = Number(value ?? 0);
  if (!Number.isFinite(n)) return 0;
  return Math.max(0, Math.min(2, Math.trunc(n)));
}

export function verificationLevelFromTier(value: unknown): VerificationLevel {
  const tier = normalizeVerificationTier(value);
  if (tier >= 2) return "trusted";
  if (tier === 1) return "verified";
  return "basic";
}

export function verificationLabel(value: unknown): string {
  return VERIFICATION_LABELS[verificationLevelFromTier(value)];
}

export function verificationSummary(value: unknown): string {
  return VERIFICATION_SUMMARIES[verificationLevelFromTier(value)];
}

export function requiredVerificationLabel(minimumTier: number): string {
  return verificationLabel(minimumTier);
}

export function blockedByVerificationMessage(minimumTier: number): string {
  const level = verificationLevelFromTier(minimumTier);
  if (level === "trusted") return "Complete live verification to use this action.";
  if (level === "verified") return "Complete account verification to use this action.";
  return "Create or restore your account before continuing.";
}

export function accountRestrictionMessage(state: any): string | null {
  if (state?.banned) return "This account is restricted. Reinstatement is required before normal actions can continue.";
  if (state?.locked) return "This account is locked. Recover or unlock the account before normal actions can continue.";
  return null;
}

export function friendlyActionError(message: string): string {
  const raw = String(message || "").trim();
  const lower = raw.toLowerCase();
  if (!raw) return "This action could not be completed.";
  if (lower.includes("nonce") || lower.includes("stale") || lower.includes("already used")) {
    return "Something changed. Refresh and try again.";
  }
  if (lower.includes("tier") || lower.includes("poh") || lower.includes("not eligible") || lower.includes("gated")) {
    return "You need to verify your account before using this action.";
  }
  if (lower.includes("juror") || lower.includes("reviewer") || lower.includes("not assigned")) {
    return "You were not selected to review this item.";
  }
  if (lower.includes("proposal") && (lower.includes("closed") || lower.includes("not open"))) {
    return "This decision is no longer open.";
  }
  if (lower.includes("duplicate vote") || lower.includes("already voted")) {
    return "Your vote has already been recorded.";
  }
  if (lower.includes("session") || lower.includes("unauthorized") || lower.includes("login")) {
    return "Your session needs attention. Sign in again or refresh your device session.";
  }
  return raw;
}

export function decisionStageLabel(value: unknown): string {
  const stage = String(value || "").trim().toLowerCase();
  if (["draft"].includes(stage)) return "Draft";
  if (["poll", "open"].includes(stage)) return "Open for early input";
  if (["voting", "vote"].includes(stage)) return "Open for voting";
  if (["revision"].includes(stage)) return "Being revised";
  if (["validation"].includes(stage)) return "Being checked";
  if (["closed"].includes(stage)) return "Voting closed";
  if (["tallied"].includes(stage)) return "Results counted";
  if (["executed"].includes(stage)) return "Approved changes applied";
  if (["finalized"].includes(stage)) return "Final result";
  if (["withdrawn", "canceled", "cancelled"].includes(stage)) return "Withdrawn";
  if (["failed", "expired"].includes(stage)) return "Ended";
  return stage ? stage.replace(/_/g, " ").replace(/\b\w/g, (char) => char.toUpperCase()) : "Status unknown";
}

export function decisionStageHelp(value: unknown): string {
  const stage = String(value || "").trim().toLowerCase();
  if (["poll", "open"].includes(stage)) return "People can share early input before the final vote.";
  if (["voting", "vote"].includes(stage)) return "Eligible people can vote on this decision now.";
  if (stage === "draft") return "This decision is still being prepared.";
  if (stage === "revision") return "This decision is being updated before voting continues.";
  if (stage === "validation") return "This decision is being checked before voting opens.";
  if (stage === "closed") return "Voting has closed and the result is waiting to be counted or published.";
  if (stage === "tallied") return "Votes have been counted.";
  if (stage === "executed") return "Approved changes have been applied.";
  if (stage === "finalized") return "This decision is complete.";
  if (stage === "withdrawn") return "The creator withdrew this decision.";
  return "Open the detail page for the latest status.";
}

export function decisionVoteChoiceLabel(value: unknown): string {
  const choice = String(value || "").trim().toLowerCase();
  if (choice === "yes") return "Yes";
  if (choice === "no") return "No";
  if (choice === "abstain") return "Abstain";
  return choice ? choice.replace(/_/g, " ").replace(/\b\w/g, (char) => char.toUpperCase()) : "None";
}

export function reviewChoiceLabel(value: unknown): string {
  const choice = String(value || "").trim().toLowerCase();
  if (choice === "yes" || choice === "remove" || choice === "report_upheld") return "Remove Post";
  if (choice === "no" || choice === "keep" || choice === "report_not_upheld") return "Keep Post";
  if (choice === "abstain" || choice === "needs_more_review") return "Need More Review";
  return choice ? choice.replace(/_/g, " ").replace(/\b\w/g, (char) => char.toUpperCase()) : "None";
}

export function reviewTallyText(counts: { yes?: number; no?: number; abstain?: number } | null | undefined): string {
  const c = counts || {};
  return `Remove ${Number(c.yes || 0)} · Keep ${Number(c.no || 0)} · Need more review ${Number(c.abstain || 0)}`;
}

export function reviewStatusLabel(value: unknown): string {
  const status = String(value || "").trim().toLowerCase();
  if (["assigned"].includes(status)) return "Assigned to you";
  if (["accepted", "review"].includes(status)) return "Accepted";
  if (["declined"].includes(status)) return "Declined";
  if (["unassigned", "none", ""].includes(status)) return "Not assigned";
  if (["resolved", "closed", "finalized", "complete", "completed"].includes(status)) return "Completed";
  return status.replace(/_/g, " ").replace(/\b\w/g, (char) => char.toUpperCase());
}

export function reportStageLabel(value: unknown): string {
  const stage = String(value || "").trim().toLowerCase();
  if (["open", "assigned", "review", "juror_review", "voting"].includes(stage)) return "Under review";
  if (["resolved", "closed", "finalized"].includes(stage)) return "Review complete";
  if (["dismissed", "kept"].includes(stage)) return "Kept visible";
  if (["removed"].includes(stage)) return "Removed";
  return stage ? stage.replace(/_/g, " ").replace(/\b\w/g, (char) => char.toUpperCase()) : "Under review";
}
