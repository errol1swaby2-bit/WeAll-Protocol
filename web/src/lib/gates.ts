// web/src/lib/gates.ts

import {
  accountRestrictionMessage,
  blockedByVerificationMessage,
  normalizeVerificationTier,
  verificationLabel,
} from "./userLanguage";

export type GateResult = {
  ok: boolean;
  reason?: string;
};

export function v2PohTier(value: unknown): number {
  return normalizeVerificationTier(value);
}

export function pohTierLabel(value: unknown): string {
  return verificationLabel(value);
}

export type GateArgs = {
  loggedIn: boolean;
  canSign: boolean;
  accountState: any | null;
  requireTier: number;
  minRep?: number;
};

/**
 * Centralized UX gating logic.
 *
 * IMPORTANT: This is only a UI hint layer. The backend and chain remain the
 * authority for all gates, assignments, account status, and action outcomes.
 */
export function checkGates(args: GateArgs): GateResult {
  if (!args.loggedIn) return { ok: false, reason: "Sign in or create an account before continuing." };
  if (!args.canSign) return { ok: false, reason: "This device is missing the local signer for this account. Restore the signer before continuing." };

  const st = args.accountState || {};
  const restriction = accountRestrictionMessage(st);
  if (restriction) return { ok: false, reason: restriction };

  const tier = v2PohTier(st?.poh_tier ?? 0);
  if (tier < args.requireTier) {
    return { ok: false, reason: blockedByVerificationMessage(args.requireTier) };
  }

  if (args.minRep != null) {
    const rep = Number(st?.reputation ?? 0);
    if (rep < args.minRep) return { ok: false, reason: "This account needs more positive community history before using this action." };
  }

  return { ok: true };
}

export function summarizeAccountState(st: any | null): string {
  if (!st) return "Account status unknown";
  const rep = Number(st?.reputation ?? 0);
  const restriction = accountRestrictionMessage(st);
  return `${pohTierLabel(st?.poh_tier ?? 0)} · community history ${rep}${restriction ? " · restricted" : ""}`;
}
