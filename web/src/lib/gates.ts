// web/src/lib/gates.ts

import {
  combineCapabilities,
  sessionCapability,
  verificationCapability,
  type Requirement,
} from "./capabilityMessages";
import {
  accountRestrictionMessage,
  blockedByVerificationMessage,
  normalizeVerificationTier,
  verificationLabel,
} from "./userLanguage";

export type GateResult = {
  ok: boolean;
  reason?: string;
  reasonCode?: string;
  requirements?: Requirement[];
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
  key?: string;
};

/**
 * Centralized UX gating logic.
 *
 * IMPORTANT: This is only a UI hint layer. The backend and chain remain the
 * authority for all gates, assignments, account status, and action outcomes.
 */
export function checkGates(args: GateArgs): GateResult {
  const key = args.key || "action";
  const st = args.accountState || {};
  const tier = v2PohTier(st?.poh_tier ?? 0);

  const checks = [sessionCapability(key, args.loggedIn, args.canSign)];

  const restriction = accountRestrictionMessage(st);
  if (restriction) {
    return {
      ok: false,
      reason: restriction,
      reasonCode: "account_restricted",
      requirements: [
        { label: "Account in good standing", satisfied: false, helpText: restriction },
        ...checks.flatMap((check) => check.requirements || []),
      ],
    };
  }

  checks.push(verificationCapability(key, tier, args.requireTier));

  if (args.minRep != null) {
    const rep = Number(st?.reputation ?? 0);
    checks.push(
      rep >= args.minRep
        ? {
            key,
            state: "allowed",
            allowed: true,
            message: "Your community history meets this requirement.",
            requirements: [{ label: "Community history", satisfied: true, helpText: "Requirement met." }],
          }
        : {
            key,
            state: "blocked_by_state",
            allowed: false,
            reasonCode: "requires_community_history",
            message: "This account needs more positive community history before using this action.",
            requirements: [
              {
                label: "Community history",
                satisfied: false,
                helpText: "Use the app constructively over time before this action unlocks.",
              },
            ],
          },
    );
  }

  const result = combineCapabilities(key, checks);
  if (result.allowed) return { ok: true, reasonCode: result.reasonCode, requirements: result.requirements };
  return {
    ok: false,
    reason: result.message || blockedByVerificationMessage(args.requireTier),
    reasonCode: result.reasonCode,
    requirements: result.requirements,
  };
}

export function summarizeAccountState(st: any | null): string {
  if (!st) return "Account status unknown";
  const rep = Number(st?.reputation ?? 0);
  const restriction = accountRestrictionMessage(st);
  return `${pohTierLabel(st?.poh_tier ?? 0)} · community history ${rep}${restriction ? " · restricted" : ""}`;
}
