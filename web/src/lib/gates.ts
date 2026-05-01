// web/src/lib/gates.ts

export type GateResult = {
  ok: boolean;
  reason?: string;
};

export function v2PohTier(value: unknown): number {
  const n = Number(value ?? 0);
  if (!Number.isFinite(n)) return 0;
  return Math.max(0, Math.min(2, Math.trunc(n)));
}

export function pohTierLabel(value: unknown): string {
  const tier = v2PohTier(value);
  if (tier >= 2) return "Live Verified Human";
  if (tier === 1) return "Async Verified Human";
  return "Unverified Account";
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
 * IMPORTANT: This is only a *UI hint* layer.
 * The protocol must still enforce the rules server-side.
 */
export function checkGates(args: GateArgs): GateResult {
  if (!args.loggedIn) return { ok: false, reason: "Not logged in (go to PoH and start a session)." };
  if (!args.canSign) return { ok: false, reason: "No local secret key for signing (generate keys on PoH page)." };

  const st = args.accountState || {};
  if (st?.banned) return { ok: false, reason: "Account is banned." };
  if (st?.locked) return { ok: false, reason: "Account is locked." };

  const tier = v2PohTier(st?.poh_tier ?? 0);
  if (tier < args.requireTier) {
    const requiredLabel = pohTierLabel(args.requireTier);
    const actualLabel = pohTierLabel(tier);
    return { ok: false, reason: `Requires ${requiredLabel} (you are ${actualLabel}).` };
  }

  if (args.minRep != null) {
    const rep = Number(st?.reputation ?? 0);
    if (rep < args.minRep) return { ok: false, reason: `Requires reputation ≥ ${args.minRep} (you are ${rep}).` };
  }

  return { ok: true };
}

export function summarizeAccountState(st: any | null): string {
  if (!st) return "(state unknown)";
  const tier = v2PohTier(st?.poh_tier ?? 0);
  const rep = Number(st?.reputation ?? 0);
  const flags: string[] = [];
  if (st?.banned) flags.push("banned");
  if (st?.locked) flags.push("locked");
  const flagStr = flags.length ? ` (${flags.join(", ")})` : "";
  return `${pohTierLabel(tier)}, rep ${rep}${flagStr}`;
}
