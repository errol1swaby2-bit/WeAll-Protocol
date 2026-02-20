// web/src/lib/gates.ts

export type GateResult = {
  ok: boolean;
  reason?: string;
};

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

  const tier = Number(st?.poh_tier ?? 0);
  if (tier < args.requireTier) {
    return { ok: false, reason: `Requires PoH tier ${args.requireTier}+ (you are tier ${tier}).` };
  }

  if (args.minRep != null) {
    const rep = Number(st?.reputation ?? 0);
    if (rep < args.minRep) return { ok: false, reason: `Requires reputation ≥ ${args.minRep} (you are ${rep}).` };
  }

  return { ok: true };
}

export function summarizeAccountState(st: any | null): string {
  if (!st) return "(state unknown)";
  const tier = Number(st?.poh_tier ?? 0);
  const rep = Number(st?.reputation ?? 0);
  const flags: string[] = [];
  if (st?.banned) flags.push("banned");
  if (st?.locked) flags.push("locked");
  const flagStr = flags.length ? ` (${flags.join(", ")})` : "";
  return `tier ${tier}, rep ${rep}${flagStr}`;
}
