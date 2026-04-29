import type { KeypairB64 } from "../auth/keys";
import type { SessionV1 } from "../auth/session";

export const POSTING_MIN_TIER = 3;
export const POSTING_MIN_REPUTATION = 0;

export type OnboardingStage =
  | "no_session"
  | "no_signer"
  | "not_registered"
  | "tier0"
  | "tier1"
  | "tier2"
  | "tier3"
  | "restricted";

export type NextAction = {
  route: string;
  label: string;
  note: string;
};

export type OnboardingSnapshot = {
  account: string;
  hasSession: boolean;
  hasLocalSigner: boolean;
  accountCreated: boolean;
  registered: boolean;
  tier: number;
  reputation: number;
  banned: boolean;
  locked: boolean;
  canPost: boolean;
  stage: OnboardingStage;
  next: NextAction;
};

function num(value: unknown, fallback = 0): number {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function hasRecordShape(state: Record<string, unknown>): boolean {
  const nonce = num(state.nonce, 0);
  if (nonce > 0) return true;
  const sessionKeys = state.session_keys;
  if (sessionKeys && typeof sessionKeys === "object" && Object.keys(sessionKeys as Record<string, unknown>).length > 0) {
    return true;
  }
  const activeKeys = state.active_keys;
  if (activeKeys && typeof activeKeys === "object" && Object.keys(activeKeys as Record<string, unknown>).length > 0) {
    return true;
  }
  if (typeof state.pubkey === "string" && state.pubkey.trim()) return true;
  if (typeof state.handle === "string" && state.handle.trim()) return true;
  return false;
}

export function hasOnChainAccountRecord(args: { accountView?: any | null; registrationView?: any | null }): boolean {
  const state = args.accountView?.state;
  if (state && typeof state === "object" && hasRecordShape(state as Record<string, unknown>)) {
    return true;
  }
  return args.registrationView?.registered === true;
}

export function resolveOnboardingSnapshot(args: {
  account?: string | null;
  session?: SessionV1 | null;
  keypair?: KeypairB64 | null;
  accountView?: any | null;
  registrationView?: any | null;
}): OnboardingSnapshot {
  const account = String(args.account || args.session?.account || "").trim();
  const state = (args.accountView?.state ?? {}) as Record<string, unknown>;

  const tier = Math.max(0, Math.floor(num(state.poh_tier, 0)));
  const reputation = num(state.reputation, 0);
  const banned = Boolean(state.banned);
  const locked = Boolean(state.locked);
  const hasSession = Boolean(args.session && account);
  const hasLocalSigner = Boolean(args.keypair?.secretKeyB64 || args.keypair?.pubkeyB64);
  const accountCreated = hasOnChainAccountRecord({
    accountView: args.accountView,
    registrationView: args.registrationView,
  });
  const registered = accountCreated;
  const canPost =
    hasSession &&
    hasLocalSigner &&
    accountCreated &&
    tier >= POSTING_MIN_TIER &&
    !banned &&
    !locked;

  let stage: OnboardingStage;
  let next: NextAction;

  if (!hasSession) {
    stage = "no_session";
    next = {
      route: "/login",
      label: "Create or restore session",
      note: "This browser still needs a device session before signed actions can work.",
    };
  } else if (!hasLocalSigner) {
    stage = "no_signer";
    next = {
      route: "/settings",
      label: "Restore local signer",
      note: "A session exists, but this device cannot sign protocol actions until the keypair is restored.",
    };
  } else if (banned || locked) {
    stage = "restricted";
    next = {
      route: "/account/" + encodeURIComponent(account),
      label: "Review account status",
      note: `This account is currently ${banned ? "banned" : "locked"}. Some actions will stay unavailable until protocol rules restore it.`,
    };
  } else if (!accountCreated) {
    stage = "not_registered";
    next = {
      route: "/login",
      label: "Finish account setup",
      note: "The local signer exists, but the on-chain account record is not visible yet.",
    };
  } else if (tier <= 0) {
    stage = "tier0";
    next = {
      route: "/poh",
      label: "Begin Tier 1 email verification",
      note: "Tier 1 is the first live PoH checkpoint and opens verified entry into the network.",
    };
  } else if (tier === 1) {
    stage = "tier1";
    next = {
      route: "/poh",
      label: "Continue to Tier 2",
      note: "Tier 2 moves into the async video review path and keeps onboarding advancing toward creator readiness.",
    };
  } else if (tier === 2) {
    stage = "tier2";
    next = {
      route: "/poh",
      label: "Continue to Tier 3",
      note: "The current frontend and backend creator flow still expects Tier 3 before posting unlocks.",
    };
  } else {
    stage = "tier3";
    next = {
      route: "/post",
      label: "Create your first post",
      note: "This device and account satisfy the current posting gate and can stay on the signed transaction path.",
    };
  }

  return {
    account,
    hasSession,
    hasLocalSigner,
    accountCreated,
    registered,
    tier,
    reputation,
    banned,
    locked,
    canPost,
    stage,
    next,
  };
}

export function summarizeNextRequirements(
  snapshot: OnboardingSnapshot,
): Array<{ label: string; ok: boolean; hint: string }> {
  return [
    {
      label: "Device session",
      ok: snapshot.hasSession,
      hint: snapshot.hasSession
        ? "A session is active on this device."
        : "Create or restore a local session first.",
    },
    {
      label: "Local signer",
      ok: snapshot.hasLocalSigner,
      hint: snapshot.hasLocalSigner
        ? "The signer keypair is available locally."
        : "Restore the matching signer keypair on this device.",
    },
    {
      label: "On-chain account",
      ok: snapshot.accountCreated,
      hint: snapshot.accountCreated
        ? "An on-chain account record is visible."
        : "Finish account creation before creator actions.",
    },
    {
      label: "PoH tier",
      ok: snapshot.tier >= POSTING_MIN_TIER,
      hint:
        snapshot.tier >= POSTING_MIN_TIER
          ? `Current tier is ${snapshot.tier}.`
          : `Current tier is ${snapshot.tier}. The active creator gate still expects Tier ${POSTING_MIN_TIER}.`,
    },
    {
      label: "Account standing",
      ok: !snapshot.banned && !snapshot.locked,
      hint:
        !snapshot.banned && !snapshot.locked
          ? "No active ban or lock is visible."
          : `Account is ${snapshot.banned ? "banned" : "locked"}.`,
    },
  ];
}
