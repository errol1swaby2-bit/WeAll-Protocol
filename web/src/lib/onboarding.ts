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

export function resolveOnboardingSnapshot(args: {
  account?: string | null;
  session?: SessionV1 | null;
  keypair?: KeypairB64 | null;
  accountView?: any | null;
  registrationView?: any | null;
}): OnboardingSnapshot {
  const account = String(args.account || args.session?.account || "").trim();
  const state = args.accountView?.state ?? {};

  const tier = Math.max(0, Math.floor(num(state?.poh_tier, 0)));
  const reputation = num(state?.reputation, 0);
  const banned = Boolean(state?.banned);
  const locked = Boolean(state?.locked);
  const hasSession = Boolean(args.session && account);
  const hasLocalSigner = Boolean(args.keypair?.secretKeyB64 || args.keypair?.pubkeyB64);
  const registered = args.registrationView?.registered === true;
  const canPost =
    hasSession &&
    hasLocalSigner &&
    registered &&
    tier >= POSTING_MIN_TIER &&
    !banned &&
    !locked;

  let stage: OnboardingStage;
  let next: NextAction;

  if (!hasSession) {
    stage = "no_session";
    next = {
      route: "/settings",
      label: "Import or restore session",
      note: "This browser still needs a device session plus the matching signer keypair.",
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
      note: `This account is currently ${
        banned ? "banned" : "locked"
      }. Some actions will stay unavailable until protocol rules restore it.`,
    };
  } else if (!registered) {
    stage = "not_registered";
    next = {
      route: "/account/" + encodeURIComponent(account),
      label: "Complete account registration",
      note: "This account still needs the network registration path completed before creator actions can unlock.",
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
        : "Import or restore the account session in Settings.",
    },
    {
      label: "Local signer",
      ok: snapshot.hasLocalSigner,
      hint: snapshot.hasLocalSigner
        ? "The signer keypair is available locally."
        : "Restore the matching signer keypair on this device.",
    },
    {
      label: "Registration",
      ok: snapshot.registered,
      hint: snapshot.registered
        ? "Account registration is visible to the network."
        : "Finish registration before creator actions.",
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
