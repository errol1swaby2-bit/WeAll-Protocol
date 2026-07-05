import { getKeypair, getSession } from "../auth/session";
import { normalizeAccount } from "../auth/keys";
import { resolveOnboardingSnapshot } from "./onboarding";
import { verificationLabel } from "./userLanguage";

export type TxLifecyclePhase = "preparing" | "submitted" | "confirmed" | "failed" | "unknown";

export type NormalizedTxStatus = {
  txId?: string;
  phase: TxLifecyclePhase;
  label: string;
  detail: string;
  terminal: boolean;
};

export type NodeConnectionState = {
  phase: "online" | "degraded" | "offline";
  label: string;
  detail: string;
  chainId?: string;
  height?: number;
  finalizedHeight?: number;
  profile?: string;
  authorityLevel: string;
};

export type SessionStateSummary = {
  account: string | null;
  hasLocalSigner: boolean;
  hasBrowserSession: boolean;
  expiresAtMs?: number;
  label: string;
  detail: string;
};

export type AccountStandingSummary = {
  account: string | null;
  registered: boolean;
  tier: number;
  locked: boolean;
  banned: boolean;
  label: string;
  detail: string;
};

export function normalizeTxStatus(raw: any, txId?: string): NormalizedTxStatus {
  const status = String(raw?.status || "").trim().toLowerCase();
  const resolvedTxId = String(raw?.tx_id || txId || "").trim() || undefined;

  if (status === "confirmed") {
    return {
      txId: resolvedTxId,
      phase: "confirmed",
      label: "Confirmed",
      detail: "This transaction is confirmed by the backend status surface.",
      terminal: true,
    };
  }

  if (status === "pending") {
    return {
      txId: resolvedTxId,
      phase: "submitted",
      label: "Pending",
      detail: "The transaction was submitted but final confirmation is still pending.",
      terminal: false,
    };
  }

  if (status === "unknown") {
    return {
      txId: resolvedTxId,
      phase: "unknown",
      label: "Unknown",
      detail: "The backend does not currently report a final lifecycle result for this transaction.",
      terminal: true,
    };
  }

  return {
    txId: resolvedTxId,
    phase: "submitted",
    label: "Submitted",
    detail: "The request completed, but no authoritative finality state was returned yet.",
    terminal: false,
  };
}

function deriveAuthorityLevel(raw: any, profile?: string): string {
  const localValidator = raw?.local_is_active_validator === true || raw?.validator_active === true;
  const profileText = String(profile || raw?.mode || "").toLowerCase();
  if (localValidator) return "active validator by chain state";
  if (profileText.includes("validator-candidate")) return "validator candidate / fail-closed";
  if (profileText.includes("validator")) return "validator-capable node; authority requires chain state";
  if (profileText.includes("operator")) return "node operator diagnostics";
  if (profileText.includes("observer")) return "observer / read-sync-forward";
  return "unknown; treat as read-only until proven by protocol state";
}

export function summarizeNodeConnection(raw: any, fallbackBase: string): NodeConnectionState {
  const ok = raw?.ok === true;
  if (!raw || typeof raw !== "object") {
    return {
      phase: "offline",
      label: "Offline",
      detail: fallbackBase,
      authorityLevel: "unknown; treat as read-only until the node responds",
    };
  }

  const chainId = raw?.chain_id ? String(raw.chain_id) : undefined;
  const height = Number.isFinite(Number(raw?.height)) ? Number(raw.height) : undefined;
  const finalizedHeight = Number.isFinite(Number(raw?.finalized_height)) ? Number(raw.finalized_height) : undefined;
  const mode = raw?.mode ? String(raw.mode) : undefined;
  const lifecycle = raw?.node_lifecycle ? String(raw.node_lifecycle) : undefined;
  const profile = lifecycle || mode;
  const authorityLevel = deriveAuthorityLevel(raw, profile);
  const detailParts = [
    chainId,
    typeof height === "number" ? `h${height}` : null,
    typeof finalizedHeight === "number" ? `finalized h${finalizedHeight}` : null,
    profile,
  ].filter(Boolean);

  if (ok) {
    return {
      phase: "online",
      label: "Backend reachable",
      detail: detailParts.join(" · "),
      chainId,
      height,
      finalizedHeight,
      profile,
      authorityLevel,
    };
  }

  return {
    phase: "degraded",
    label: "Degraded",
    detail: detailParts.join(" · ") || fallbackBase,
    chainId,
    height,
    finalizedHeight,
    profile,
    authorityLevel,
  };
}

export function summarizeSessionState(args: { accountView?: any; registrationView?: any }): SessionStateSummary {
  const session = getSession();
  const account = session ? normalizeAccount(session.account) : "";
  const keypair = account ? getKeypair(account) : null;
  const hasLocalSigner = !!keypair?.secretKeyB64;
  const hasBrowserSession = !!session?.sessionKey;

  if (!account) {
    return {
      account: null,
      hasLocalSigner: false,
      hasBrowserSession: false,
      label: "No active session",
      detail: "No account is active on this device.",
    };
  }

  const parts: string[] = [];
  parts.push(hasLocalSigner ? "local signer ready" : "no local signer");
  parts.push(hasBrowserSession ? "browser session active" : "no browser session key");

  return {
    account,
    hasLocalSigner,
    hasBrowserSession,
    expiresAtMs: session?.expiresAtMs,
    label: "Local session",
    detail: parts.join(" · "),
  };
}

export function summarizeAccountStanding(args: { accountView?: any; registrationView?: any }): AccountStandingSummary {
  const session = getSession();
  const account = session ? normalizeAccount(session.account) : "";
  const keypair = account ? getKeypair(account) : null;
  const snapshot = resolveOnboardingSnapshot({
    account,
    session,
    keypair,
    accountView: args.accountView,
    registrationView: args.registrationView,
  });

  if (!account) {
    return {
      account: null,
      registered: false,
      tier: 0,
      locked: false,
      banned: false,
      label: "No on-chain account selected",
      detail: "Sign in or restore an account to inspect standing.",
    };
  }

  const flags: string[] = [];
  flags.push(snapshot.registered ? "registered" : "registration needed");
  flags.push(verificationLabel(snapshot.tier));
  if (snapshot.locked) flags.push("locked");
  if (snapshot.banned) flags.push("banned");

  return {
    account,
    registered: snapshot.registered,
    tier: snapshot.tier,
    locked: snapshot.locked,
    banned: snapshot.banned,
    label: verificationLabel(snapshot.tier),
    detail: flags.join(" · "),
  };
}
