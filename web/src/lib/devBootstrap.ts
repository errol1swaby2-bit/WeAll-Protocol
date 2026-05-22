import { setAccount, setApiBase, weall } from "../api/weall";
import { clearNonceReservation, clearSession, ensureBackendSession, getKeypair, getSession, issueSessionFromSecretKey, submitSignedTx, syncNonceReservation } from "../auth/session";
import type { AppConfig } from "./config";

export type DevBootstrapStep = {
  label?: string;
  href?: string;
};

export type DevBootstrapManifest = {
  profile?: string;
  generated_at?: string;
  account?: string;
  pubkeyB64?: string;
  publicKeyB64?: string;
  secretKeyB64?: string;
  secret_key_b64?: string;
  createAccount?: boolean;
  create_account?: boolean;
  apiBase?: string;
  api_base?: string;
  sessionTtlSeconds?: number;
  note?: string;
  seededGroup?: { group_id?: string; member_visible?: boolean; visibility?: string };
  seededProposal?: { proposal_id?: string; stage?: string };
  seededDispute?: { dispute_id?: string; stage?: string; juror?: string; juror_status?: string; target_id?: string };
  waitForAccountMs?: number;
  wait_for_account_ms?: number;
  recommendedPath?: DevBootstrapStep[];
  fallbackInstructions?: string[];
  resetInstructions?: string[];
};

const LS_BOOTSTRAP_MARKER = "weall_dev_bootstrap_marker_v1";

function readMarker(): string {
  try {
    return String(localStorage.getItem(LS_BOOTSTRAP_MARKER) || "").trim();
  } catch {
    return "";
  }
}

function writeMarker(value: string): void {
  try {
    localStorage.setItem(LS_BOOTSTRAP_MARKER, value);
  } catch {
    // ignore storage errors
  }
}

function buildMarker(manifest: DevBootstrapManifest): string {
  const account = String(manifest.account || "").trim().toLowerCase();
  const pubkey = String(manifest.pubkeyB64 || "").trim();
  return `${account}::${pubkey}`;
}

async function fetchManifest(url: string): Promise<DevBootstrapManifest | null> {
  try {
    const res = await fetch(url, { cache: "no-store" });
    if (!res.ok) return null;
    const body = (await res.json()) as DevBootstrapManifest;
    if (!body || typeof body !== "object") return null;
    return body;
  } catch {
    return null;
  }
}

type DevBootstrapSecretResponse = {
  account?: string;
  pubkeyB64?: string;
  secretKeyB64?: string;
  secret_key_b64?: string;
  sessionTtlSeconds?: number;
};

function manifestSessionTtlSeconds(manifest: DevBootstrapManifest | DevBootstrapSecretResponse): number {
  return Math.max(300, Number(manifest.sessionTtlSeconds || 24 * 60 * 60));
}

function usableApiBase(...candidates: Array<string | undefined>): string {
  for (const candidate of candidates) {
    const normalized = String(candidate || "").trim();
    if (normalized && normalized !== "/") return normalized;
  }
  return "/";
}

function apiJoin(base: string, path: string): string {
  const normalizedBase = usableApiBase(base);
  if (normalizedBase === "/") return path;
  return `${normalizedBase.replace(/\/+$/, "")}${path}`;
}

function manifestApiBase(config: AppConfig, manifest: DevBootstrapManifest): string {
  return usableApiBase(manifest.apiBase, manifest.api_base, config.defaultApiBase);
}

async function fetchSecret(config: AppConfig, manifest: DevBootstrapManifest): Promise<DevBootstrapSecretResponse | null> {
  const account = String(manifest.account || "").trim();
  if (!account) return null;

  const inlineSecret = String(manifest.secretKeyB64 || manifest.secret_key_b64 || "").trim();
  if (inlineSecret) {
    return {
      account,
      secretKeyB64: inlineSecret,
      secret_key_b64: inlineSecret,
      pubkeyB64: String(manifest.pubkeyB64 || manifest.publicKeyB64 || "").trim(),
      sessionTtlSeconds: manifest.sessionTtlSeconds,
    };
  }

  const base = manifestApiBase(config, manifest);
  const url = apiJoin(base, `/v1/dev/bootstrap-secret?account=${encodeURIComponent(account)}`);
  try {
    const res = await fetch(url, { cache: "no-store" });
    if (!res.ok) return null;
    const body = (await res.json()) as DevBootstrapSecretResponse;
    return body && typeof body === "object" ? body : null;
  } catch {
    return null;
  }
}

function shouldCreateAccount(manifest: DevBootstrapManifest): boolean {
  return manifest.createAccount === true || manifest.create_account === true;
}

function accountRecordLooksPresent(value: any): boolean {
  const state = value?.state && typeof value.state === "object" ? value.state : null;
  if (!state) return false;
  if (Number(state.nonce || 0) > 0) return true;
  if (typeof state.pubkey === "string" && state.pubkey.trim()) return true;
  if (Array.isArray(state.pubkeys) && state.pubkeys.length > 0) return true;
  if (Array.isArray(state.active_keys) && state.active_keys.length > 0) return true;
  return !!(state.keys && typeof state.keys === "object");
}

async function waitForAccountRecord(account: string, base: string, timeoutMs: number): Promise<boolean> {
  const deadline = Date.now() + Math.max(1_000, Math.min(120_000, Number(timeoutMs || 20_000)));
  while (Date.now() <= deadline) {
    try {
      const view = await weall.account(account, base);
      if (accountRecordLooksPresent(view)) return true;
    } catch {
      // Account may not be visible locally until observer reconciliation catches up.
    }
    await new Promise((resolve) => window.setTimeout(resolve, 500));
  }
  return false;
}

async function ensureAccountRecord(_config: AppConfig, manifest: DevBootstrapManifest, account: string, pubkeyB64: string, base: string): Promise<void> {
  if (!shouldCreateAccount(manifest)) return;

  try {
    const existing = await weall.account(account, base);
    if (accountRecordLooksPresent(existing)) return;
  } catch {
    // Continue into ACCOUNT_REGISTER.
  }

  await submitSignedTx({
    account,
    tx_type: "ACCOUNT_REGISTER",
    payload: { pubkey: pubkeyB64 },
    parent: null,
    base,
  });

  const timeoutMs = Number(manifest.waitForAccountMs || manifest.wait_for_account_ms || 30_000);
  const visible = await waitForAccountRecord(account, base, timeoutMs);
  if (!visible) {
    throw new Error("dev_bootstrap_account_not_visible_after_register");
  }
}

async function applyManifest(config: AppConfig, manifest: DevBootstrapManifest): Promise<boolean> {
  const account = String(manifest.account || "").trim();
  if (!account) return false;

  const secret = await fetchSecret(config, manifest);
  const secretKeyB64 = String(secret?.secretKeyB64 || secret?.secret_key_b64 || "").trim();
  if (!secretKeyB64) return false;

  const marker = buildMarker(manifest);
  const normalizedBase = manifestApiBase(config, manifest);
  const ttlSeconds = manifestSessionTtlSeconds(secret || manifest);

  setApiBase(normalizedBase);
  setAccount(account);
  clearNonceReservation(account);
  const issued = issueSessionFromSecretKey({
    account,
    secretKeyB64,
    ttlSeconds,
  });
  clearSession();

  try {
    await ensureAccountRecord(config, manifest, account, issued.keypair.pubkeyB64, normalizedBase);
    await ensureBackendSession({
      account,
      ttlSeconds,
      base: normalizedBase || undefined,
    });
    await syncNonceReservation(account, normalizedBase || undefined);
  } catch {
    clearSession();
  }

  writeMarker(marker);
  return true;
}

export async function maybeApplyDevBootstrap(config: AppConfig): Promise<boolean> {
  if (!config.enableDevBootstrap) return false;

  const manifest = await fetchManifest(config.devBootstrapManifestUrl);
  if (!manifest) return false;

  const account = String(manifest.account || "").trim();
  if (!account) return false;

  const marker = buildMarker(manifest);
  const session = getSession();
  const existing = account ? getKeypair(account) : null;
  if (session?.account === account && existing?.secretKeyB64 && readMarker() === marker) {
    return false;
  }

  return applyManifest(config, manifest);
}

export async function maybeRepairDevBootstrapSession(config: AppConfig): Promise<boolean> {
  if (!config.enableDevBootstrap) return false;

  const manifest = await fetchManifest(config.devBootstrapManifestUrl);
  if (!manifest) return false;

  const account = String(manifest.account || "").trim();
  const pubkeyB64 = String(manifest.pubkeyB64 || "").trim();
  const secret = await fetchSecret(config, manifest);
  const secretKeyB64 = String(secret?.secretKeyB64 || secret?.secret_key_b64 || "").trim();
  if (!account || !secretKeyB64) return false;

  const session = getSession();
  const existing = account ? getKeypair(account) : null;
  const marker = buildMarker(manifest);
  const hasSameMarker = readMarker() == marker;
  const hasExpectedAccount = String(session?.account || "").trim() == account;
  const hasExpectedSecret = String(existing?.secretKeyB64 || "").trim() == secretKeyB64;
  const hasExpectedPubkey = !pubkeyB64 || String(existing?.pubkeyB64 || "").trim() == pubkeyB64;

  if (hasSameMarker && hasExpectedAccount && hasExpectedSecret && hasExpectedPubkey) {
    return false;
  }

  return applyManifest(config, manifest);
}
