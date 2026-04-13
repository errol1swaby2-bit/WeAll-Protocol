import { setAccount, setApiBase } from "../api/weall";
import { clearNonceReservation, clearSession, ensureBackendSession, getKeypair, getSession, issueSessionFromSecretKey, syncNonceReservation } from "../auth/session";
import type { AppConfig } from "./config";

export type DevBootstrapManifest = {
  profile?: string;
  generated_at?: string;
  account?: string;
  pubkeyB64?: string;
  secretKeyB64?: string;
  apiBase?: string;
  sessionTtlSeconds?: number;
  note?: string;
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

function manifestSessionTtlSeconds(manifest: DevBootstrapManifest): number {
  return Math.max(300, Number(manifest.sessionTtlSeconds || 24 * 60 * 60));
}

async function applyManifest(config: AppConfig, manifest: DevBootstrapManifest): Promise<boolean> {
  const account = String(manifest.account || "").trim();
  const secretKeyB64 = String(manifest.secretKeyB64 || "").trim();
  if (!account || !secretKeyB64) return false;

  const marker = buildMarker(manifest);
  const normalizedBase = String(manifest.apiBase || config.defaultApiBase || "").trim() || "/";
  const ttlSeconds = manifestSessionTtlSeconds(manifest);

  setApiBase(normalizedBase);
  setAccount(account);
  clearNonceReservation(account);
  issueSessionFromSecretKey({
    account,
    secretKeyB64,
    ttlSeconds,
  });
  clearSession();

  try {
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
  const secretKeyB64 = String(manifest.secretKeyB64 || "").trim();
  if (!account || !secretKeyB64) return false;

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
  const secretKeyB64 = String(manifest.secretKeyB64 || "").trim();
  const pubkeyB64 = String(manifest.pubkeyB64 || "").trim();
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
