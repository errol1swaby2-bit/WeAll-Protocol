// projects/web/src/auth/session.ts
// web/src/auth/session.ts
import { canonicalTxMessage, loadKeypair, normalizeAccount, signDetachedB64 } from "./keys";
import { getApiBaseUrl, weall } from "../api/weall";

/**
 * This session is a client-side convenience layer. It does not replace on-chain auth.
 * We also support issuing a session key on-chain via ACCOUNT_SESSION_KEY_ISSUE so
 * the backend can enforce private endpoints by ledger state.
 */

type SessionState = {
  account: string;
  expiresAtMs: number;
  sessionKey?: string;
};

const SESSION_KEY = "weall_session::active";
const DEFAULT_TTL_MS = 30 * 60 * 1000; // 30 minutes

function randomSessionKey(): string {
  // URL-safe base64-ish token
  const a = new Uint8Array(24);
  crypto.getRandomValues(a);
  let s = "";
  for (let i = 0; i < a.length; i++) s += String.fromCharCode(a[i]);
  // btoa expects latin1
  const b64 = btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  return `sk_${b64}`;
}

export function getAuthHeaders(): Record<string, string> {
  const s = getSession();
  if (!s?.account || !s?.sessionKey) return {};
  return {
    "X-WeAll-Account": normalizeAccount(s.account),
    "X-WeAll-Session-Key": String(s.sessionKey),
  };
}

export function startSession(account: string, ttlMs: number = DEFAULT_TTL_MS, sessionKey?: string): void {
  const now = Date.now();
  const st: SessionState = {
    account: normalizeAccount(account),
    expiresAtMs: now + ttlMs,
    sessionKey: (sessionKey || "").trim() || randomSessionKey(),
  };
  localStorage.setItem(SESSION_KEY, JSON.stringify(st));
}

export function endSession(): void {
  localStorage.removeItem(SESSION_KEY);
}

export function getSession(): SessionState | null {
  try {
    const raw = localStorage.getItem(SESSION_KEY);
    if (!raw) return null;
    const obj = JSON.parse(raw);
    if (!obj || typeof obj !== "object") return null;
    const account = normalizeAccount(String(obj.account || ""));
    const expiresAtMs = Number(obj.expiresAtMs || 0);
    if (!account || !expiresAtMs) return null;
    if (Date.now() > expiresAtMs) return null;
    const sessionKey = String((obj as any).sessionKey || "").trim();
    return { account, expiresAtMs, sessionKey: sessionKey || undefined };
  } catch {
    return null;
  }
}

/**
 * Nonce reservation to reduce accidental double-nonce submissions in the UI.
 * This is best-effort; the chain is still authoritative.
 */
const NONCE_RES_KEY_PREFIX = "weall_nonce_reservation::";

export function reserveNextNonce(account: string, onChainNonce: number): number {
  const acct = normalizeAccount(account);
  const key = `${NONCE_RES_KEY_PREFIX}${acct}`;
  const raw = localStorage.getItem(key);
  let last = 0;
  if (raw) {
    const n = Number(raw);
    if (Number.isFinite(n)) last = n;
  }
  const next = Math.max(onChainNonce + 1, last + 1);
  localStorage.setItem(key, String(next));
  return next;
}

export function clearNonceReservation(account: string): void {
  const acct = normalizeAccount(account);
  localStorage.removeItem(`${NONCE_RES_KEY_PREFIX}${acct}`);
}

/**
 * Keypair access wrappers
 */
export function getKeypair(account: string) {
  return loadKeypair(normalizeAccount(account));
}

export function clearKeypair(account: string) {
  // implemented in keys.ts via deleteKeypair; kept for legacy imports
  // Consumers should call deleteKeypair directly where possible.
  // eslint-disable-next-line no-console
  console.warn("clearKeypair() is deprecated; use deleteKeypair() from auth/keys instead.");
}

/**
 * Submit a signed tx using the local keypair. Handles nonce fetching + reservation.
 */
export async function submitSignedTx(args: {
  account: string;
  tx_type: string;
  payload: any;
  parent: string | null;
  base?: string;
}): Promise<any> {
  const base = args.base || getApiBaseUrl();
  const acct = normalizeAccount(args.account);
  const kp = loadKeypair(acct);
  if (!kp?.secretKeyB64) throw new Error("no_local_secret_key");

  const nonceR: any = await weall.accountNonce(acct, base);
  const onChainNonce = Number(nonceR?.nonce ?? 0);
  const nonce = reserveNextNonce(acct, onChainNonce);

  const env = {
    chain_id: "weall",
    tx_type: args.tx_type,
    signer: acct,
    nonce,
    payload: args.payload ?? {},
    parent: args.parent ?? null,
  };

  const msg = canonicalTxMessage(env);
  const sig = signDetachedB64(kp.secretKeyB64, msg);

  return await weall.submitTx({ ...env, sig }, base);
}

/**
 * Issue an on-chain session key for this device, then start a local session.
 *
 * This is the production-gating mechanism used by require_account_session() on the backend.
 *
 * Returns the session key that was issued.
 */
export async function loginOnThisDevice(args: {
  account: string;
  ttlMs?: number;
  ttlS?: number;
  base?: string;
  sessionKey?: string;
}): Promise<{ account: string; sessionKey: string; receipt: any }> {
  const base = args.base || getApiBaseUrl();
  const account = normalizeAccount(args.account);

  const kp = loadKeypair(account);
  if (!kp?.secretKeyB64) {
    throw new Error("no_local_secret_key");
  }

  const ttlMs = typeof args.ttlMs === "number" && args.ttlMs > 0 ? Math.floor(args.ttlMs) : DEFAULT_TTL_MS;
  const ttlS = typeof args.ttlS === "number" && args.ttlS > 0 ? Math.floor(args.ttlS) : Math.floor(ttlMs / 1000);

  const sessionKey = (args.sessionKey || "").trim() || randomSessionKey();

  // Submit on-chain session issuance.
  const receipt = await submitSignedTx({
    account,
    tx_type: "ACCOUNT_SESSION_KEY_ISSUE",
    payload: { session_key: sessionKey, ttl_s: ttlS },
    parent: null,
    base,
  });

  // Only start local session after successful on-chain submit.
  startSession(account, ttlMs, sessionKey);

  return { account, sessionKey, receipt };
}

/**
 * Best-effort on-chain session revoke (optional). This does not delete local keys.
 * If you call this and it succeeds, you probably also want to endSession().
 */
export async function revokeSessionKeyOnChain(args: {
  account: string;
  sessionKey: string;
  base?: string;
}): Promise<any> {
  const base = args.base || getApiBaseUrl();
  const account = normalizeAccount(args.account);
  const sk = String(args.sessionKey || "").trim();
  if (!sk) throw new Error("missing_session_key");

  return await submitSignedTx({
    account,
    tx_type: "ACCOUNT_SESSION_KEY_REVOKE",
    payload: { session_key: sk },
    parent: null,
    base,
  });
}
