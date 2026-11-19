import type { TxEnvelope } from "./session";

// A pending bearer is private tab-scoped material, just like an active bearer.
// No candidate, signature, or recovery seed is written to localStorage.
const PREFIX = "weall_pending_canonical_login_v1::";
export type CanonicalLoginScope = { account: string; base: string; pubkey: string };
type TrackedTx = { txId: string; nonce: number };
export type CanonicalLoginAttempt = {
  version: 1;
  scope: CanonicalLoginScope;
  chainId: string;
  deviceId: string;
  sessionKey: string;
  ttlSeconds: number;
  startedAtMs: number;
  deviceTx?: TrackedTx;
  sessionTx?: TrackedTx;
  blocked?: boolean;
};

export class PendingCanonicalLoginError extends Error {
  constructor(stage: string) {
    super("Login is waiting for canonical " + stage + ". The existing attempt is retained in this tab; retry will reconcile it instead of issuing another key.");
    this.name = "PendingCanonicalLoginError";
  }
}

/**
 * Only retry the selected-node identity GET on explicit HTTP 429. The
 * current node rate limiter does not send Retry-After; bounded exponential
 * backoff allows its bucket to replenish without using cached identity.
 * Never retry a transaction submission here or accept a failed read.
 */
export async function readCanonicalLoginChainId(
  readStatus: () => Promise<{ chain_id?: unknown }>,
  pause: (ms: number) => Promise<void>,
): Promise<string> {
  const delays = [500, 1000, 2000, 4000, 4000];
  for (let retry = 0; ; retry += 1) {
    try {
      const status = await readStatus();
      return typeof status?.chain_id === "string" ? status.chain_id.trim() : "";
    } catch (error) {
      if ((error as { status?: unknown } | null)?.status !== 429) throw error;
      if (retry >= delays.length) throw new PendingCanonicalLoginError("chain identity (node rate limit)");
      await pause(delays[retry]);
    }
  }
}

/**
 * A fresh canonical login may not invent a nonce from a stale account view.
 * Only retry explicit 429 responses to this safe, pending-aware GET, before
 * signing or writing a tracked transaction. Never retry submission here.
 */
export async function readCanonicalLoginNextNonce(
  account: string,
  readNonce: () => Promise<any>,
  pause: (ms: number) => Promise<void>,
): Promise<number> {
  const delays = [500, 1000, 2000, 4000, 4000];
  for (let retry = 0; ; retry += 1) {
    try {
      const result = await readNonce();
      const cursor = result?.nonce_cursor;
      const next = result?.next_nonce;
      if (result?.ok !== true || result.account !== account ||
          !Number.isSafeInteger(cursor) || cursor < 0 ||
          !Number.isSafeInteger(next) || next !== cursor + 1) {
        throw new Error("canonical_login_nonce_unavailable");
      }
      return next;
    } catch (error) {
      if ((error as { status?: unknown } | null)?.status !== 429) throw error;
      if (retry >= delays.length) throw new PendingCanonicalLoginError("nonce reservation (node rate limit)");
      await pause(delays[retry]);
    }
  }
}

function storageKey(scope: CanonicalLoginScope): string {
  return PREFIX + JSON.stringify([scope.account, scope.base, scope.pubkey]);
}

function validTx(value: unknown): value is TrackedTx {
  if (!value || typeof value !== "object") return false;
  const tx = value as TrackedTx;
  return /^tx:[0-9a-f]{64}$/.test(tx.txId) && Number.isSafeInteger(tx.nonce) && tx.nonce > 0;
}

export function readCanonicalLogin(scope: CanonicalLoginScope, storage: Storage = sessionStorage): CanonicalLoginAttempt | null {
  const raw = storage.getItem(storageKey(scope));
  if (raw === null) return null;
  let attempt: CanonicalLoginAttempt;
  try { attempt = JSON.parse(raw); } catch { throw new Error("pending_canonical_login_invalid"); }
  if (!attempt || attempt.version !== 1 || !attempt.scope ||
      storageKey(attempt.scope) !== storageKey(scope) || !attempt.chainId ||
      typeof attempt.deviceId !== "string" || !attempt.deviceId ||
      typeof attempt.sessionKey !== "string" || !attempt.sessionKey ||
      !Number.isSafeInteger(attempt.ttlSeconds) || attempt.ttlSeconds < 60 ||
      !Number.isSafeInteger(attempt.startedAtMs) || attempt.startedAtMs <= 0 ||
      (attempt.deviceTx !== undefined && !validTx(attempt.deviceTx)) ||
      (attempt.sessionTx !== undefined && (!attempt.deviceTx || !validTx(attempt.sessionTx) ||
        attempt.sessionTx.nonce <= attempt.deviceTx.nonce))) {
    throw new Error("pending_canonical_login_invalid");
  }
  if (attempt.blocked) throw new Error("Pending login has an inconsistent acknowledgement. Inspect the tracked transaction before starting another attempt.");
  return attempt;
}

export function writeCanonicalLogin(attempt: CanonicalLoginAttempt, storage: Storage = sessionStorage): void {
  const key = storageKey(attempt.scope);
  const serialized = JSON.stringify(attempt);
  storage.setItem(key, serialized);
  if (storage.getItem(key) !== serialized) throw new Error("pending_canonical_login_storage_failed");
}

export function clearCanonicalLogin(scope: CanonicalLoginScope, storage: Storage = sessionStorage): void {
  storage.removeItem(storageKey(scope));
}

// Explicit signer removal must also discard any privately held candidates.
export function clearCanonicalLoginsForAccount(account: string, storage: Storage = sessionStorage): void {
  if (!account) return;
  for (let index = storage.length - 1; index >= 0; index -= 1) {
    const key = storage.key(index);
    if (!key?.startsWith(PREFIX)) continue;
    let parts: unknown;
    try { parts = JSON.parse(key.slice(PREFIX.length)); } catch { continue; }
    if (Array.isArray(parts) && parts[0] === account) storage.removeItem(key);
  }
}

export function canonicalLoginPayload(attempt: CanonicalLoginAttempt, step: "deviceTx" | "sessionTx"): Record<string, string | number> {
  return step === "deviceTx"
    ? { device_id: attempt.deviceId, device_type: "browser", label: "Browser session", pubkey: attempt.scope.pubkey }
    : { session_key: attempt.sessionKey, ttl_s: attempt.ttlSeconds };
}

function sortedFlatJson(value: Record<string, unknown>): string {
  const sorted: Record<string, unknown> = {};
  for (const key of Object.keys(value).sort()) sorted[key] = value[key];
  return JSON.stringify(sorted);
}

/** Mirrors runtime/tx_id.py for these two flat, user-signed envelopes only. */
export async function canonicalLoginTxId(attempt: CanonicalLoginAttempt, step: "deviceTx" | "sessionTx", envelope: TxEnvelope): Promise<string> {
  const txType = step === "deviceTx" ? "ACCOUNT_DEVICE_REGISTER" : "ACCOUNT_SESSION_KEY_ISSUE";
  const expected = canonicalLoginPayload(attempt, step);
  // Fixed diagnostic suffixes identify the failing field without exposing
  // account keys, bearer, signature, nonce value or other signed contents.
  const mismatch = envelope.chain_id !== attempt.chainId ? "chain"
    : envelope.signer !== attempt.scope.account ? "signer"
    : envelope.tx_type !== txType ? "type"
    : envelope.parent != null ? "parent"
    : !Number.isSafeInteger(envelope.nonce) || envelope.nonce <= 0 ? "nonce"
    : !envelope.payload || sortedFlatJson(envelope.payload) !== sortedFlatJson(expected) ? "payload"
    : "";
  if (mismatch) throw new Error("pending_canonical_login_envelope_mismatch:" + mismatch);
  const payload: Record<string, unknown> = {};
  for (const key of Object.keys(expected).sort()) payload[key] = expected[key];
  const canonical = sortedFlatJson({
    chain_id: attempt.chainId, nonce: envelope.nonce, payload,
    signer: attempt.scope.account, system: false, tx_type: txType,
  });
  const digest = await globalThis.crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical));
  return "tx:" + Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, "0")).join("");
}

/** Record the exact signed semantic identity before dispatch. Never replace an uncertain ID. */
export async function trackCanonicalLoginTx(attempt: CanonicalLoginAttempt, step: "deviceTx" | "sessionTx", envelope: TxEnvelope, storage: Storage = sessionStorage): Promise<void> {
  const txId = await canonicalLoginTxId(attempt, step, envelope);
  const previous = attempt[step];
  if (previous) {
    if (previous.txId !== txId || previous.nonce !== envelope.nonce) throw new Error("pending_canonical_login_already_tracked");
    return;
  }
  if (step === "sessionTx" && (!attempt.deviceTx || envelope.nonce <= attempt.deviceTx.nonce)) {
    throw new Error("pending_canonical_login_device_receipt_required");
  }
  attempt[step] = { txId, nonce: envelope.nonce };
  writeCanonicalLogin(attempt, storage);
}
