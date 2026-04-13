// projects/web/src/auth/session.ts
//
// Frontend session + tx signing helpers aligned to the backend.
//
// This module is intentionally the single integration point between:
//   - local keys (auth/keys.ts)
//   - on-chain session keys (ACCOUNT_SESSION_KEY_ISSUE / REVOKE)
//   - API auth headers (x-weall-account / x-weall-session-key)
//   - tx submission (/v1/tx/submit)

import { getChainId, getEnvChainId } from "../lib/chain";
import { createBrowserSession, weall } from "../api/weall";

import {
  KeypairB64,
  canonicalTxMessage,
  deleteKeypair,
  generateKeypair,
  loadKeypair,
  normalizeAccount,
  saveKeypair,
  signDetachedB64,
} from "./keys";

export type SessionV1 = {
  version: 1;
  account: string;
  sessionKey?: string;
  expiresAtMs: number;
};

const LS_SESSION = "weall_session_v1";
const LS_NONCE_RESERVATION_PREFIX = "weall_nonce_resv_v1::";

type SignerSubmissionSnapshot = {
  account: string;
  pendingCount: number;
};

const signerSubmissionQueues = new Map<string, Promise<unknown>>();
const signerPendingCounts = new Map<string, number>();
const signerSubmissionListeners = new Map<string, Set<(snapshot: SignerSubmissionSnapshot) => void>>();

function b64Encode(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

function normalizeB64(s: string): string {
  const raw = String(s || "").trim().replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/");
  const pad = raw.length % 4;
  return pad ? raw + "=".repeat(4 - pad) : raw;
}

function b64Decode(s: string): Uint8Array {
  const bin = atob(normalizeB64(s));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function composeSecretKeyB64(nodeSeedB64: string, nodePubkeyB64: string): string {
  const seed = b64Decode(nodeSeedB64);
  const pub = b64Decode(nodePubkeyB64);
  if (seed.length !== 32) throw new Error("invalid_node_seed");
  if (pub.length !== 32) throw new Error("invalid_node_pubkey");
  const secret = new Uint8Array(64);
  secret.set(seed, 0);
  secret.set(pub, 32);
  return b64Encode(secret);
}

function randomSessionKeyB64(bytes = 32): string {
  const u = new Uint8Array(bytes);
  crypto.getRandomValues(u);
  return b64Encode(u);
}

function randomDeviceId(account: string): string {
  const u = new Uint8Array(12);
  crypto.getRandomValues(u);
  const suffix = Array.from(u).map((b) => b.toString(16).padStart(2, "0")).join("");
  return `browser:${normalizeAccount(account)}:${suffix}`;
}

function canonicalSessionLoginMessage(args: {
  account: string;
  sessionKey: string;
  ttlSeconds: number;
  issuedAtMs: number;
  deviceId: string;
}): Uint8Array {
  const obj = {
    t: "SESSION_LOGIN",
    account: normalizeAccount(args.account),
    session_key: String(args.sessionKey || ""),
    ttl_s: Math.max(60, Math.floor(Number(args.ttlSeconds || 0))),
    issued_at_ms: Math.floor(Number(args.issuedAtMs || 0)),
    device_id: String(args.deviceId || ""),
  };
  return new TextEncoder().encode(JSON.stringify(obj, Object.keys(obj).sort()));
}

export function getSession(): SessionV1 | null {
  try {
    const raw = localStorage.getItem(LS_SESSION);
    if (!raw) return null;
    const obj = JSON.parse(raw);
    if (!obj || typeof obj !== "object") return null;
    if (obj.version !== 1) return null;
    const account = normalizeAccount(String(obj.account || ""));
    if (!account) return null;
    const expiresAtMs = Number(obj.expiresAtMs || 0);
    if (!Number.isFinite(expiresAtMs) || expiresAtMs <= 0) {
      endSession();
      return null;
    }
    if (Date.now() >= expiresAtMs) {
      endSession();
      return null;
    }
    const sessionKey = obj.sessionKey ? String(obj.sessionKey) : undefined;
    return { version: 1, account, expiresAtMs, sessionKey };
  } catch {
    return null;
  }
}

export function setSession(s: SessionV1): void {
  const account = normalizeAccount(s.account);
  const expiresAtMs = Number(s.expiresAtMs || 0);
  if (!account) throw new Error("invalid_session_account");
  if (!Number.isFinite(expiresAtMs) || expiresAtMs <= 0) throw new Error("invalid_session_expiry");
  const out: SessionV1 = {
    version: 1,
    account,
    expiresAtMs,
    sessionKey: s.sessionKey ? String(s.sessionKey) : undefined,
  };
  localStorage.setItem(LS_SESSION, JSON.stringify(out));
}

export function endSession(): void {
  try {
    localStorage.removeItem(LS_SESSION);
  } catch {
    // ignore
  }
}

export function getKeypair(account: string): KeypairB64 | null {
  return loadKeypair(account);
}

export function ensureKeypair(account: string): KeypairB64 {
  const acct = normalizeAccount(account);
  if (!acct) throw new Error("invalid_account");
  const existing = loadKeypair(acct);
  if (existing) return existing;
  const kp = generateKeypair();
  saveKeypair(acct, kp);
  return kp;
}

export function clearKeypair(account: string): void {
  deleteKeypair(account);
}

export function clearSession(): void {
  endSession();
}

export function removeKeypair(account: string): void {
  clearKeypair(account);
}

export function issueSessionFromSecretKey(args: {
  account: string;
  secretKeyB64: string;
  ttlSeconds?: number;
}): { session: SessionV1; keypair: KeypairB64 } {
  const acct = normalizeAccount(args.account);
  const secretKeyB64 = String(args.secretKeyB64 || "").trim();
  if (!acct) throw new Error("invalid_account");
  if (!secretKeyB64) throw new Error("secret_key_required");

  const secretBytes = b64Decode(secretKeyB64);
  if (secretBytes.length !== 64) throw new Error("invalid_secret_key");

  const publicBytes = secretBytes.slice(32);
  let pubBin = "";
  for (let i = 0; i < publicBytes.length; i++) pubBin += String.fromCharCode(publicBytes[i]);
  const pubkeyB64 = btoa(pubBin);

  const kp: KeypairB64 = { pubkeyB64, secretKeyB64 };
  saveKeypair(acct, kp);

  const ttlSeconds = Math.max(60, Math.floor(Number(args.ttlSeconds ?? 24 * 60 * 60)));
  const session: SessionV1 = {
    version: 1,
    account: acct,
    expiresAtMs: Date.now() + ttlSeconds * 1000,
  };
  setSession(session);
  return { session, keypair: kp };
}

export function getAuthHeaders(account?: string): Record<string, string> {
  const s = getSession();
  if (!s) return {};
  const acct = normalizeAccount(account || s.account);
  if (!acct || acct !== s.account) return {};
  if (!s.sessionKey) return {};
  return {
    "x-weall-account": acct,
    "x-weall-session-key": String(s.sessionKey),
  };
}

function nonceReservationKey(account: string): string {
  return `${LS_NONCE_RESERVATION_PREFIX}${normalizeAccount(account)}`;
}

export function clearNonceReservation(account: string): void {
  try {
    localStorage.removeItem(nonceReservationKey(account));
  } catch {
    // ignore
  }
}

function getReservedNonce(account: string): number {
  try {
    const raw = localStorage.getItem(nonceReservationKey(account));
    if (!raw) return 0;
    const n = Number(raw);
    return Number.isFinite(n) ? Math.max(0, Math.floor(n)) : 0;
  } catch {
    return 0;
  }
}

function setReservedNonce(account: string, nonce: number): void {
  try {
    localStorage.setItem(nonceReservationKey(account), String(Math.max(0, Math.floor(nonce))));
  } catch {
    // ignore
  }
}

function extractErrorCode(error: unknown): string {
  const src = error && typeof error === "object" ? (error as Record<string, any>) : {};
  const direct = String(src.code || "").trim();
  if (direct) return direct;

  const payload = src.payload && typeof src.payload === "object" ? (src.payload as Record<string, any>) : {};
  const payloadCode = String(payload.error?.code || payload.code || "").trim();
  if (payloadCode) return payloadCode;

  const payloadDetails = payload.error?.details && typeof payload.error.details === "object"
    ? (payload.error.details as Record<string, any>)
    : {};
  const nested = payloadDetails.details && typeof payloadDetails.details === "object"
    ? (payloadDetails.details as Record<string, any>)
    : {};
  for (const candidate of [payloadDetails.error, payloadDetails.code, nested.error, nested.code, nested.reason]) {
    const normalized = String(candidate || "").trim();
    if (normalized) return normalized;
  }

  const body = src.body && typeof src.body === "object" ? (src.body as Record<string, any>) : {};
  const bodyCode = String(body.error?.code || body.code || "").trim();
  if (bodyCode) return bodyCode;

  const bodyDetails = body.error?.details && typeof body.error.details === "object"
    ? (body.error.details as Record<string, any>)
    : {};
  for (const candidate of [bodyDetails.error, bodyDetails.code, bodyDetails.reason]) {
    const normalized = String(candidate || "").trim();
    if (normalized) return normalized;
  }

  return "";
}

function isNonceReservationConflictError(error: unknown): boolean {
  const code = extractErrorCode(error);
  return code === "bad_nonce" || code === "mempool_signer_nonce_conflict" || code === "tx_id_conflict";
}

function pendingSnapshot(account: string): SignerSubmissionSnapshot {
  const signer = normalizeAccount(account);
  return {
    account: signer,
    pendingCount: signer ? Math.max(0, Math.floor(signerPendingCounts.get(signer) || 0)) : 0,
  };
}

function emitSignerSubmissionSnapshot(account: string): void {
  const signer = normalizeAccount(account);
  if (!signer) return;
  const listeners = signerSubmissionListeners.get(signer);
  if (!listeners || !listeners.size) return;
  const snapshot = pendingSnapshot(signer);
  listeners.forEach((listener) => {
    try {
      listener(snapshot);
    } catch {
      // ignore listener failure
    }
  });
}

function setSignerPendingCount(account: string, nextCount: number): void {
  const signer = normalizeAccount(account);
  if (!signer) return;
  const normalized = Math.max(0, Math.floor(nextCount));
  if (normalized <= 0) signerPendingCounts.delete(signer);
  else signerPendingCounts.set(signer, normalized);
  emitSignerSubmissionSnapshot(signer);
}

export function isSignerSubmissionBusy(account: string): boolean {
  return pendingSnapshot(account).pendingCount > 0;
}

export function getSignerSubmissionSnapshot(account: string): SignerSubmissionSnapshot {
  return pendingSnapshot(account);
}

export function subscribeSignerSubmission(account: string, listener: (snapshot: SignerSubmissionSnapshot) => void): () => void {
  const signer = normalizeAccount(account);
  if (!signer) {
    listener({ account: "", pendingCount: 0 });
    return () => undefined;
  }
  const listeners = signerSubmissionListeners.get(signer) || new Set<(snapshot: SignerSubmissionSnapshot) => void>();
  listeners.add(listener);
  signerSubmissionListeners.set(signer, listeners);
  listener(pendingSnapshot(signer));
  return () => {
    const current = signerSubmissionListeners.get(signer);
    if (!current) return;
    current.delete(listener);
    if (!current.size) signerSubmissionListeners.delete(signer);
  };
}

export async function syncNonceReservation(account: string, base?: string): Promise<number> {
  const acct = normalizeAccount(account);
  if (!acct) throw new Error("invalid_account");

  try {
    const a: any = await weall.account(acct, base);
    const onChain = Number(a?.state?.nonce ?? 0);
    if (Number.isFinite(onChain) && onChain >= 0) {
      setReservedNonce(acct, Math.floor(onChain));
      return Math.floor(onChain);
    }
  } catch {
    // ignore and fall through to clear
  }

  clearNonceReservation(acct);
  return 0;
}

type NonceClaim = {
  account: string;
  nonce: number;
  previousReserved: number;
};

export type NonceSequence = {
  account: string;
  nextNonce: number;
};

function runSignerSerialized<T>(account: string, task: () => Promise<T>): Promise<T> {
  const signer = normalizeAccount(account);
  if (!signer) return Promise.reject(new Error("invalid_account"));

  const previous = signerSubmissionQueues.get(signer) || Promise.resolve();
  const current = previous
    .catch(() => undefined)
    .then(async () => {
      const currentCount = signerPendingCounts.get(signer) || 0;
      setSignerPendingCount(signer, currentCount + 1);
      try {
        return await task();
      } finally {
        const nextCount = Math.max(0, (signerPendingCounts.get(signer) || 1) - 1);
        setSignerPendingCount(signer, nextCount);
      }
    });

  signerSubmissionQueues.set(signer, current);

  return current.finally(() => {
    if (signerSubmissionQueues.get(signer) === current) {
      signerSubmissionQueues.delete(signer);
    }
  });
}

export async function beginNonceSequence(account: string, base?: string): Promise<NonceSequence> {
  const acct = normalizeAccount(account);
  if (!acct) throw new Error("invalid_account");
  const synced = await syncNonceReservation(acct, base);
  return {
    account: acct,
    nextNonce: Math.max(1, Math.floor(synced) + 1),
  };
}

export async function submitSignedTxInSequence(args: {
  sequence: NonceSequence;
  tx_type: string;
  payloadFactory: (nonce: number) => any;
  parent?: string | null;
  base?: string;
}): Promise<{ env: TxEnvelope; result: any }> {
  return runSignerSerialized(args.sequence.account, async () => {
    const signer = normalizeAccount(args.sequence.account);
    if (!signer) throw new Error("invalid_account");

    const kp = loadKeypair(signer);
    if (!kp) throw new Error("missing_local_keypair");

    const chain_id = await resolveChainId();

    for (let attempt = 0; attempt < 2; attempt += 1) {
      const nonce = Math.max(1, Math.floor(args.sequence.nextNonce));
      const payload = args.payloadFactory(nonce);
      const unsigned = buildUnsignedEnvelope({
        chain_id,
        tx_type: args.tx_type,
        signer,
        nonce,
        payload,
        parent: args.parent ?? null,
      });
      const signed = signEnvelope(unsigned, kp);

      try {
        const result = await weall.txSubmit(signed, args.base);
        args.sequence.nextNonce = nonce + 1;
        setReservedNonce(signer, nonce);
        return { env: signed, result };
      } catch (error) {
        if (attempt === 0 && isNonceReservationConflictError(error)) {
          const synced = await syncNonceReservation(signer, args.base);
          args.sequence.nextNonce = Math.max(1, synced + 1);
          continue;
        }
        throw error;
      }
    }

    throw new Error("nonce_retry_exhausted");
  });
}

async function claimNextNonce(account: string, base?: string): Promise<NonceClaim> {
  const acct = normalizeAccount(account);
  if (!acct) throw new Error("invalid_account");

  let chainNext = 1;
  try {
    const a: any = await weall.account(acct, base);
    const onChain = Number(a?.state?.nonce ?? 0);
    if (Number.isFinite(onChain)) chainNext = Math.max(1, Math.floor(onChain) + 1);
  } catch {
    chainNext = 1;
  }

  const previousReserved = getReservedNonce(acct);
  const nonce = Math.max(chainNext, previousReserved + 1);
  setReservedNonce(acct, nonce);
  return { account: acct, nonce, previousReserved };
}

function rollbackNonceClaim(claim: NonceClaim | null | undefined): void {
  if (!claim) return;
  try {
    const current = getReservedNonce(claim.account);
    if (current !== claim.nonce) return;
    if (claim.previousReserved > 0) {
      setReservedNonce(claim.account, claim.previousReserved);
    } else {
      localStorage.removeItem(nonceReservationKey(claim.account));
    }
  } catch {
    // ignore
  }
}

export type TxEnvelope = {
  chain_id?: string;
  tx_type: string;
  signer: string;
  nonce: number;
  payload: any;
  parent?: string | null;
  sig?: string;
};

function buildUnsignedEnvelope(args: {
  chain_id?: string;
  tx_type: string;
  signer: string;
  nonce: number;
  payload: any;
  parent?: string | null;
}): TxEnvelope {
  return {
    chain_id: args.chain_id,
    tx_type: String(args.tx_type),
    signer: normalizeAccount(args.signer) || String(args.signer),
    nonce: Math.max(0, Math.floor(Number(args.nonce || 0))),
    payload: args.payload ?? {},
    parent: args.parent ?? null,
  };
}

function signEnvelope(env: TxEnvelope, kp: KeypairB64): TxEnvelope {
  const msg = canonicalTxMessage({
    chain_id: env.chain_id || "",
    tx_type: env.tx_type,
    signer: env.signer,
    nonce: env.nonce,
    payload: env.payload ?? {},
    parent: env.parent ?? null,
  });
  const sig = signDetachedB64(kp.secretKeyB64, msg);
  return { ...env, sig };
}

async function resolveChainId(): Promise<string> {
  try {
    return (await getChainId()) || getEnvChainId() || "testnet";
  } catch {
    return getEnvChainId() || "testnet";
  }
}

export async function submitSignedTx(args: {
  account: string;
  tx_type: string;
  payload: any;
  parent?: string | null;
  base?: string;
}): Promise<any> {
  return runSignerSerialized(args.account, async () => {
    const signer = normalizeAccount(args.account);
    if (!signer) throw new Error("invalid_account");

    const kp = loadKeypair(signer);
    if (!kp) throw new Error("missing_local_keypair");

    const chain_id = await resolveChainId();

    for (let attempt = 0; attempt < 2; attempt += 1) {
      const claim = await claimNextNonce(signer, args.base);
      const unsigned = buildUnsignedEnvelope({
        chain_id,
        tx_type: args.tx_type,
        signer,
        nonce: claim.nonce,
        payload: args.payload ?? {},
        parent: args.parent ?? null,
      });
      const signed = signEnvelope(unsigned, kp);
      try {
        return await weall.txSubmit(signed, args.base);
      } catch (error) {
        rollbackNonceClaim(claim);
        if (attempt === 0 && isNonceReservationConflictError(error)) {
          await syncNonceReservation(signer, args.base);
          continue;
        }
        throw error;
      }
    }

    throw new Error("nonce_retry_exhausted");
  });
}

export async function submitSignedTxWithNonce(args: {
  account: string;
  tx_type: string;
  payloadFactory: (nonce: number) => any;
  parent?: string | null;
  base?: string;
}): Promise<{ env: TxEnvelope; result: any }> {
  return runSignerSerialized(args.account, async () => {
    const signer = normalizeAccount(args.account);
    if (!signer) throw new Error("invalid_account");

    const kp = loadKeypair(signer);
    if (!kp) throw new Error("missing_local_keypair");

    const chain_id = await resolveChainId();

    for (let attempt = 0; attempt < 2; attempt += 1) {
      const claim = await claimNextNonce(signer, args.base);
      const payload = args.payloadFactory(claim.nonce);

      const unsigned = buildUnsignedEnvelope({
        chain_id,
        tx_type: args.tx_type,
        signer,
        nonce: claim.nonce,
        payload,
        parent: args.parent ?? null,
      });
      const signed = signEnvelope(unsigned, kp);
      try {
        const result = await weall.txSubmit(signed, args.base);
        return { env: signed, result };
      } catch (error) {
        rollbackNonceClaim(claim);
        if (attempt === 0 && isNonceReservationConflictError(error)) {
          await syncNonceReservation(signer, args.base);
          continue;
        }
        throw error;
      }
    }

    throw new Error("nonce_retry_exhausted");
  });
}

export async function restoreAccountAndLoginOnThisDevice(args: {
  account: string;
  secretKeyB64: string;
  ttlSeconds?: number;
  base?: string;
}): Promise<{ session: SessionV1; keypair: KeypairB64; result: any }> {
  const acct = normalizeAccount(args.account);
  const secretKeyB64 = String(args.secretKeyB64 || "").trim();
  if (!acct) throw new Error("invalid_account");
  if (!secretKeyB64) throw new Error("secret_key_required");

  endSession();
  clearNonceReservation(acct);
  const keypair = saveKeypair(acct, { secretKeyB64 });

  try {
    const result = await loginOnThisDevice({
      account: acct,
      ttlSeconds: args.ttlSeconds,
      base: args.base,
    });
    const session = getSession();
    if (!session || !session.sessionKey) throw new Error("session_issue_failed");
    return { session, keypair, result };
  } catch (error) {
    endSession();
    throw error;
  }
}

export async function loginOnThisDevice(args: { account: string; ttlSeconds?: number; base?: string }): Promise<any> {
  const acct = normalizeAccount(args.account);
  if (!acct) throw new Error("invalid_account");

  const ttlSeconds = Math.max(60, Math.floor(Number(args.ttlSeconds ?? 24 * 60 * 60)));
  const requestedSessionKey = randomSessionKeyB64(32);
  const deviceId = randomDeviceId(acct);
  const issuedAtMs = Date.now();

  const kp = loadKeypair(acct);
  if (!kp) throw new Error("missing_local_keypair");

  const sig = signDetachedB64(
    kp.secretKeyB64,
    canonicalSessionLoginMessage({
      account: acct,
      sessionKey: requestedSessionKey,
      ttlSeconds,
      issuedAtMs,
      deviceId,
    }),
  );

  const response = await createBrowserSession(
    {
      account: acct,
      session_key: requestedSessionKey,
      ttl_s: ttlSeconds,
      issued_at_ms: issuedAtMs,
      device_id: deviceId,
      sig,
      pubkey: kp.pubkeyB64,
    },
    args.base,
  );

  const expiresAtMs = Date.now() + ttlSeconds * 1000;
  setSession({
    version: 1,
    account: acct,
    sessionKey: requestedSessionKey,
    expiresAtMs,
  });
  return response;
}



export async function ensureBackendSession(args: { account: string; ttlSeconds?: number; base?: string }): Promise<SessionV1> {
  const acct = normalizeAccount(args.account);
  if (!acct) throw new Error("invalid_account");

  const ttlSeconds = Math.max(60, Math.floor(Number(args.ttlSeconds ?? 24 * 60 * 60)));
  const current = getSession();
  if (current?.account === acct && current.sessionKey && current.expiresAtMs > Date.now()) {
    return current;
  }

  const kp = loadKeypair(acct);
  if (!kp) throw new Error("missing_local_keypair");

  await loginOnThisDevice({
    account: acct,
    ttlSeconds,
    base: args.base,
  });

  const repaired = getSession();
  if (!repaired?.account || repaired.account !== acct || !repaired.sessionKey) {
    throw new Error("session_issue_failed");
  }
  return repaired;
}

export async function revokeSessionKeyOnChain(args: { account: string; sessionKey: string; base?: string }): Promise<any> {
  const account = normalizeAccount(args.account);
  const sessionKey = String(args.sessionKey || "").trim();
  if (!account) throw new Error("invalid_account");
  if (!sessionKey) throw new Error("session_key_required");

  return await submitSignedTx({
    account,
    tx_type: "ACCOUNT_SESSION_KEY_REVOKE",
    payload: { session_key: sessionKey },
    parent: null,
    base: args.base,
  });
}

export async function revokeCurrentSessionKey(args?: { base?: string }): Promise<any> {
  const s = getSession();
  if (!s?.account || !s?.sessionKey) throw new Error("not_logged_in");
  return await submitSignedTx({
    account: s.account,
    tx_type: "ACCOUNT_SESSION_KEY_REVOKE",
    payload: { session_key: s.sessionKey },
    parent: null,
    base: args?.base,
  });
}

export async function issueFreshSessionKey(args?: { ttlSeconds?: number; base?: string }): Promise<any> {
  const s = getSession();
  if (!s?.account) throw new Error("not_logged_in");

  const acct = normalizeAccount(s.account);
  const ttlSeconds = Math.max(60, Math.floor(Number(args?.ttlSeconds ?? 24 * 60 * 60)));
  const sessionKey = randomSessionKeyB64(32);

  const result = await submitSignedTx({
    account: acct,
    tx_type: "ACCOUNT_SESSION_KEY_ISSUE",
    payload: { session_key: sessionKey, ttl_s: ttlSeconds },
    parent: null,
    base: args?.base,
  });

  setSession({
    version: 1,
    account: acct,
    sessionKey,
    expiresAtMs: Date.now() + ttlSeconds * 1000,
  });
  return result;
}
