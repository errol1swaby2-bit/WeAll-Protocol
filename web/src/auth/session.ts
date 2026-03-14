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
import { weall } from "../api/weall";

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
  account: string; // canonical '@name'
  // Opaque string used by backend require_account_session gate.
  sessionKey?: string;
  // Client-side expiry hint (backend enforces TTL using ledger time).
  expiresAtMs: number;
};

const LS_SESSION = "weall_session_v1";
const LS_NONCE_RESERVATION_PREFIX = "weall_nonce_resv_v1::";

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
    if (!Number.isFinite(expiresAtMs) || expiresAtMs <= 0) return null;
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

async function nextNonce(account: string, base?: string): Promise<number> {
  const acct = normalizeAccount(account);
  if (!acct) throw new Error("invalid_account");

  let chainNext = 1;
  try {
    const a: any = await weall.account(acct, base);
    const onChain = Number(a?.state?.nonce ?? 0);
    if (Number.isFinite(onChain)) chainNext = Math.max(1, Math.floor(onChain) + 1);
  } catch {
    // If the account does not exist yet, nonce starts at 1.
    chainNext = 1;
  }

  const reserved = getReservedNonce(acct);
  const n = Math.max(chainNext, reserved + 1);
  setReservedNonce(acct, n);
  return n;
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
  const env: TxEnvelope = {
    chain_id: args.chain_id,
    tx_type: String(args.tx_type),
    signer: normalizeAccount(args.signer) || String(args.signer),
    nonce: Math.max(0, Math.floor(Number(args.nonce || 0))),
    payload: args.payload ?? {},
    parent: args.parent ?? null,
  };
  return env;
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
  const signer = normalizeAccount(args.account);
  if (!signer) throw new Error("invalid_account");

  const kp = loadKeypair(signer);
  if (!kp) throw new Error("missing_local_keypair");

  const chain_id = await resolveChainId();
  const nonce = await nextNonce(signer, args.base);

  const unsigned = buildUnsignedEnvelope({
    chain_id,
    tx_type: args.tx_type,
    signer,
    nonce,
    payload: args.payload ?? {},
    parent: args.parent ?? null,
  });
  const signed = signEnvelope(unsigned, kp);
  return await weall.txSubmit(signed, args.base);
}

export async function submitSignedTxWithNonce(args: {
  account: string;
  tx_type: string;
  payloadFactory: (nonce: number) => any;
  parent?: string | null;
  base?: string;
}): Promise<{ env: TxEnvelope; result: any }> {
  const signer = normalizeAccount(args.account);
  if (!signer) throw new Error("invalid_account");

  const kp = loadKeypair(signer);
  if (!kp) throw new Error("missing_local_keypair");

  const chain_id = await resolveChainId();
  const nonce = await nextNonce(signer, args.base);
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
  const result = await weall.txSubmit(signed, args.base);
  return { env: signed, result };
}

// ---------------------------------------------------------------------------
// On-chain session keys (device login)
// ---------------------------------------------------------------------------

export async function loginOnThisDevice(args: { account: string; ttlSeconds?: number; base?: string }): Promise<any> {
  const acct = normalizeAccount(args.account);
  if (!acct) throw new Error("invalid_account");

  const ttlSeconds = Math.max(60, Math.floor(Number(args.ttlSeconds ?? 24 * 60 * 60))); // default 24h
  const sessionKey = randomSessionKeyB64(32);
  const expiresAtMs = Date.now() + ttlSeconds * 1000;

  const res = await submitSignedTx({
    account: acct,
    tx_type: "ACCOUNT_SESSION_KEY_ISSUE",
    payload: { session_key: sessionKey, ttl_s: ttlSeconds },
    parent: null,
    base: args.base,
  });

  setSession({ version: 1, account: acct, sessionKey, expiresAtMs });
  return res;
}

export async function revokeSessionKeyOnChain(args: {
  account: string;
  sessionKey: string;
  base?: string;
}): Promise<any> {
  const acct = normalizeAccount(args.account);
  const sk = String(args.sessionKey || "").trim();
  if (!acct) throw new Error("invalid_account");
  if (!sk) throw new Error("missing_session_key");

  return await submitSignedTx({
    account: acct,
    tx_type: "ACCOUNT_SESSION_KEY_REVOKE",
    payload: { session_key: sk },
    parent: null,
    base: args.base,
  });
}
