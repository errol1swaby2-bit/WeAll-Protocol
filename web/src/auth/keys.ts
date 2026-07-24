import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";

// Raw account secret material is kept only for the active browser session or in an
// explicitly user-exported recovery file. We never persist raw account private keys
// in localStorage; local storage contains public metadata only.
export type KeypairB64 = {
  pubkeyB64: string;
  secretKeyB64: string;
};

export type StoredKeypair = {
  version?: number;
  sigProfile?: string;
  secretKeyFormat?: string;
  publicKey?: string;
  secretKey?: string;
  pubkeyB64?: string;
  secretKeyB64?: string;
  hasSecret?: boolean;
};

export type AccountIdValidation = {
  ok: boolean;
  normalized: string;
  reason?:
    | "empty"
    | "non_canonical"
    | "reserved_prefix"
    | "reserved_id"
    | "too_short"
    | "too_long"
    | "invalid_chars";
};

const KEYPAIR_PREFIX = "weall_keypair::";
const SECRET_PREFIX = "weall_secret::";
export const BROWSER_PQ_SIG_PROFILE = "pq-mldsa-v1";
export const CONTROLLED_TESTNET_SIG_PROFILE = "pq-mldsa-v1";
export const MLDSA65_SECRET_SEED_BYTES = 32;
export const MLDSA65_PUBLIC_KEY_BYTES = 1952;
export const MLDSA65_SIGNATURE_BYTES = 3309;
export const MLDSA65_SECRET_KEY_FORMAT = "mldsa65-seed-b64";
export const MLDSA65_PROTOCOL_CONTEXT = "weall:pq-mldsa-v1:protocol-signature";
const MLDSA65_PROTOCOL_CONTEXT_BYTES = new TextEncoder().encode(MLDSA65_PROTOCOL_CONTEXT);

function bytesToB64(bytes: Uint8Array): string {
  let binary = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

function b64ToBytes(value: string): Uint8Array {
  const raw = String(value || "")
    .trim()
    .replace(/\s+/g, "")
    .replace(/-/g, "+")
    .replace(/_/g, "/");
  if (!raw) return new Uint8Array();
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(raw)) throw new Error("invalid_base64");
  const pad = raw.length % 4;
  const normalized = pad ? raw + "=".repeat(4 - pad) : raw;
  const binary = atob(normalized);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

function utf8ToBytes(value: string): Uint8Array {
  return new TextEncoder().encode(String(value ?? ""));
}

function stableNormalize(value: any): any {
  if (value === null || value === undefined) return null;
  if (typeof value !== "object") return value;
  if (Array.isArray(value)) return value.map((item) => stableNormalize(item));
  const out: Record<string, unknown> = {};
  for (const key of Object.keys(value).sort()) {
    out[key] = stableNormalize(value[key]);
  }
  return out;
}

function stableStringify(value: any): string {
  return JSON.stringify(stableNormalize(value));
}

function secretStorageKey(account: string): string {
  return `${SECRET_PREFIX}${normalizeAccount(account)}`;
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let diff = 0;
  for (let i = 0; i < left.length; i++) diff |= left[i] ^ right[i];
  return diff === 0;
}

function keypairFromSeed(seed: Uint8Array): { publicKey: Uint8Array; secretKey: Uint8Array } {
  if (seed.length !== MLDSA65_SECRET_SEED_BYTES) throw new Error("invalid_mldsa65_seed_length");
  return ml_dsa65.keygen(seed);
}

function readPublicKeyFromSecret(secretKeyB64: string): string {
  let seed: Uint8Array;
  try {
    seed = b64ToBytes(secretKeyB64);
  } catch {
    throw new Error("invalid_secret_key_base64");
  }
  return bytesToB64(keypairFromSeed(seed).publicKey);
}

export function validateAccountId(raw: string): AccountIdValidation {
  const t0 = String(raw || "").trim();
  if (!t0) return { ok: false, normalized: "", reason: "empty" };

  if (!t0.startsWith("@") || /^@{2,}/.test(t0)) {
    const normalized = `@${t0.replace(/^@+/, "").toLowerCase()}`;
    return { ok: false, normalized, reason: "non_canonical" };
  }

  if (t0 !== t0.toLowerCase()) {
    return { ok: false, normalized: t0.toLowerCase(), reason: "non_canonical" };
  }

  const t = t0;
  if (t.startsWith("@_")) return { ok: false, normalized: t, reason: "reserved_prefix" };
  if (t === "@system" || t === "@_system") return { ok: false, normalized: t, reason: "reserved_id" };

  const name = t.slice(1);
  if (name.length < 1) return { ok: false, normalized: t, reason: "too_short" };
  if (name.length > 32) return { ok: false, normalized: t, reason: "too_long" };
  if (!/^[a-z0-9_]+$/.test(name)) return { ok: false, normalized: t, reason: "invalid_chars" };

  return { ok: true, normalized: t };
}

export function normalizeAccount(value: string): string {
  const v = String(value || "").trim();
  if (!v) return "";
  if (!v.startsWith("@")) {
    return `@${v.toLowerCase()}`;
  }
  return v.toLowerCase();
}

export function keyStorageKey(account: string): string {
  return `${KEYPAIR_PREFIX}${normalizeAccount(account)}`;
}

export function generateKeypair(): KeypairB64 {
  const seed = new Uint8Array(MLDSA65_SECRET_SEED_BYTES);
  crypto.getRandomValues(seed);
  const kp = keypairFromSeed(seed);
  if (kp.publicKey.length !== MLDSA65_PUBLIC_KEY_BYTES) throw new Error("invalid_generated_public_key_length");
  return {
    pubkeyB64: bytesToB64(kp.publicKey),
    secretKeyB64: bytesToB64(seed),
  };
}


const RECOVERY_AUTH_PUBLIC_PREFIX = "weall_recovery_authority_public::";
const RECOVERY_AUTH_SECRET_PREFIX = "weall_recovery_authority_secret::";

function recoveryAuthorityPublicKey(account: string): string {
  return `${RECOVERY_AUTH_PUBLIC_PREFIX}${normalizeAccount(account)}`;
}

function recoveryAuthoritySecretKey(account: string): string {
  return `${RECOVERY_AUTH_SECRET_PREFIX}${normalizeAccount(account)}`;
}

export function saveRecoveryAuthorityKeypair(account: string, pair: KeypairB64): void {
  const normalized = normalizeAccount(account);
  if (!normalized) throw new Error("account_required");
  const valid = validateKeypair(pair.pubkeyB64, pair.secretKeyB64);
  if (!valid.ok) throw new Error(`invalid_recovery_authority:${valid.reason || "unknown"}`);
  localStorage.setItem(recoveryAuthorityPublicKey(normalized), pair.pubkeyB64);
  sessionStorage.setItem(recoveryAuthoritySecretKey(normalized), pair.secretKeyB64);
}

export function loadRecoveryAuthorityKeypair(account: string): KeypairB64 | null {
  const normalized = normalizeAccount(account);
  if (!normalized) return null;
  const pubkeyB64 = String(localStorage.getItem(recoveryAuthorityPublicKey(normalized)) || "").trim();
  const secretKeyB64 = String(sessionStorage.getItem(recoveryAuthoritySecretKey(normalized)) || "").trim();
  if (!pubkeyB64 || !secretKeyB64) return null;
  return validateKeypair(pubkeyB64, secretKeyB64).ok ? { pubkeyB64, secretKeyB64 } : null;
}

export function ensureRecoveryAuthorityKeypair(account: string): KeypairB64 {
  const existing = loadRecoveryAuthorityKeypair(account);
  if (existing) return existing;
  const pair = generateKeypair();
  saveRecoveryAuthorityKeypair(account, pair);
  return pair;
}

export function derivePublicKeyFromSecretKey(secretKeyB64: string): string {
  return readPublicKeyFromSecret(secretKeyB64);
}

export function validateKeypair(
  pubkeyB64: string,
  secretKeyB64: string,
): { ok: boolean; reason?: string } {
  let publicKey: Uint8Array;
  let seed: Uint8Array;
  try {
    publicKey = b64ToBytes(pubkeyB64);
  } catch {
    return { ok: false, reason: "invalid_public_key_base64" };
  }
  try {
    seed = b64ToBytes(secretKeyB64);
  } catch {
    return { ok: false, reason: "invalid_secret_key_base64" };
  }
  if (seed.length !== MLDSA65_SECRET_SEED_BYTES) {
    return { ok: false, reason: "invalid_secret_key_length" };
  }
  if (publicKey.length !== MLDSA65_PUBLIC_KEY_BYTES) {
    return { ok: false, reason: "invalid_public_key_length" };
  }
  try {
    const derived = keypairFromSeed(seed).publicKey;
    if (!equalBytes(publicKey, derived)) return { ok: false, reason: "public_key_mismatch" };
  } catch {
    return { ok: false, reason: "invalid_secret_key" };
  }
  return { ok: true };
}

export function saveKeypair(
  account: string,
  kp: { pubkeyB64?: string; secretKeyB64: string },
): KeypairB64 {
  const normalized = normalizeAccount(account);
  if (!normalized) throw new Error("account_required");

  const secretKeyB64 = String(kp?.secretKeyB64 || "").trim();
  if (!secretKeyB64) throw new Error("secret_key_required");

  const pubkeyB64 = String(kp?.pubkeyB64 || readPublicKeyFromSecret(secretKeyB64)).trim();
  if (!pubkeyB64) throw new Error("public_key_required");
  const valid = validateKeypair(pubkeyB64, secretKeyB64);
  if (!valid.ok) throw new Error(`invalid_keypair:${valid.reason || "unknown"}`);

  const secureMeta: StoredKeypair = {
    version: 3,
    sigProfile: BROWSER_PQ_SIG_PROFILE,
    secretKeyFormat: MLDSA65_SECRET_KEY_FORMAT,
    publicKey: pubkeyB64,
    hasSecret: false,
  };
  localStorage.setItem(keyStorageKey(normalized), JSON.stringify(secureMeta));
  sessionStorage.setItem(secretStorageKey(normalized), secretKeyB64);

  return { pubkeyB64, secretKeyB64 };
}

function readStoredKeypair(raw: string | null): StoredKeypair | null {
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw) as StoredKeypair;
    if (!parsed || typeof parsed !== "object") return null;
    return parsed;
  } catch {
    return null;
  }
}

export function loadKeypair(account: string): KeypairB64 | null {
  const normalized = normalizeAccount(account);
  if (!normalized) return null;

  const stored = readStoredKeypair(localStorage.getItem(keyStorageKey(normalized)));
  if (stored?.sigProfile && stored.sigProfile !== BROWSER_PQ_SIG_PROFILE) return null;
  if (stored?.secretKeyFormat && stored.secretKeyFormat !== MLDSA65_SECRET_KEY_FORMAT) return null;

  const secretKeyB64 = String(sessionStorage.getItem(secretStorageKey(normalized)) || "").trim();
  if (!secretKeyB64) return null;
  let pubkeyB64 = String(stored?.publicKey || stored?.pubkeyB64 || "").trim();
  try {
    if (!pubkeyB64) pubkeyB64 = readPublicKeyFromSecret(secretKeyB64);
  } catch {
    return null;
  }
  const valid = validateKeypair(pubkeyB64, secretKeyB64);
  if (!valid.ok) return null;
  return { pubkeyB64, secretKeyB64 };
}

export function getKeypair(account: string): KeypairB64 | null {
  return loadKeypair(account);
}

export function deleteKeypair(account: string): void {
  const normalized = normalizeAccount(account);
  if (!normalized) return;
  localStorage.removeItem(keyStorageKey(normalized));
  sessionStorage.removeItem(secretStorageKey(normalized));
}

export function removeKeypair(account: string): void {
  deleteKeypair(account);
}

export function hasSecretInSession(account: string): boolean {
  const normalized = normalizeAccount(account);
  if (!normalized) return false;
  const s = String(sessionStorage.getItem(secretStorageKey(normalized)) || "");
  try {
    return b64ToBytes(s).length === MLDSA65_SECRET_SEED_BYTES;
  } catch {
    return false;
  }
}

export function browserPqSigningNotice(): string {
  return "Controlled-testnet browser-local ML-DSA-65 protocol signing is enabled. Recovery files contain the 32-byte signing seed and must be kept private; this is not a production hardware-wallet boundary.";
}

export function signDetachedB64(secretKeyB64: string, msgBytes: Uint8Array): string {
  let seed: Uint8Array;
  try {
    seed = b64ToBytes(secretKeyB64);
  } catch {
    throw new Error("invalid_secret_key_base64");
  }
  const kp = keypairFromSeed(seed);
  const signature = ml_dsa65.sign(msgBytes, kp.secretKey, { context: MLDSA65_PROTOCOL_CONTEXT_BYTES });
  if (signature.length !== MLDSA65_SIGNATURE_BYTES) throw new Error("invalid_mldsa65_signature_length");
  return bytesToB64(signature);
}

export function verifyDetachedB64(
  pubkeyB64: string,
  msgBytes: Uint8Array,
  signatureB64: string,
): boolean {
  let publicKey: Uint8Array;
  let signature: Uint8Array;
  try {
    publicKey = b64ToBytes(pubkeyB64);
    signature = b64ToBytes(signatureB64);
  } catch {
    return false;
  }
  if (publicKey.length !== MLDSA65_PUBLIC_KEY_BYTES || signature.length !== MLDSA65_SIGNATURE_BYTES) {
    return false;
  }
  try {
    return ml_dsa65.verify(signature, msgBytes, publicKey, { context: MLDSA65_PROTOCOL_CONTEXT_BYTES });
  } catch {
    return false;
  }
}

export function canonicalTxMessage(env: {
  chain_id: string;
  network_id?: string;
  sig_profile?: string;
  tx_type: string;
  signer: string;
  nonce: number;
  payload: any;
  parent: string | null;
}): Uint8Array {
  const chain_id = String(env.chain_id || "").trim();
  const network_id = String(env.network_id || "").trim();
  const sig_profile = String(env.sig_profile || BROWSER_PQ_SIG_PROFILE).trim();
  const tx_type = String(env.tx_type || "");
  const signer = String(env.signer || "");
  const nonce = Math.floor(Number(env.nonce || 0));
  const payload = env.payload && typeof env.payload === "object" ? env.payload : {};
  const parent = env.parent == null ? null : String(env.parent);

  const obj: Record<string, unknown> = {
    ...(chain_id ? { chain_id } : {}),
    ...(network_id ? { network_id } : {}),
    domain_separator: "weall.tx.v1",
    object_kind: "tx",
    sig_profile,
    tx_type,
    signer,
    nonce,
    payload,
    ...(parent != null ? { parent } : {}),
  };

  return utf8ToBytes(stableStringify(obj));
}
