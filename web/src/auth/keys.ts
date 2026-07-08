import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";

// never persist raw account private keys anywhere except explicit user-approved
// browser storage / recovery material.  The browser secret format below is a
// WeAll-local recovery bundle: 32-byte ML-DSA seed || 1952-byte ML-DSA public
// key.  Keeping the seed instead of noble's expanded secret lets recovery files
// stay deterministic and lets the browser rederive the exact signing secret at
// signing time.
export type KeypairB64 = {
  pubkeyB64: string;
  secretKeyB64: string;
};

export type StoredKeypair = {
  version?: number;
  publicKey?: string;
  secretKey?: string;
  pubkeyB64?: string;
  secretKeyB64?: string;
  hasSecret?: boolean;
  sigProfile?: string;
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
export const MLDSA65_SEED_BYTES = 32;
export const MLDSA65_PUBLIC_KEY_BYTES = 1952;
export const MLDSA65_SECRET_KEY_BYTES = 4032;
export const MLDSA65_SIGNATURE_BYTES = 3309;
export const WEALL_BROWSER_SECRET_BUNDLE_BYTES = MLDSA65_SEED_BYTES + MLDSA65_PUBLIC_KEY_BYTES;

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
  const pad = raw.length % 4;
  const normalized = pad ? raw + "=".repeat(4 - pad) : raw;
  const binary = atob(normalized);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a[i] ^ b[i];
  return diff === 0;
}

function randomBytes(length: number): Uint8Array {
  const out = new Uint8Array(length);
  crypto.getRandomValues(out);
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

function splitBrowserSecretBundle(secretKeyB64: string): { seed: Uint8Array; publicKey: Uint8Array } {
  const secret = b64ToBytes(secretKeyB64);
  if (secret.length !== WEALL_BROWSER_SECRET_BUNDLE_BYTES) {
    throw new Error("invalid_mldsa_secret_bundle");
  }
  return {
    seed: secret.slice(0, MLDSA65_SEED_BYTES),
    publicKey: secret.slice(MLDSA65_SEED_BYTES),
  };
}

function expandedSecretKeyFromBundle(secretKeyB64: string): { publicKey: Uint8Array; secretKey: Uint8Array } {
  const { seed, publicKey } = splitBrowserSecretBundle(secretKeyB64);
  const generated = ml_dsa65.keygen(seed);
  if (!equalBytes(generated.publicKey, publicKey)) {
    throw new Error("mldsa_seed_public_key_mismatch");
  }
  return { publicKey, secretKey: generated.secretKey };
}

function readPublicKeyFromSecret(secretKeyB64: string): string {
  const { publicKey } = splitBrowserSecretBundle(secretKeyB64);
  return bytesToB64(publicKey);
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
  const seed = randomBytes(MLDSA65_SEED_BYTES);
  const keys = ml_dsa65.keygen(seed);
  const secretKeyB64 = bytesToB64(concatBytes(seed, keys.publicKey));
  return { pubkeyB64: bytesToB64(keys.publicKey), secretKeyB64 };
}

export function derivePublicKeyFromSecretKey(secretKeyB64: string): string {
  return readPublicKeyFromSecret(secretKeyB64);
}

export function validateKeypair(
  pubkeyB64: string,
  secretKeyB64: string,
): { ok: boolean; reason?: string } {
  try {
    const expectedPublicKey = b64ToBytes(pubkeyB64);
    if (expectedPublicKey.length !== MLDSA65_PUBLIC_KEY_BYTES) return { ok: false, reason: "invalid_mldsa_public_key_length" };
    const { publicKey, secretKey } = expandedSecretKeyFromBundle(secretKeyB64);
    if (!equalBytes(publicKey, expectedPublicKey)) return { ok: false, reason: "public_key_mismatch" };
    const msg = utf8ToBytes("weall.browser.mldsa65.keypair.selftest.v1");
    const sig = ml_dsa65.sign(msg, secretKey);
    if (sig.length !== MLDSA65_SIGNATURE_BYTES) return { ok: false, reason: "invalid_mldsa_signature_length" };
    if (!ml_dsa65.verify(sig, msg, expectedPublicKey)) {
      return { ok: false, reason: "selftest_verify_failed" };
    }
    return { ok: true };
  } catch (err: any) {
    return { ok: false, reason: String(err?.message || "invalid_mldsa_keypair") };
  }
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
  if (!valid.ok) throw new Error(`invalid_mldsa_keypair:${valid.reason || "unknown"}`);

  const secureMeta = { version: 3, sigProfile: BROWSER_PQ_SIG_PROFILE, publicKey: pubkeyB64, hasSecret: true };
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
  const secretKeyB64 = String(sessionStorage.getItem(secretStorageKey(normalized)) || "").trim();
  const pubkeyB64 = String(
    stored?.publicKey || stored?.pubkeyB64 || (secretKeyB64 ? readPublicKeyFromSecret(secretKeyB64) : ""),
  ).trim();

  if (!pubkeyB64 || !secretKeyB64) return null;
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
  return s.trim().length >= 10;
}

export function browserPqSigningNotice(): string {
  return "Browser-local ML-DSA signing is enabled for controlled-testnet account and session flows. This remains pending external cryptographic review before production security claims.";
}

export function signDetachedB64(secretKeyB64: string, msgBytes: Uint8Array): string {
  const { secretKey } = expandedSecretKeyFromBundle(secretKeyB64);
  const sig = ml_dsa65.sign(msgBytes, secretKey);
  return bytesToB64(sig);
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
