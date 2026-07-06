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
const MLDSA_BROWSER_SIGNING_AVAILABLE = false;

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

function readPublicKeyFromSecret(secretKeyB64: string): string {
  throw new Error("browser_pq_signing_not_implemented");
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
  throw new Error("browser_pq_signing_not_implemented");
}

export function derivePublicKeyFromSecretKey(secretKeyB64: string): string {
  return readPublicKeyFromSecret(secretKeyB64);
}

export function validateKeypair(
  pubkeyB64: string,
  secretKeyB64: string,
): { ok: boolean; reason?: string } {
  return { ok: false, reason: "browser_pq_signing_not_implemented" };
}

export function saveKeypair(
  account: string,
  kp: { pubkeyB64?: string; secretKeyB64: string },
): KeypairB64 {
  throw new Error("browser_pq_signing_not_implemented");
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
  return null;
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
  return "Browser-local protocol signing is disabled until a reviewed ML-DSA implementation is available; controlled/public testnet signing must use backend/operator custody.";
}


export function signDetachedB64(secretKeyB64: string, msgBytes: Uint8Array): string {
  throw new Error("browser_pq_signing_not_implemented");
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
