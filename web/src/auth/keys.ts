import nacl from "tweetnacl";

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

const KEYRING_PREFIX = "weall.keyring.";
const KEYPAIR_PREFIX = "weall_keypair::";
const SECRET_PREFIX = "weall_secret::";
const SECRET_KEY_BYTES = 64;
const PUBLIC_KEY_BYTES = 32;

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
  const secret = b64ToBytes(String(secretKeyB64 || "").trim());
  if (secret.length !== SECRET_KEY_BYTES) {
    throw new Error("secret_key_must_be_64_bytes_base64");
  }
  return bytesToB64(secret.slice(PUBLIC_KEY_BYTES));
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
  const kp = nacl.sign.keyPair();
  return {
    pubkeyB64: bytesToB64(kp.publicKey),
    secretKeyB64: bytesToB64(kp.secretKey),
  };
}

export function derivePublicKeyFromSecretKey(secretKeyB64: string): string {
  return readPublicKeyFromSecret(secretKeyB64);
}

export function validateKeypair(
  pubkeyB64: string,
  secretKeyB64: string,
): { ok: boolean; reason?: string } {
  try {
    const pub = b64ToBytes(String(pubkeyB64 || ""));
    const sec = b64ToBytes(String(secretKeyB64 || ""));
    if (pub.length !== PUBLIC_KEY_BYTES) return { ok: false, reason: "pubkey_len" };
    if (sec.length !== SECRET_KEY_BYTES) return { ok: false, reason: "secret_len" };
    for (let i = 0; i < PUBLIC_KEY_BYTES; i++) {
      if (sec[PUBLIC_KEY_BYTES + i] !== pub[i]) {
        return { ok: false, reason: "pubkey_mismatch" };
      }
    }
    return { ok: true };
  } catch {
    return { ok: false, reason: "decode_failed" };
  }
}

export function saveKeypair(
  account: string,
  kp: { pubkeyB64?: string; secretKeyB64: string },
): KeypairB64 {
  const normalized = normalizeAccount(account);
  if (!normalized) throw new Error("account_required");

  const secretKeyB64 = String(kp.secretKeyB64 || "").trim();
  if (!secretKeyB64) throw new Error("secret_key_required");

  const pubkeyB64 =
    String(kp.pubkeyB64 || "").trim() || derivePublicKeyFromSecretKey(secretKeyB64);

  const valid = validateKeypair(pubkeyB64, secretKeyB64);
  if (!valid.ok) throw new Error(`invalid_keypair:${valid.reason || "unknown"}`);

  const legacyStored: StoredKeypair = {
    version: 2,
    publicKey: pubkeyB64,
    secretKey: secretKeyB64,
    pubkeyB64,
    secretKeyB64,
    hasSecret: true,
  };

  const secureMeta: StoredKeypair = {
    version: 2,
    publicKey: pubkeyB64,
    pubkeyB64,
    hasSecret: false,
  };

  localStorage.setItem(`${KEYRING_PREFIX}${normalized}`, JSON.stringify(legacyStored));
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

  const legacy = readStoredKeypair(localStorage.getItem(`${KEYRING_PREFIX}${normalized}`));
  const meta = readStoredKeypair(localStorage.getItem(keyStorageKey(normalized)));

  const storedPub =
    String(
      legacy?.pubkeyB64 ||
        legacy?.publicKey ||
        meta?.pubkeyB64 ||
        meta?.publicKey ||
        "",
    ).trim();

  const legacySecret = String(legacy?.secretKeyB64 || legacy?.secretKey || "").trim();
  if (legacySecret) {
    const pubkeyB64 = storedPub || derivePublicKeyFromSecretKey(legacySecret);
    const valid = validateKeypair(pubkeyB64, legacySecret);
    if (!valid.ok) return null;

    sessionStorage.setItem(secretStorageKey(normalized), legacySecret);
    localStorage.setItem(
      keyStorageKey(normalized),
      JSON.stringify({
        version: 2,
        publicKey: pubkeyB64,
        pubkeyB64,
        hasSecret: false,
      } satisfies StoredKeypair),
    );

    return { pubkeyB64, secretKeyB64: legacySecret };
  }

  const sessionSecret = String(sessionStorage.getItem(secretStorageKey(normalized)) || "").trim();
  if (!sessionSecret) return null;

  const pubkeyB64 = storedPub || derivePublicKeyFromSecretKey(sessionSecret);
  const valid = validateKeypair(pubkeyB64, sessionSecret);
  if (!valid.ok) return null;

  return { pubkeyB64, secretKeyB64: sessionSecret };
}

export function getKeypair(account: string): KeypairB64 | null {
  return loadKeypair(account);
}

export function deleteKeypair(account: string): void {
  const normalized = normalizeAccount(account);
  if (!normalized) return;
  localStorage.removeItem(`${KEYRING_PREFIX}${normalized}`);
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

export function signDetachedB64(secretKeyB64: string, msgBytes: Uint8Array): string {
  const sec = b64ToBytes(secretKeyB64);
  if (sec.length !== SECRET_KEY_BYTES) {
    throw new Error("invalid_secret_key");
  }
  const sig = nacl.sign.detached(msgBytes, sec);
  return bytesToB64(sig);
}

export function canonicalTxMessage(env: {
  chain_id: string;
  tx_type: string;
  signer: string;
  nonce: number;
  payload: any;
  parent: string | null;
}): Uint8Array {
  const chain_id = String(env.chain_id || "").trim();
  const tx_type = String(env.tx_type || "");
  const signer = String(env.signer || "");
  const nonce = Math.floor(Number(env.nonce || 0));
  const payload = env.payload && typeof env.payload === "object" ? env.payload : {};
  const parent = env.parent == null ? null : String(env.parent);

  const obj: Record<string, unknown> = {
    ...(chain_id ? { chain_id } : {}),
    tx_type,
    signer,
    nonce,
    payload,
    ...(parent != null ? { parent } : {}),
  };

  return utf8ToBytes(stableStringify(obj));
}
