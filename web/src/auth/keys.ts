// web/src/auth/keys.ts
import nacl from "tweetnacl";

/**
 * Keys + signing helpers for WeAll.
 *
 * Design goals:
 * - No fragile crypto deps (use tweetnacl only)
 * - Deterministic message serialization matching backend (canonical_tx_message)
 * - Storage baseline:
 *    - persist pubkey in localStorage
 *    - keep secret key out of localStorage (sessionStorage only)
 *    - legacy (v1) localStorage secrets auto-migrate to sessionStorage on load
 * - Production-grade user backup:
 *    - encrypted export/import using WebCrypto (PBKDF2 + AES-GCM)
 */

export type KeypairB64 = {
  pubkeyB64: string; // base64 of 32 bytes
  secretKeyB64: string; // base64 of 64 bytes
};

function b64Encode(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

function b64Decode(s: string): Uint8Array {
  const bin = atob(String(s || ""));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function abToB64(buf: ArrayBuffer): string {
  return b64Encode(new Uint8Array(buf));
}

function toArrayBuffer(u8: Uint8Array): ArrayBuffer {
  // Ensure a real ArrayBuffer (not SharedArrayBuffer / ArrayBufferLike) for WebCrypto typings.
  // Also ensures we respect byteOffset/byteLength.
  return u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength) as ArrayBuffer;
}

function toU8(u8: Uint8Array): Uint8Array {
  return new Uint8Array(toArrayBuffer(u8));
}

function b64ToAb(s: string): ArrayBuffer {
  const u = b64Decode(s);
  return toArrayBuffer(u);
}

function utf8ToBytes(s: string): Uint8Array {
  return new TextEncoder().encode(String(s ?? ""));
}

function bytesToUtf8(b: ArrayBuffer | Uint8Array): string {
  const u = b instanceof Uint8Array ? b : new Uint8Array(b);
  return new TextDecoder().decode(u);
}

function randomBytes(n: number): Uint8Array {
  const out = new Uint8Array(n);
  crypto.getRandomValues(out);
  return out;
}

export function normalizeAccount(s: string): string {
  const t = String(s || "").trim();
  if (!t) return "";
  if (t.startsWith("@")) return `@${t.replace(/^@+/, "")}`;
  return `@${t}`;
}

export function generateKeypair(): KeypairB64 {
  const kp = nacl.sign.keyPair();
  return {
    pubkeyB64: b64Encode(kp.publicKey),
    secretKeyB64: b64Encode(kp.secretKey),
  };
}

export function keyStorageKey(account: string): string {
  return `weall_keypair::${normalizeAccount(account)}`;
}

function secretStorageKey(account: string): string {
  return `weall_secret::${normalizeAccount(account)}`;
}

type StoredKeypair =
  | (KeypairB64 & { version?: number })
  | { version: 2; pubkeyB64: string; hasSecret: false };

export function saveKeypair(account: string, kp: KeypairB64): void {
  const k = keyStorageKey(account);
  // Security baseline: keep the secret out of persistent storage.
  // We persist only the pubkey; the secret stays in sessionStorage.
  const meta: StoredKeypair = { version: 2, pubkeyB64: kp.pubkeyB64, hasSecret: false };
  localStorage.setItem(k, JSON.stringify(meta));
  sessionStorage.setItem(secretStorageKey(account), kp.secretKeyB64);
}

export function loadKeypair(account: string): KeypairB64 | null {
  const k = keyStorageKey(account);
  const raw = localStorage.getItem(k);
  if (!raw) return null;
  try {
    const obj: StoredKeypair = JSON.parse(raw);
    if (!obj || typeof obj !== "object") return null;

    const pubkeyB64 = String((obj as any).pubkeyB64 || "");
    if (pubkeyB64.length < 10) return null;

    // Legacy (v1): secret was stored in localStorage. Migrate it to sessionStorage.
    const legacySecret = String((obj as any).secretKeyB64 || "");
    if (legacySecret.length >= 10) {
      sessionStorage.setItem(secretStorageKey(account), legacySecret);
      const meta: StoredKeypair = { version: 2, pubkeyB64, hasSecret: false };
      localStorage.setItem(k, JSON.stringify(meta));
      return { pubkeyB64, secretKeyB64: legacySecret };
    }

    // v2: secret is session-only.
    const secretKeyB64 = sessionStorage.getItem(secretStorageKey(account)) || "";
    if (secretKeyB64.length < 10) return null;
    return { pubkeyB64, secretKeyB64 };
  } catch {
    return null;
  }
}

export function deleteKeypair(account: string): void {
  const k = keyStorageKey(account);
  localStorage.removeItem(k);
  sessionStorage.removeItem(secretStorageKey(account));
}

export function hasSecretInSession(account: string): boolean {
  const s = sessionStorage.getItem(secretStorageKey(account)) || "";
  return s.length >= 10;
}

export function validateKeypair(pubkeyB64: string, secretKeyB64: string): { ok: boolean; reason?: string } {
  const pub = b64Decode(String(pubkeyB64 || ""));
  const sec = b64Decode(String(secretKeyB64 || ""));
  if (pub.length !== 32) return { ok: false, reason: "pubkey_len" };
  if (sec.length !== 64) return { ok: false, reason: "secret_len" };
  // tweetnacl secretKey last 32 bytes is publicKey
  for (let i = 0; i < 32; i++) {
    if (sec[32 + i] !== pub[i]) return { ok: false, reason: "pubkey_mismatch" };
  }
  return { ok: true };
}

export function signDetachedB64(secretKeyB64: string, msgBytes: Uint8Array): string {
  const sec = b64Decode(secretKeyB64);
  const sig = nacl.sign.detached(msgBytes, sec);
  return b64Encode(sig);
}

export function canonicalTxMessage(env: {
  chain_id: string;
  tx_type: string;
  signer: string;
  nonce: number;
  payload: any;
  parent: string | null;
}): Uint8Array {
  // IMPORTANT: must match backend canonical_tx_message() exactly.
  const obj = {
    chain_id: String(env.chain_id || ""),
    tx_type: String(env.tx_type || ""),
    signer: String(env.signer || ""),
    nonce: Number(env.nonce || 0),
    payload: env.payload ?? {},
    parent: env.parent == null ? null : String(env.parent),
  };
  const s = JSON.stringify(obj);
  return utf8ToBytes(s);
}

// --- Encrypted backup (PBKDF2 + AES-GCM) ---

export type EncryptedKeyBackupV1 = {
  version: 1;
  type: "weall_key_backup";
  created_ts_ms: number;

  account: string;
  pubkeyB64: string;

  kdf: {
    name: "PBKDF2";
    hash: "SHA-256";
    iterations: number;
    saltB64: string;
  };

  cipher: {
    name: "AES-GCM";
    ivB64: string;
  };

  ciphertextB64: string;
};

const PBKDF2_ITERS = 200_000;

async function deriveAesKeyFromPassphrase(passphrase: string, salt: Uint8Array, iterations: number): Promise<CryptoKey> {
  if (!crypto?.subtle) throw new Error("webcrypto_unavailable");

  const baseKey = await crypto.subtle.importKey(
    "raw",
    toArrayBuffer(utf8ToBytes(passphrase)),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt: toArrayBuffer(salt),
      iterations,
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

/**
 * Export an encrypted JSON backup for the currently-loaded account keypair.
 * The secret key is encrypted and never stored persistently by this function.
 */
export async function exportEncryptedKeyBackupJson(account: string, passphrase: string): Promise<string> {
  const acct = normalizeAccount(account);
  if (!acct) throw new Error("account_required");
  if (!passphrase || passphrase.trim().length < 12) throw new Error("passphrase_too_short");

  const kp = loadKeypair(acct);
  if (!kp?.secretKeyB64) throw new Error("no_secret_key_in_session");

  const valid = validateKeypair(kp.pubkeyB64, kp.secretKeyB64);
  if (!valid.ok) throw new Error(`invalid_keypair:${valid.reason}`);

  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = await deriveAesKeyFromPassphrase(passphrase, salt, PBKDF2_ITERS);

  // Encrypt the secret key (base64 string) as UTF-8.
  const plaintext = toU8(utf8ToBytes(kp.secretKeyB64));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv: toArrayBuffer(iv) }, key, toArrayBuffer(plaintext));

  const backup: EncryptedKeyBackupV1 = {
    version: 1,
    type: "weall_key_backup",
    created_ts_ms: Date.now(),

    account: acct,
    pubkeyB64: kp.pubkeyB64,

    kdf: {
      name: "PBKDF2",
      hash: "SHA-256",
      iterations: PBKDF2_ITERS,
      saltB64: b64Encode(salt),
    },

    cipher: {
      name: "AES-GCM",
      ivB64: b64Encode(iv),
    },

    ciphertextB64: abToB64(ct),
  };

  return JSON.stringify(backup, null, 2);
}

/**
 * Import an encrypted key backup JSON. Decrypts using passphrase, validates,
 * and writes it to current storage model (pubkey persisted, secret session-only).
 *
 * Returns the restored account.
 */
export async function importEncryptedKeyBackupJson(jsonText: string, passphrase: string): Promise<{ account: string; pubkeyB64: string }> {
  if (!passphrase || passphrase.trim().length < 12) throw new Error("passphrase_too_short");
  const raw = String(jsonText || "").trim();
  if (!raw) throw new Error("empty_backup_json");

  let obj: any;
  try {
    obj = JSON.parse(raw);
  } catch {
    throw new Error("invalid_backup_json");
  }

  if (!obj || typeof obj !== "object") throw new Error("invalid_backup_json");
  if (obj.version !== 1 || obj.type !== "weall_key_backup") throw new Error("unsupported_backup_format");

  const acct = normalizeAccount(String(obj.account || ""));
  const pubkeyB64 = String(obj.pubkeyB64 || "");
  if (!acct) throw new Error("backup_missing_account");
  if (!pubkeyB64) throw new Error("backup_missing_pubkey");

  const kdf = obj.kdf || {};
  const cipher = obj.cipher || {};

  if (kdf.name !== "PBKDF2" || kdf.hash !== "SHA-256") throw new Error("unsupported_kdf");
  const iterations = Number(kdf.iterations || 0);
  if (!Number.isFinite(iterations) || iterations < 50_000) throw new Error("kdf_iterations_too_low");

  const salt = b64Decode(String(kdf.saltB64 || ""));
  const iv = b64Decode(String(cipher.ivB64 || ""));
  if (salt.length < 8) throw new Error("invalid_salt");
  if (iv.length !== 12) throw new Error("invalid_iv");

  if (cipher.name !== "AES-GCM") throw new Error("unsupported_cipher");

  const ciphertext = b64ToAb(String(obj.ciphertextB64 || ""));
  if (!ciphertext || (ciphertext as ArrayBuffer).byteLength < 24) throw new Error("invalid_ciphertext");

  const key = await deriveAesKeyFromPassphrase(passphrase, salt, iterations);

  let secretKeyB64: string;
  try {
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: toArrayBuffer(iv) }, key, ciphertext);
    secretKeyB64 = bytesToUtf8(pt).trim();
  } catch {
    // Authentication failure should look like "wrong passphrase" to user.
    throw new Error("decrypt_failed_wrong_passphrase_or_corrupt_backup");
  }

  const valid = validateKeypair(pubkeyB64, secretKeyB64);
  if (!valid.ok) throw new Error(`invalid_keypair:${valid.reason}`);

  saveKeypair(acct, { pubkeyB64, secretKeyB64 });
  return { account: acct, pubkeyB64 };
}
