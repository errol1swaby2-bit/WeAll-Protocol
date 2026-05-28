import { normalizeAccount } from "../auth/keys";

export const MESSAGE_E2EE_SCHEME = "WEALL_E2EE_V1";

export type MessagingEncryptionIdentity = {
  version: 1;
  account: string;
  publicJwk: JsonWebKey;
  privateJwk: JsonWebKey;
  keyId: string;
  createdAt: string;
};

export type EncryptedDirectMessagePayload = {
  to: string;
  encryption: typeof MESSAGE_E2EE_SCHEME;
  ciphertext_b64: string;
  iv_b64: string;
  aad_b64: string;
  sender_encryption_public_jwk: JsonWebKey;
  recipient_encryption_public_jwk: JsonWebKey;
  sender_encryption_key_id: string;
  recipient_encryption_key_id: string;
  thread_id?: string;
};

const STORAGE_PREFIX = "weall.messaging.e2ee.v1::";
const encoder = new TextEncoder();
const decoder = new TextDecoder();

function storageKey(account: string): string {
  return `${STORAGE_PREFIX}${normalizeAccount(account)}`;
}

function deviceStorageKey(account: string): string {
  return `${STORAGE_PREFIX}device::${normalizeAccount(account)}`;
}

function backupStorageKey(account: string): string {
  return `${STORAGE_PREFIX}backup::${normalizeAccount(account)}`;
}

function bytesToB64(bytes: Uint8Array): string {
  let binary = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

function b64ToBytes(value: string): Uint8Array {
  const raw = String(value || "").trim().replace(/\s+/g, "");
  const pad = raw.length % 4;
  const normalized = pad ? raw + "=".repeat(4 - pad) : raw;
  const binary = atob(normalized);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
  return out;
}

function canonicalJson(value: any): string {
  if (value === null || value === undefined) return "null";
  if (typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
}

async function sha256B64(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return bytesToB64(new Uint8Array(digest));
}

async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

export async function messagingEncryptionKeyId(publicJwk: JsonWebKey): Promise<string> {
  const digest = await sha256B64(canonicalJson({ crv: publicJwk.crv, kty: publicJwk.kty, x: publicJwk.x, y: publicJwk.y }));
  return `msgenc:${digest.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "").slice(0, 32)}`;
}

function validatePublicJwk(value: any): JsonWebKey | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const jwk = value as JsonWebKey;
  if (jwk.kty !== "EC" || jwk.crv !== "P-256" || !jwk.x || !jwk.y) return null;
  return { kty: "EC", crv: "P-256", x: String(jwk.x), y: String(jwk.y), ext: true };
}

export function readMessagingEncryptionIdentity(account: string): MessagingEncryptionIdentity | null {
  try {
    const parsed = JSON.parse(localStorage.getItem(storageKey(account)) || "null") as MessagingEncryptionIdentity | null;
    if (!parsed || parsed.version !== 1 || normalizeAccount(parsed.account) !== normalizeAccount(account)) return null;
    if (!validatePublicJwk(parsed.publicJwk)) return null;
    if (!parsed.privateJwk || typeof parsed.privateJwk !== "object") return null;
    if (!parsed.keyId) return null;
    return parsed;
  } catch {
    return null;
  }
}

async function generateIdentity(account: string): Promise<MessagingEncryptionIdentity> {
  const acct = normalizeAccount(account);
  if (!acct) throw new Error("account_required");
  const pair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveKey"]);
  const publicJwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
  const privateJwk = await crypto.subtle.exportKey("jwk", pair.privateKey);
  const safePublic = validatePublicJwk(publicJwk);
  if (!safePublic) throw new Error("messaging_encryption_key_generation_failed");
  const keyId = await messagingEncryptionKeyId(safePublic);
  const identity: MessagingEncryptionIdentity = {
    version: 1,
    account: acct,
    publicJwk: safePublic,
    privateJwk,
    keyId,
    createdAt: new Date().toISOString(),
  };
  localStorage.setItem(storageKey(acct), JSON.stringify(identity));
  return identity;
}

export async function ensureMessagingEncryptionIdentity(account: string): Promise<MessagingEncryptionIdentity> {
  const existing = readMessagingEncryptionIdentity(account);
  if (existing) return existing;
  return generateIdentity(account);
}

export type MessagingDeviceRecord = {
  version: 1;
  account: string;
  deviceId: string;
  keyId: string;
  fingerprint: string;
  createdAt: string;
  lastSeenAt: string;
  revoked?: boolean;
  revokedAt?: string;
};

export type MessagingIdentityBackup = {
  version: 1;
  account: string;
  keyId: string;
  fingerprint: string;
  kdf: "PBKDF2-SHA256";
  iterations: number;
  salt_b64: string;
  iv_b64: string;
  ciphertext_b64: string;
  createdAt: string;
};

function readDeviceRecord(account: string): MessagingDeviceRecord | null {
  try {
    const parsed = JSON.parse(localStorage.getItem(deviceStorageKey(account)) || "null") as MessagingDeviceRecord | null;
    if (!parsed || parsed.version !== 1) return null;
    if (normalizeAccount(parsed.account) !== normalizeAccount(account)) return null;
    return parsed;
  } catch {
    return null;
  }
}

export async function messagingDeviceRecord(account: string): Promise<MessagingDeviceRecord | null> {
  const identity = readMessagingEncryptionIdentity(account);
  if (!identity) return null;
  const existing = readDeviceRecord(account);
  const fingerprint = messagingEncryptionFingerprint(identity.publicJwk);
  if (existing && existing.keyId === identity.keyId && !existing.revoked) {
    const updated = { ...existing, fingerprint, lastSeenAt: new Date().toISOString() };
    localStorage.setItem(deviceStorageKey(account), JSON.stringify(updated));
    return updated;
  }
  const deviceHash = await sha256Hex(`${normalizeAccount(account)}|${identity.keyId}|${identity.createdAt}`);
  const rec: MessagingDeviceRecord = {
    version: 1,
    account: normalizeAccount(account),
    deviceId: `msgdev:${deviceHash.slice(0, 24)}`,
    keyId: identity.keyId,
    fingerprint,
    createdAt: existing?.createdAt || new Date().toISOString(),
    lastSeenAt: new Date().toISOString(),
  };
  localStorage.setItem(deviceStorageKey(account), JSON.stringify(rec));
  return rec;
}

export function listLocalMessagingDevices(account: string): MessagingDeviceRecord[] {
  const rec = readDeviceRecord(account);
  return rec ? [rec] : [];
}

export function revokeLocalMessagingDevice(account: string): void {
  const rec = readDeviceRecord(account);
  if (!rec) return;
  localStorage.setItem(deviceStorageKey(account), JSON.stringify({ ...rec, revoked: true, revokedAt: new Date().toISOString() }));
}

async function deriveBackupKey(passphrase: string, salt: Uint8Array): Promise<CryptoKey> {
  if (!String(passphrase || "").trim()) throw new Error("backup_passphrase_required");
  const material = await crypto.subtle.importKey("raw", encoder.encode(passphrase), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "PBKDF2", hash: "SHA-256", salt, iterations: 210000 }, material, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

export async function exportMessagingIdentityBackup(account: string, passphrase: string): Promise<MessagingIdentityBackup> {
  const identity = readMessagingEncryptionIdentity(account);
  if (!identity) throw new Error("messaging_identity_missing");
  const salt = new Uint8Array(16);
  const iv = new Uint8Array(12);
  crypto.getRandomValues(salt);
  crypto.getRandomValues(iv);
  const key = await deriveBackupKey(passphrase, salt);
  const plaintext = canonicalJson(identity);
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoder.encode(plaintext));
  const backup: MessagingIdentityBackup = {
    version: 1,
    account: normalizeAccount(account),
    keyId: identity.keyId,
    fingerprint: messagingEncryptionFingerprint(identity.publicJwk),
    kdf: "PBKDF2-SHA256",
    iterations: 210000,
    salt_b64: bytesToB64(salt),
    iv_b64: bytesToB64(iv),
    ciphertext_b64: bytesToB64(new Uint8Array(ciphertext)),
    createdAt: new Date().toISOString(),
  };
  localStorage.setItem(backupStorageKey(account), JSON.stringify({ ...backup, ciphertext_b64: "<redacted-local-export-only>" }));
  return backup;
}

export async function importMessagingIdentityBackup(account: string, passphrase: string, backup: MessagingIdentityBackup): Promise<MessagingEncryptionIdentity> {
  const acct = normalizeAccount(account);
  if (!acct) throw new Error("account_required");
  if (!backup || backup.version !== 1 || normalizeAccount(backup.account) !== acct) throw new Error("backup_account_mismatch");
  const key = await deriveBackupKey(passphrase, b64ToBytes(backup.salt_b64));
  const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64ToBytes(backup.iv_b64) }, key, b64ToBytes(backup.ciphertext_b64));
  const parsed = JSON.parse(decoder.decode(plaintext)) as MessagingEncryptionIdentity;
  if (!parsed || parsed.version !== 1 || normalizeAccount(parsed.account) !== acct || parsed.keyId !== backup.keyId || !validatePublicJwk(parsed.publicJwk)) throw new Error("invalid_messaging_identity_backup");
  localStorage.setItem(storageKey(acct), JSON.stringify(parsed));
  await messagingDeviceRecord(acct);
  return parsed;
}

export function forgetTrustedMessagingPeer(viewer: string, peer: string): void {
  localStorage.removeItem(peerTrustStorageKey(viewer, peer));
}

export function verifyMessagingPeerFingerprint(args: { viewer: string; peer: string; expectedFingerprint: string }): boolean {
  const trusted = readTrustedMessagingPeer(args.viewer, args.peer);
  return !!trusted && trusted.fingerprint === String(args.expectedFingerprint || "").trim();
}


export function messagingEncryptionFingerprint(publicJwk: JsonWebKey | null | undefined): string {
  const safe = validatePublicJwk(publicJwk);
  if (!safe) return "";
  const x = String(safe.x || "");
  const y = String(safe.y || "");
  return `P-256:${x.slice(0, 8)}…${x.slice(-6)}:${y.slice(0, 8)}…${y.slice(-6)}`;
}

export function sameMessagingPublicJwk(a: JsonWebKey | null | undefined, b: JsonWebKey | null | undefined): boolean {
  const aa = validatePublicJwk(a);
  const bb = validatePublicJwk(b);
  if (!aa || !bb) return false;
  return aa.kty === bb.kty && aa.crv === bb.crv && aa.x === bb.x && aa.y === bb.y;
}



type TrustedPeerRecord = {
  version: 1;
  viewer: string;
  peer: string;
  keyId: string;
  fingerprint: string;
  publicJwk: JsonWebKey;
  trustedAt: string;
};

function peerTrustStorageKey(viewer: string, peer: string): string {
  return `${STORAGE_PREFIX}trust::${normalizeAccount(viewer)}::${normalizeAccount(peer)}`;
}

export function readTrustedMessagingPeer(viewer: string, peer: string): TrustedPeerRecord | null {
  try {
    const raw = localStorage.getItem(peerTrustStorageKey(viewer, peer));
    const parsed = JSON.parse(raw || "null") as TrustedPeerRecord | null;
    if (!parsed || parsed.version !== 1) return null;
    if (normalizeAccount(parsed.viewer) !== normalizeAccount(viewer)) return null;
    if (normalizeAccount(parsed.peer) !== normalizeAccount(peer)) return null;
    if (!parsed.keyId || !validatePublicJwk(parsed.publicJwk)) return null;
    return parsed;
  } catch {
    return null;
  }
}

export function trustMessagingPeerKey(args: { viewer: string; peer: string; keyId: string; publicJwk: JsonWebKey }): TrustedPeerRecord {
  const publicJwk = validatePublicJwk(args.publicJwk);
  if (!publicJwk) throw new Error("invalid_peer_messaging_public_key");
  const rec: TrustedPeerRecord = {
    version: 1,
    viewer: normalizeAccount(args.viewer),
    peer: normalizeAccount(args.peer),
    keyId: String(args.keyId || "").trim(),
    fingerprint: messagingEncryptionFingerprint(publicJwk),
    publicJwk,
    trustedAt: new Date().toISOString(),
  };
  if (!rec.viewer || !rec.peer || !rec.keyId) throw new Error("missing_peer_trust_fields");
  localStorage.setItem(peerTrustStorageKey(rec.viewer, rec.peer), JSON.stringify(rec));
  return rec;
}

export function messagingPeerTrustState(args: { viewer: string; peer: string; keyId: string; publicJwk: JsonWebKey | null | undefined }): {
  status: "missing" | "untrusted" | "trusted" | "changed";
  fingerprint: string;
  trustedFingerprint: string;
  trustedKeyId: string;
} {
  const publicJwk = validatePublicJwk(args.publicJwk);
  if (!publicJwk || !String(args.keyId || "").trim()) {
    return { status: "missing", fingerprint: "", trustedFingerprint: "", trustedKeyId: "" };
  }
  const fingerprint = messagingEncryptionFingerprint(publicJwk);
  const trusted = readTrustedMessagingPeer(args.viewer, args.peer);
  if (!trusted) return { status: "untrusted", fingerprint, trustedFingerprint: "", trustedKeyId: "" };
  const keyId = String(args.keyId || "").trim();
  if (trusted.keyId !== keyId || !sameMessagingPublicJwk(trusted.publicJwk, publicJwk)) {
    return { status: "changed", fingerprint, trustedFingerprint: trusted.fingerprint, trustedKeyId: trusted.keyId };
  }
  return { status: "trusted", fingerprint, trustedFingerprint: trusted.fingerprint, trustedKeyId: trusted.keyId };
}

export function accountMessagingPublicJwk(accountState: any): JsonWebKey | null {
  const policy = accountState && typeof accountState === "object" ? accountState.security_policy : null;
  if (!policy || typeof policy !== "object") return null;
  return validatePublicJwk((policy as Record<string, any>).messaging_encryption_public_jwk);
}

export function accountMessagingKeyId(accountState: any): string {
  const policy = accountState && typeof accountState === "object" ? accountState.security_policy : null;
  if (!policy || typeof policy !== "object") return "";
  return String((policy as Record<string, any>).messaging_encryption_key_id || "").trim();
}

async function importPrivateKey(jwk: JsonWebKey): Promise<CryptoKey> {
  return crypto.subtle.importKey("jwk", jwk, { name: "ECDH", namedCurve: "P-256" }, false, ["deriveKey"]);
}

async function importPublicKey(jwk: JsonWebKey): Promise<CryptoKey> {
  const safe = validatePublicJwk(jwk);
  if (!safe) throw new Error("recipient_missing_messaging_encryption_key");
  return crypto.subtle.importKey("jwk", safe, { name: "ECDH", namedCurve: "P-256" }, false, []);
}

async function deriveAesKey(privateJwk: JsonWebKey, publicJwk: JsonWebKey): Promise<CryptoKey> {
  const privateKey = await importPrivateKey(privateJwk);
  const publicKey = await importPublicKey(publicJwk);
  return crypto.subtle.deriveKey({ name: "ECDH", public: publicKey }, privateKey, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

function aadText(args: { sender: string; recipient: string; senderKeyId: string; recipientKeyId: string }): string {
  return [MESSAGE_E2EE_SCHEME, normalizeAccount(args.sender), normalizeAccount(args.recipient), args.senderKeyId, args.recipientKeyId].join("|");
}

export async function encryptDirectMessage(args: {
  sender: string;
  recipient: string;
  plaintext: string;
  recipientPublicJwk: JsonWebKey;
  recipientKeyId?: string;
  threadId?: string;
}): Promise<EncryptedDirectMessagePayload> {
  const sender = normalizeAccount(args.sender);
  const recipient = normalizeAccount(args.recipient);
  const plaintext = String(args.plaintext || "");
  if (!sender || !recipient) throw new Error("message_sender_recipient_required");
  if (!plaintext.trim()) throw new Error("message_body_required");
  const identity = await ensureMessagingEncryptionIdentity(sender);
  const recipientPublicJwk = validatePublicJwk(args.recipientPublicJwk);
  if (!recipientPublicJwk) throw new Error("recipient_missing_messaging_encryption_key");
  const recipientKeyId = String(args.recipientKeyId || (await messagingEncryptionKeyId(recipientPublicJwk))).trim();
  const key = await deriveAesKey(identity.privateJwk, recipientPublicJwk);
  const iv = new Uint8Array(12);
  crypto.getRandomValues(iv);
  const aad = aadText({ sender, recipient, senderKeyId: identity.keyId, recipientKeyId });
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: encoder.encode(aad) }, key, encoder.encode(plaintext));
  return {
    to: recipient,
    encryption: MESSAGE_E2EE_SCHEME,
    ciphertext_b64: bytesToB64(new Uint8Array(ciphertext)),
    iv_b64: bytesToB64(iv),
    aad_b64: bytesToB64(encoder.encode(aad)),
    sender_encryption_public_jwk: identity.publicJwk,
    recipient_encryption_public_jwk: recipientPublicJwk,
    sender_encryption_key_id: identity.keyId,
    recipient_encryption_key_id: recipientKeyId,
    ...(args.threadId ? { thread_id: args.threadId } : {}),
  };
}

export async function decryptDirectMessage(args: {
  viewer: string;
  sender: string;
  recipient: string;
  encryption: any;
}): Promise<string> {
  const viewer = normalizeAccount(args.viewer);
  const sender = normalizeAccount(args.sender);
  const recipient = normalizeAccount(args.recipient);
  const envelope = args.encryption && typeof args.encryption === "object" ? args.encryption as Record<string, any> : {};
  if (envelope.scheme !== MESSAGE_E2EE_SCHEME) throw new Error("unsupported_message_encryption");
  const identity = await ensureMessagingEncryptionIdentity(viewer);
  const peerPublic = viewer === sender ? validatePublicJwk(envelope.recipient_encryption_public_jwk) : validatePublicJwk(envelope.sender_encryption_public_jwk);
  if (!peerPublic) throw new Error("message_missing_peer_public_key");
  const key = await deriveAesKey(identity.privateJwk, peerPublic);
  const iv = b64ToBytes(String(envelope.iv_b64 || ""));
  const ciphertext = b64ToBytes(String(envelope.ciphertext_b64 || ""));
  const senderKeyId = String(envelope.sender_encryption_key_id || "");
  const recipientKeyId = String(envelope.recipient_encryption_key_id || "");
  const aad = aadText({ sender, recipient, senderKeyId, recipientKeyId });
  const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv, additionalData: encoder.encode(aad) }, key, ciphertext);
  return decoder.decode(plaintext);
}
