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

function readStoredIdentity(account: string): MessagingEncryptionIdentity | null {
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
  const existing = readStoredIdentity(account);
  if (existing) return existing;
  return generateIdentity(account);
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
