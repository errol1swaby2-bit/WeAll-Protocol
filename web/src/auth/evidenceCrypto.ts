import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";

export const EVIDENCE_KEM_ALGORITHM = "ml-kem-768";
export const EVIDENCE_CONTENT_ALGORITHM = "aes-256-gcm";
export const MLKEM768_PUBLIC_KEY_BYTES = 1184;

export type EvidenceKemKeypair = {
  publicKeyB64: string;
  secretKeyB64: string;
};

export type EncryptedEvidence = {
  file: File;
  contentKey: Uint8Array;
  ciphertextCommitment: string;
  encryptionContextCommitment: string;
};

export type EvidenceKeyEnvelope = {
  algorithm: "ml-kem-768+aes-256-gcm";
  kemCiphertextB64: string;
  nonceB64: string;
  wrappedKeyB64: string;
  contextCommitment: string;
  envelopeCommitment: string;
};

const encoder = new TextEncoder();

function bytesToB64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(binary);
}

function b64ToBytes(value: string): Uint8Array {
  const normalized = String(value || "").trim().replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}

async function sha256Commitment(bytes: Uint8Array): Promise<string> {
  const digest = await sha256(bytes);
  return `sha256:${Array.from(digest).map((value) => value.toString(16).padStart(2, "0")).join("")}`;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function kemSecretStorageKey(account: string): string {
  return `weall_evidence_kem_secret::${String(account || "").trim().toLowerCase()}`;
}

function kemPublicStorageKey(account: string): string {
  return `weall_evidence_kem_public::${String(account || "").trim().toLowerCase()}`;
}

export function generateEvidenceKemKeypair(): EvidenceKemKeypair {
  const pair = ml_kem768.keygen();
  if (pair.publicKey.length !== MLKEM768_PUBLIC_KEY_BYTES) throw new Error("invalid_mlkem768_public_key");
  return { publicKeyB64: bytesToB64(pair.publicKey), secretKeyB64: bytesToB64(pair.secretKey) };
}

export function validateEvidenceKemKeypair(pair: EvidenceKemKeypair): { ok: true } | { ok: false; reason: string } {
  try {
    const publicKey = b64ToBytes(pair.publicKeyB64);
    const secretKey = b64ToBytes(pair.secretKeyB64);
    if (publicKey.length !== MLKEM768_PUBLIC_KEY_BYTES) return { ok: false, reason: "invalid_mlkem768_public_key" };
    if (secretKey.length === 0) return { ok: false, reason: "invalid_mlkem768_secret_key" };
    const encapsulated = ml_kem768.encapsulate(publicKey);
    const decapsulated = ml_kem768.decapsulate(encapsulated.cipherText, secretKey);
    if (decapsulated.length !== encapsulated.sharedSecret.length) return { ok: false, reason: "mlkem_keypair_mismatch" };
    for (let index = 0; index < decapsulated.length; index += 1) {
      if (decapsulated[index] !== encapsulated.sharedSecret[index]) return { ok: false, reason: "mlkem_keypair_mismatch" };
    }
    return { ok: true };
  } catch {
    return { ok: false, reason: "invalid_mlkem768_keypair" };
  }
}

export function saveEvidenceKemKeypair(account: string, pair: EvidenceKemKeypair): void {
  const valid = validateEvidenceKemKeypair(pair);
  if (!valid.ok) throw new Error(valid.reason);
  // Public metadata may persist. The decapsulation secret remains session-only
  // and is exported only through the user-controlled recovery file.
  localStorage.setItem(kemPublicStorageKey(account), pair.publicKeyB64);
  sessionStorage.setItem(kemSecretStorageKey(account), pair.secretKeyB64);
}

export function loadEvidenceKemKeypair(account: string): EvidenceKemKeypair | null {
  const publicKeyB64 = String(localStorage.getItem(kemPublicStorageKey(account)) || "").trim();
  const secretKeyB64 = String(sessionStorage.getItem(kemSecretStorageKey(account)) || "").trim();
  if (!publicKeyB64 || !secretKeyB64) return null;
  try {
    if (b64ToBytes(publicKeyB64).length !== MLKEM768_PUBLIC_KEY_BYTES) return null;
  } catch {
    return null;
  }
  return { publicKeyB64, secretKeyB64 };
}

export function ensureEvidenceKemKeypair(account: string): EvidenceKemKeypair {
  const existing = loadEvidenceKemKeypair(account);
  if (existing) return existing;
  const generated = generateEvidenceKemKeypair();
  saveEvidenceKemKeypair(account, generated);
  return generated;
}

export async function encryptEvidenceBlob(args: {
  blob: Blob;
  filename: string;
  context: string;
}): Promise<EncryptedEvidence> {
  const contentKey = crypto.getRandomValues(new Uint8Array(32));
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const contextBytes = encoder.encode(args.context);
  const key = await crypto.subtle.importKey("raw", contentKey, "AES-GCM", false, ["encrypt"]);
  const plaintext = new Uint8Array(await args.blob.arrayBuffer());
  const encrypted = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: contextBytes }, key, plaintext),
  );
  const envelope = concat(encoder.encode("WEALL_POH_EVIDENCE_V1\0"), nonce, encrypted);
  return {
    file: new File([envelope], args.filename.replace(/\.[^.]+$/, "") + ".weall-evidence", {
      type: "application/octet-stream",
    }),
    contentKey,
    ciphertextCommitment: await sha256Commitment(envelope),
    encryptionContextCommitment: await sha256Commitment(contextBytes),
  };
}

export async function wrapEvidenceKeyForRecipient(args: {
  contentKey: Uint8Array;
  recipientPublicKeyB64: string;
  context: string;
}): Promise<EvidenceKeyEnvelope> {
  const recipientPublicKey = b64ToBytes(args.recipientPublicKeyB64);
  if (recipientPublicKey.length !== MLKEM768_PUBLIC_KEY_BYTES) throw new Error("invalid_recipient_mlkem_key");
  const encapsulated = ml_kem768.encapsulate(recipientPublicKey);
  const contextBytes = encoder.encode(args.context);
  const wrappingMaterial = await sha256(concat(encapsulated.sharedSecret, contextBytes));
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const wrappingKey = await crypto.subtle.importKey("raw", wrappingMaterial, "AES-GCM", false, ["encrypt"]);
  const wrappedKey = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: contextBytes }, wrappingKey, args.contentKey),
  );
  const commitmentBytes = concat(encapsulated.cipherText, nonce, wrappedKey, contextBytes);
  return {
    algorithm: "ml-kem-768+aes-256-gcm",
    kemCiphertextB64: bytesToB64(encapsulated.cipherText),
    nonceB64: bytesToB64(nonce),
    wrappedKeyB64: bytesToB64(wrappedKey),
    contextCommitment: await sha256Commitment(contextBytes),
    envelopeCommitment: await sha256Commitment(commitmentBytes),
  };
}

function envelopeField(envelope: Record<string, unknown>, camel: string, snake: string): string {
  return String(envelope[camel] ?? envelope[snake] ?? "").trim();
}

export async function unwrapEvidenceKeyForRecipient(args: {
  envelope: EvidenceKeyEnvelope | Record<string, unknown>;
  recipientSecretKeyB64: string;
  context: string;
}): Promise<Uint8Array> {
  const envelope = args.envelope as Record<string, unknown>;
  const algorithm = String(envelope.algorithm || "").trim().toLowerCase();
  if (algorithm !== "ml-kem-768+aes-256-gcm") throw new Error("unsupported_evidence_key_envelope");

  const kemCiphertext = b64ToBytes(envelopeField(envelope, "kemCiphertextB64", "kem_ciphertext_b64"));
  const nonce = b64ToBytes(envelopeField(envelope, "nonceB64", "nonce_b64"));
  const wrappedKey = b64ToBytes(envelopeField(envelope, "wrappedKeyB64", "wrapped_key_b64"));
  const recipientSecretKey = b64ToBytes(args.recipientSecretKeyB64);
  const contextBytes = encoder.encode(args.context);

  if (nonce.length !== 12) throw new Error("invalid_evidence_key_envelope_nonce");
  const expectedContextCommitment = envelopeField(envelope, "contextCommitment", "context_commitment");
  if (!expectedContextCommitment || (await sha256Commitment(contextBytes)) !== expectedContextCommitment) {
    throw new Error("evidence_key_envelope_context_mismatch");
  }

  const expectedEnvelopeCommitment = envelopeField(envelope, "envelopeCommitment", "envelope_commitment");
  const actualEnvelopeCommitment = await sha256Commitment(concat(kemCiphertext, nonce, wrappedKey, contextBytes));
  if (!expectedEnvelopeCommitment || actualEnvelopeCommitment !== expectedEnvelopeCommitment) {
    throw new Error("evidence_key_envelope_commitment_mismatch");
  }

  const sharedSecret = ml_kem768.decapsulate(kemCiphertext, recipientSecretKey);
  const wrappingMaterial = await sha256(concat(sharedSecret, contextBytes));
  const wrappingKey = await crypto.subtle.importKey("raw", wrappingMaterial, "AES-GCM", false, ["decrypt"]);
  let plaintext: ArrayBuffer;
  try {
    plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: nonce, additionalData: contextBytes },
      wrappingKey,
      wrappedKey,
    );
  } catch {
    throw new Error("evidence_key_unwrap_failed");
  }
  const contentKey = new Uint8Array(plaintext);
  if (contentKey.length !== 32) throw new Error("invalid_evidence_content_key");
  return contentKey;
}

export async function decryptEvidenceCiphertext(args: {
  ciphertext: ArrayBuffer | Uint8Array;
  contentKey: Uint8Array;
  context: string;
  expectedCiphertextCommitment?: string;
  mimeType?: string;
}): Promise<Blob> {
  if (args.contentKey.length !== 32) throw new Error("invalid_evidence_content_key");
  const ciphertext = args.ciphertext instanceof Uint8Array ? args.ciphertext : new Uint8Array(args.ciphertext);
  const expectedCommitment = String(args.expectedCiphertextCommitment || "").trim();
  if (expectedCommitment && (await sha256Commitment(ciphertext)) !== expectedCommitment) {
    throw new Error("evidence_ciphertext_commitment_mismatch");
  }

  const prefix = encoder.encode("WEALL_POH_EVIDENCE_V1\0");
  if (ciphertext.length <= prefix.length + 12) throw new Error("invalid_evidence_ciphertext");
  for (let i = 0; i < prefix.length; i += 1) {
    if (ciphertext[i] !== prefix[i]) throw new Error("invalid_evidence_ciphertext_version");
  }

  const nonce = ciphertext.slice(prefix.length, prefix.length + 12);
  const encrypted = ciphertext.slice(prefix.length + 12);
  const contextBytes = encoder.encode(args.context);
  const key = await crypto.subtle.importKey("raw", args.contentKey, "AES-GCM", false, ["decrypt"]);
  let plaintext: ArrayBuffer;
  try {
    plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: nonce, additionalData: contextBytes },
      key,
      encrypted,
    );
  } catch {
    throw new Error("evidence_ciphertext_decryption_failed");
  }
  return new Blob([plaintext], { type: String(args.mimeType || "video/webm").trim() || "video/webm" });
}
