export const PRIVATE_MESSAGING_UNSUPPORTED = "PRIVATE_MESSAGING_UNSUPPORTED";

export type MessagingEncryptionIdentity = never;
export type EncryptedDirectMessagePayload = never;
export type MessagingDeviceRecord = never;
export type MessagingIdentityBackup = never;
export type TrustedPeerRecord = never;

function unsupported(): never {
  throw new Error(PRIVATE_MESSAGING_UNSUPPORTED);
}

export async function messagingEncryptionKeyId(): Promise<string> { unsupported(); }
export function readMessagingEncryptionIdentity(): null { return null; }
export async function ensureMessagingEncryptionIdentity(): Promise<MessagingEncryptionIdentity> { unsupported(); }
export async function messagingDeviceRecord(): Promise<MessagingDeviceRecord | null> { return null; }
export function listLocalMessagingDevices(): MessagingDeviceRecord[] { return []; }
export function revokeLocalMessagingDevice(): void { /* no-op: unsupported */ }
export async function exportMessagingIdentityBackup(): Promise<MessagingIdentityBackup> { unsupported(); }
export async function importMessagingIdentityBackup(): Promise<MessagingEncryptionIdentity> { unsupported(); }
export function forgetTrustedMessagingPeer(): void { /* no-op: unsupported */ }
export function verifyMessagingPeerFingerprint(): boolean { return false; }
export function messagingEncryptionFingerprint(): string { return ""; }
export function sameMessagingPublicJwk(): boolean { return false; }
export function readTrustedMessagingPeer(): TrustedPeerRecord | null { return null; }
export function trustMessagingPeerKey(): TrustedPeerRecord { unsupported(); }
export function messagingPeerTrustState(): { state: "unsupported"; label: string; ok: false } {
  return { state: "unsupported", label: PRIVATE_MESSAGING_UNSUPPORTED, ok: false };
}
export function accountMessagingPublicJwk(): null { return null; }
export function accountMessagingKeyId(): string { return ""; }
export async function encryptDirectMessage(): Promise<EncryptedDirectMessagePayload> { unsupported(); }
export async function decryptDirectMessage(): Promise<string> { unsupported(); }
