// web/src/lib/keys.ts
// Thin compatibility wrapper for older imports.
// The canonical implementation lives in web/src/auth/keys.ts.

import {
  generateKeypair,
  loadKeypair as _loadKeypair,
  saveKeypair as _saveKeypair,
  deleteKeypair as _deleteKeypair,
  signDetachedB64 as _signDetachedB64,
} from "../auth/keys";

export type { KeypairB64 as KeypairB64 } from "../auth/keys";

/**
 * Load the keypair for an account.
 *
 * Note: pubkey is persisted in localStorage, secret is session-only.
 */
export function loadKeypair(account: string): { pubkeyB64: string; secretKeyB64: string } | null {
  return _loadKeypair(account);
}

/**
 * Generate a fresh keypair and store it for the account.
 *
 * Returns the generated keypair.
 */
export async function saveKeypair(account: string): Promise<{ pubkeyB64: string; secretKeyB64: string }> {
  const kp = generateKeypair();
  _saveKeypair(account, kp);
  return kp;
}

/** Delete key material for an account (both pubkey + session secret). */
export function deleteKeypair(account: string): void {
  _deleteKeypair(account);
}

function utf8ToBytes(s: string): Uint8Array {
  return new TextEncoder().encode(String(s ?? ""));
}

/**
 * Sign a message and return base64 signature.
 *
 * Accepts either a UTF-8 string message or raw bytes.
 */
export function signDetachedB64(secretKeyB64: string, msg: string | Uint8Array): string {
  const msgBytes = typeof msg === "string" ? utf8ToBytes(msg) : msg;
  return _signDetachedB64(secretKeyB64, msgBytes);
}
