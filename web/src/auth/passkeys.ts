import { normalizeAccount } from "./keys";

export type EasySignInRecord = {
  version: 1;
  account: string;
  credentialId: string;
  label: string;
  createdAt: string;
};

const PASSKEY_PREFIX = "weall_easy_signin::";
const PASSKEY_INDEX = "weall_easy_signin_index_v1";

function bytesToB64url(bytes: Uint8Array): string {
  let binary = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}


function b64urlToBytes(value: string): Uint8Array {
  const normalized = String(value || "").replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4 || 4)) % 4);
  const binary = atob(padded);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

function randomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

function bytesToArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

function storageKey(credentialId: string): string {
  return `${PASSKEY_PREFIX}${credentialId}`;
}

function readIndex(): string[] {
  try {
    const parsed = JSON.parse(localStorage.getItem(PASSKEY_INDEX) || "[]");
    if (!Array.isArray(parsed)) return [];
    return parsed.map((item) => String(item || "").trim()).filter(Boolean);
  } catch {
    return [];
  }
}

function writeIndex(ids: string[]): void {
  const unique = Array.from(new Set(ids.map((id) => String(id || "").trim()).filter(Boolean))).sort();
  localStorage.setItem(PASSKEY_INDEX, JSON.stringify(unique));
}

export function passkeysAvailable(): boolean {
  return typeof window !== "undefined" && typeof navigator !== "undefined" && !!navigator.credentials && typeof PublicKeyCredential !== "undefined";
}

export function listEasySignInRecords(): EasySignInRecord[] {
  const out: EasySignInRecord[] = [];
  for (const id of readIndex()) {
    try {
      const parsed = JSON.parse(localStorage.getItem(storageKey(id)) || "null") as EasySignInRecord | null;
      if (!parsed || parsed.version !== 1 || !parsed.account || !parsed.credentialId) continue;
      out.push(parsed);
    } catch {
      // ignore malformed local metadata
    }
  }
  return out.sort((a, b) => a.account.localeCompare(b.account) || a.createdAt.localeCompare(b.createdAt));
}

export function getEasySignInForAccount(account: string): EasySignInRecord | null {
  const acct = normalizeAccount(account);
  if (!acct) return null;
  return listEasySignInRecords().find((record) => record.account === acct) || null;
}

export async function registerEasySignIn(args: { account: string; displayName?: string }): Promise<EasySignInRecord> {
  const account = normalizeAccount(args.account);
  if (!account) throw new Error("account_required");
  if (!passkeysAvailable()) throw new Error("passkeys_not_available");

  const challenge = bytesToArrayBuffer(randomBytes(32));
  const userId = bytesToArrayBuffer(new TextEncoder().encode(account));
  const credential = (await navigator.credentials.create({
    publicKey: {
      challenge,
      rp: { name: "WeAll" },
      user: {
        id: userId,
        name: account,
        displayName: args.displayName || account,
      },
      pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
      authenticatorSelection: {
        residentKey: "preferred",
        userVerification: "preferred",
      },
      timeout: 60000,
      attestation: "none",
    },
  })) as PublicKeyCredential | null;

  if (!credential?.rawId) throw new Error("passkey_registration_cancelled");
  const credentialId = bytesToB64url(new Uint8Array(credential.rawId));
  const record: EasySignInRecord = {
    version: 1,
    account,
    credentialId,
    label: "Easy sign-in passkey",
    createdAt: new Date().toISOString(),
  };
  localStorage.setItem(storageKey(credentialId), JSON.stringify(record));
  writeIndex([...readIndex(), credentialId]);
  return record;
}

export async function confirmEasySignIn(record?: EasySignInRecord | null): Promise<EasySignInRecord> {
  if (!passkeysAvailable()) throw new Error("passkeys_not_available");
  const selected = record || listEasySignInRecords()[0] || null;
  if (!selected) throw new Error("no_easy_signin_saved");

  const challenge = bytesToArrayBuffer(randomBytes(32));
  const credential = (await navigator.credentials.get({
    publicKey: {
      challenge,
      allowCredentials: [{ id: bytesToArrayBuffer(b64urlToBytes(selected.credentialId)), type: "public-key" }],
      userVerification: "preferred",
      timeout: 60000,
    },
  })) as PublicKeyCredential | null;
  if (!credential?.rawId) throw new Error("passkey_signin_cancelled");
  const returned = bytesToB64url(new Uint8Array(credential.rawId));
  if (returned !== selected.credentialId) throw new Error("passkey_account_mismatch");
  return selected;
}

export function forgetEasySignIn(credentialId: string): void {
  const id = String(credentialId || "").trim();
  if (!id) return;
  localStorage.removeItem(storageKey(id));
  writeIndex(readIndex().filter((stored) => stored !== id));
}
