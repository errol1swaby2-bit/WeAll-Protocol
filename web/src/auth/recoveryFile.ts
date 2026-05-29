import { derivePublicKeyFromSecretKey, normalizeAccount, validateKeypair } from "./keys";

export type RecoveryKeyFileV1 = {
  type: "weall_recovery_key";
  version: 1;
  account: string;
  publicKeyB64: string;
  secretKeyB64: string;
  createdAt: string;
  warning: string;
};

function safeFileAccount(account: string): string {
  return normalizeAccount(account).replace(/^@/, "").replace(/[^a-z0-9_]+/g, "_") || "account";
}

export function buildRecoveryKeyFile(args: {
  account: string;
  secretKeyB64: string;
  publicKeyB64?: string;
  createdAt?: Date;
}): RecoveryKeyFileV1 {
  const account = normalizeAccount(args.account);
  const secretKeyB64 = String(args.secretKeyB64 || "").trim();
  const publicKeyB64 = String(args.publicKeyB64 || "").trim() || derivePublicKeyFromSecretKey(secretKeyB64);
  const valid = validateKeypair(publicKeyB64, secretKeyB64);
  if (!account) throw new Error("account_required");
  if (!valid.ok) throw new Error(`invalid_recovery_key:${valid.reason || "unknown"}`);
  return {
    type: "weall_recovery_key",
    version: 1,
    account,
    publicKeyB64,
    secretKeyB64,
    createdAt: (args.createdAt || new Date()).toISOString(),
    warning: "Anyone with this file can restore this WeAll account key. Store it somewhere private.",
  };
}

export function recoveryFileName(account: string): string {
  return `weall-recovery-key-${safeFileAccount(account)}.json`;
}

export function recoveryFileText(file: RecoveryKeyFileV1): string {
  return `${JSON.stringify(file, null, 2)}\n`;
}

export function downloadRecoveryKeyFile(args: {
  account: string;
  secretKeyB64: string;
  publicKeyB64?: string;
}): RecoveryKeyFileV1 {
  const file = buildRecoveryKeyFile(args);
  const blob = new Blob([recoveryFileText(file)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = recoveryFileName(file.account);
  a.rel = "noopener";
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
  return file;
}

export function parseRecoveryKeyFileText(text: string): RecoveryKeyFileV1 {
  let parsed: any;
  try {
    parsed = JSON.parse(String(text || ""));
  } catch {
    throw new Error("invalid_recovery_file_json");
  }

  if (!parsed || typeof parsed !== "object") throw new Error("invalid_recovery_file");
  if (parsed.type !== "weall_recovery_key" || Number(parsed.version) !== 1) {
    throw new Error("unsupported_recovery_file");
  }

  const account = normalizeAccount(String(parsed.account || ""));
  const secretKeyB64 = String(parsed.secretKeyB64 || "").trim();
  const publicKeyB64 = String(parsed.publicKeyB64 || "").trim() || derivePublicKeyFromSecretKey(secretKeyB64);
  const valid = validateKeypair(publicKeyB64, secretKeyB64);
  if (!account) throw new Error("recovery_file_missing_account");
  if (!valid.ok) throw new Error(`invalid_recovery_key:${valid.reason || "unknown"}`);

  return {
    type: "weall_recovery_key",
    version: 1,
    account,
    publicKeyB64,
    secretKeyB64,
    createdAt: String(parsed.createdAt || new Date(0).toISOString()),
    warning: String(parsed.warning || "Anyone with this file can restore this WeAll account key. Store it somewhere private."),
  };
}

export async function readRecoveryKeyFile(file: File): Promise<RecoveryKeyFileV1> {
  if (!file) throw new Error("recovery_file_required");
  const text = await file.text();
  return parseRecoveryKeyFileText(text);
}

export function verifyRecoveryKeyFileForAccount(file: RecoveryKeyFileV1, expected: {
  account: string;
  publicKeyB64: string;
  secretKeyB64?: string;
}): { ok: true } | { ok: false; reason: string } {
  const account = normalizeAccount(expected.account);
  const publicKeyB64 = String(expected.publicKeyB64 || "").trim();
  const secretKeyB64 = String(expected.secretKeyB64 || "").trim();

  if (!file || file.type !== "weall_recovery_key" || file.version !== 1) {
    return { ok: false, reason: "invalid_recovery_file" };
  }
  if (!account || normalizeAccount(file.account) !== account) {
    return { ok: false, reason: "recovery_account_mismatch" };
  }
  if (!publicKeyB64 || String(file.publicKeyB64 || "").trim() !== publicKeyB64) {
    return { ok: false, reason: "recovery_public_key_mismatch" };
  }
  if (secretKeyB64 && String(file.secretKeyB64 || "").trim() !== secretKeyB64) {
    return { ok: false, reason: "recovery_secret_key_mismatch" };
  }

  const valid = validateKeypair(file.publicKeyB64, file.secretKeyB64);
  if (!valid.ok) return { ok: false, reason: valid.reason || "invalid_recovery_key" };
  return { ok: true };
}
