import {
  BROWSER_PQ_SIG_PROFILE,
  derivePublicKeyFromSecretKey,
  MLDSA65_SECRET_KEY_FORMAT,
  normalizeAccount,
  validateKeypair,
} from "./keys";
import { validateEvidenceKemKeypair } from "./evidenceCrypto";

export type RecoveryKeyFileV2 = {
  type: "weall_recovery_key";
  version: 2;
  sigProfile: "pq-mldsa-v1";
  algorithm: "ML-DSA";
  parameterSet: "ML-DSA-65";
  secretKeyFormat: "mldsa65-seed-b64";
  account: string;
  publicKeyB64: string;
  secretKeyB64: string;
  recoveryAuthorityPublicKeyB64?: string;
  recoveryAuthoritySecretKeyB64?: string;
  evidenceKemPublicKeyB64?: string;
  evidenceKemSecretKeyB64?: string;
  createdAt: string;
  warning: string;
};

export type RecoveryKeyFile = RecoveryKeyFileV2;

function safeFileAccount(account: string): string {
  return normalizeAccount(account).replace(/^@/, "").replace(/[^a-z0-9_]+/g, "_") || "account";
}

function warningText(): string {
  return "Anyone with this file can restore this WeAll account key. It contains the active ML-DSA-65 signing seed plus any included recovery/evidence secrets; store it somewhere private.";
}

function validateAuxiliaryRecoveryMaterial(value: {
  recoveryAuthorityPublicKeyB64?: string;
  recoveryAuthoritySecretKeyB64?: string;
  evidenceKemPublicKeyB64?: string;
  evidenceKemSecretKeyB64?: string;
}): void {
  const recoveryPublic = String(value.recoveryAuthorityPublicKeyB64 || "").trim();
  const recoverySecret = String(value.recoveryAuthoritySecretKeyB64 || "").trim();
  if (Boolean(recoveryPublic) !== Boolean(recoverySecret)) throw new Error("incomplete_recovery_authority_keypair");
  if (recoveryPublic && recoverySecret) {
    const valid = validateKeypair(recoveryPublic, recoverySecret);
    if (!valid.ok) throw new Error(`invalid_recovery_authority:${valid.reason || "unknown"}`);
  }

  const kemPublic = String(value.evidenceKemPublicKeyB64 || "").trim();
  const kemSecret = String(value.evidenceKemSecretKeyB64 || "").trim();
  if (Boolean(kemPublic) !== Boolean(kemSecret)) throw new Error("incomplete_evidence_kem_keypair");
  if (kemPublic && kemSecret) {
    const valid = validateEvidenceKemKeypair({ publicKeyB64: kemPublic, secretKeyB64: kemSecret });
    if (!valid.ok) throw new Error(valid.reason);
  }
}

export function buildRecoveryKeyFile(args: {
  account: string;
  secretKeyB64: string;
  publicKeyB64?: string;
  recoveryAuthorityPublicKeyB64?: string;
  recoveryAuthoritySecretKeyB64?: string;
  evidenceKemPublicKeyB64?: string;
  evidenceKemSecretKeyB64?: string;
  createdAt?: Date;
}): RecoveryKeyFileV2 {
  const account = normalizeAccount(args.account);
  const secretKeyB64 = String(args.secretKeyB64 || "").trim();
  const publicKeyB64 = String(args.publicKeyB64 || "").trim() || derivePublicKeyFromSecretKey(secretKeyB64);
  const valid = validateKeypair(publicKeyB64, secretKeyB64);
  if (!account) throw new Error("account_required");
  if (!valid.ok) throw new Error(`invalid_recovery_key:${valid.reason || "unknown"}`);
  validateAuxiliaryRecoveryMaterial(args);
  return {
    type: "weall_recovery_key",
    version: 2,
    sigProfile: BROWSER_PQ_SIG_PROFILE,
    algorithm: "ML-DSA",
    parameterSet: "ML-DSA-65",
    secretKeyFormat: MLDSA65_SECRET_KEY_FORMAT,
    account,
    publicKeyB64,
    secretKeyB64,
    recoveryAuthorityPublicKeyB64: String(args.recoveryAuthorityPublicKeyB64 || "").trim() || undefined,
    recoveryAuthoritySecretKeyB64: String(args.recoveryAuthoritySecretKeyB64 || "").trim() || undefined,
    evidenceKemPublicKeyB64: String(args.evidenceKemPublicKeyB64 || "").trim() || undefined,
    evidenceKemSecretKeyB64: String(args.evidenceKemSecretKeyB64 || "").trim() || undefined,
    createdAt: (args.createdAt || new Date()).toISOString(),
    warning: warningText(),
  };
}

export function recoveryFileName(account: string): string {
  return `weall-recovery-key-${safeFileAccount(account)}.json`;
}

export function recoveryFileText(file: RecoveryKeyFileV2): string {
  return `${JSON.stringify(file, null, 2)}\n`;
}

export function downloadRecoveryKeyFile(args: {
  account: string;
  secretKeyB64: string;
  publicKeyB64?: string;
  recoveryAuthorityPublicKeyB64?: string;
  recoveryAuthoritySecretKeyB64?: string;
  evidenceKemPublicKeyB64?: string;
  evidenceKemSecretKeyB64?: string;
}): RecoveryKeyFileV2 {
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

function validateRecoveryEnvelope(parsed: any): void {
  if (parsed.type !== "weall_recovery_key" || Number(parsed.version) !== 2) {
    throw new Error("unsupported_recovery_file");
  }
  if (String(parsed.sigProfile || "") !== BROWSER_PQ_SIG_PROFILE) {
    throw new Error("unsupported_recovery_sig_profile");
  }
  if (String(parsed.algorithm || "") !== "ML-DSA" || String(parsed.parameterSet || "") !== "ML-DSA-65") {
    throw new Error("unsupported_recovery_algorithm");
  }
  if (String(parsed.secretKeyFormat || "") !== MLDSA65_SECRET_KEY_FORMAT) {
    throw new Error("unsupported_recovery_secret_key_format");
  }
}

export function parseRecoveryKeyFileText(text: string): RecoveryKeyFileV2 {
  let parsed: any;
  try {
    parsed = JSON.parse(String(text || ""));
  } catch {
    throw new Error("invalid_recovery_file_json");
  }

  if (!parsed || typeof parsed !== "object") throw new Error("invalid_recovery_file");
  validateRecoveryEnvelope(parsed);

  const account = normalizeAccount(String(parsed.account || ""));
  const secretKeyB64 = String(parsed.secretKeyB64 || "").trim();
  const publicKeyB64 = String(parsed.publicKeyB64 || "").trim() || derivePublicKeyFromSecretKey(secretKeyB64);
  const valid = validateKeypair(publicKeyB64, secretKeyB64);
  if (!account) throw new Error("recovery_file_missing_account");
  if (!valid.ok) throw new Error(`invalid_recovery_key:${valid.reason || "unknown"}`);
  validateAuxiliaryRecoveryMaterial(parsed);

  return {
    type: "weall_recovery_key",
    version: 2,
    sigProfile: BROWSER_PQ_SIG_PROFILE,
    algorithm: "ML-DSA",
    parameterSet: "ML-DSA-65",
    secretKeyFormat: MLDSA65_SECRET_KEY_FORMAT,
    account,
    publicKeyB64,
    secretKeyB64,
    recoveryAuthorityPublicKeyB64: String(parsed.recoveryAuthorityPublicKeyB64 || "").trim() || undefined,
    recoveryAuthoritySecretKeyB64: String(parsed.recoveryAuthoritySecretKeyB64 || "").trim() || undefined,
    evidenceKemPublicKeyB64: String(parsed.evidenceKemPublicKeyB64 || "").trim() || undefined,
    evidenceKemSecretKeyB64: String(parsed.evidenceKemSecretKeyB64 || "").trim() || undefined,
    createdAt: String(parsed.createdAt || new Date(0).toISOString()),
    warning: String(parsed.warning || warningText()),
  };
}

export async function readRecoveryKeyFile(file: File): Promise<RecoveryKeyFileV2> {
  if (!file) throw new Error("recovery_file_required");
  const text = await file.text();
  return parseRecoveryKeyFileText(text);
}

export function verifyRecoveryKeyFileForAccount(file: RecoveryKeyFileV2, expected: {
  account: string;
  publicKeyB64: string;
  secretKeyB64?: string;
}): { ok: true } | { ok: false; reason: string } {
  const account = normalizeAccount(expected.account);
  const publicKeyB64 = String(expected.publicKeyB64 || "").trim();
  const secretKeyB64 = String(expected.secretKeyB64 || "").trim();

  if (
    !file
    || file.type !== "weall_recovery_key"
    || file.version !== 2
    || file.sigProfile !== BROWSER_PQ_SIG_PROFILE
    || file.secretKeyFormat !== MLDSA65_SECRET_KEY_FORMAT
  ) {
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
  try {
    validateAuxiliaryRecoveryMaterial(file);
  } catch (error) {
    return { ok: false, reason: String((error as Error)?.message || error || "invalid_auxiliary_recovery_material") };
  }
  return { ok: true };
}
