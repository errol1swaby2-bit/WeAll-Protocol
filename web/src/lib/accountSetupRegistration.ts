import { weall } from "../api/weall";
import { canonicalMldsa65PublicKeyHex, ensureRecoveryAuthorityKeypair, normalizeAccount } from "../auth/keys";
import { ensureEvidenceKemKeypair } from "../auth/evidenceCrypto";
import { getKeypair, submitSignedTxWithNonce, type TxEnvelope } from "../auth/session";
import {
  fetchAccountRegistrationWorkPolicy,
  solveAccountRegistrationWork,
} from "./accountRegistrationWork";

/**
 * Mirrors runtime/tx_id.py: signature-independent tx identity over a sorted,
 * UTF-8 canonical JSON envelope with system=false and optional parent.
 * Only use for the ACCOUNT_REGISTER envelope prepared by this frontend.
 * The backend-returned ID is checked against this prediction when available.
 */
function canonicalRegistrationValue(value: unknown): unknown {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("invalid_registration_identity_number");
    return value;
  }
  if (Array.isArray(value)) return value.map(canonicalRegistrationValue);
  if (value && typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const normalized: Record<string, unknown> = {};
    for (const key of Object.keys(obj).sort()) {
      if (obj[key] === undefined) throw new Error("invalid_registration_identity_undefined");
      normalized[key] = canonicalRegistrationValue(obj[key]);
    }
    return normalized;
  }
  throw new Error("invalid_registration_identity_value");
}

export async function canonicalRegistrationTxId(envelope: TxEnvelope): Promise<string> {
  const chainId = String(envelope.chain_id || "").trim();
  const signer = String(envelope.signer || "").trim();
  const nonce = Number(envelope.nonce);
  if (!chainId || !signer || envelope.tx_type !== "ACCOUNT_REGISTER" || !Number.isSafeInteger(nonce) || nonce <= 0) {
    throw new Error("invalid_registration_identity_envelope");
  }
  const canonical = canonicalRegistrationValue({
    chain_id: chainId,
    tx_type: "ACCOUNT_REGISTER",
    signer,
    nonce,
    payload: envelope.payload,
    system: false,
    ...(envelope.parent == null ? {} : { parent: envelope.parent }),
  });
  if (!globalThis.crypto?.subtle) throw new Error("secure_crypto_unavailable");
  const bytes = new TextEncoder().encode(JSON.stringify(canonical));
  const digest = await globalThis.crypto.subtle.digest("SHA-256", bytes);
  return "tx:" + Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export type RegistrationStatus = "registered" | "not_registered" | "key_mismatch" | "unavailable";

/** Confirm both on-chain presence and the browser signer's bound public key. */
export async function readAccountRegistrationStatus(account: string, base: string): Promise<RegistrationStatus> {
  const acct = normalizeAccount(account);
  const keypair = acct ? getKeypair(acct) : null;
  if (!acct || !keypair?.pubkeyB64) return "unavailable";

  // /v1/accounts/{account}/registered is a Tier-2 *posting eligibility*
  // predicate, not a basic-account existence check. Read the actual account
  // state and verify its bound public key instead.
  try {
    const view = await weall.account(acct, base);
    const state = view?.account?.state ?? view?.state ?? null;
    if (!state || typeof state !== "object") return "unavailable";
    const pubkey = String(state.pubkey || "").trim();
    if (pubkey && canonicalMldsa65PublicKeyHex(pubkey) !== canonicalMldsa65PublicKeyHex(keypair.pubkeyB64)) return "key_mismatch";
    const nonce = Number(state.nonce || 0);
    if (pubkey && nonce > 0) return "registered";
    if (nonce === 0 && !pubkey) return "not_registered";
    return "unavailable";
  } catch {
    // A failed read is not permission to submit a second registration.
    return "unavailable";
  }
}

export async function submitBasicAccountRegistration(account: string, base: string, onBeforeSubmit?: (txId: string) => void): Promise<string> {
  const acct = normalizeAccount(account);
  const keypair = acct ? getKeypair(acct) : null;
  if (!acct || !keypair?.secretKeyB64 || !keypair.pubkeyB64) {
    throw new Error("Restore your local account key before registering.");
  }
  const recovery = ensureRecoveryAuthorityKeypair(acct);
  const evidence = ensureEvidenceKemKeypair(acct);
  const policyResponse = await fetchAccountRegistrationWorkPolicy(base);
  let predictedTxId = "";
  const submitted = await submitSignedTxWithNonce({
    account: acct,
    tx_type: "ACCOUNT_REGISTER",
    payloadFactory: async (nonce) => {
      const payload = {
        pubkey: keypair.pubkeyB64,
        recovery_pubkey: recovery.pubkeyB64,
        recovery_sig_profile: "pq-mldsa-v1",
        evidence_kem_pubkey: evidence.publicKeyB64,
        evidence_kem_algorithm: "ml-kem-768",
      };
      const work = await solveAccountRegistrationWork({
        policyResponse,
        signer: acct,
        txNonce: nonce,
        sigProfile: "pq-mldsa-v1",
        parent: null,
        payload,
      });
      return { ...payload, ...work };
    },
    parent: null,
    base,
    onBeforeSubmit: async (signed) => {
      predictedTxId = await canonicalRegistrationTxId(signed);
      onBeforeSubmit?.(predictedTxId);
    },
  });
  const txId = String(submitted?.result?.tx_id || submitted?.result?.result?.tx_id || "").trim();
  if (!txId) throw new Error("Registration may have been submitted without an acknowledgement. Reconcile the tracked transaction before retrying.");
  if (txId !== predictedTxId) throw new Error("Node returned a transaction ID inconsistent with the signed registration. Do not retry automatically.");
  return txId;
}

export type RegistrationFinality = "confirmed" | "pending" | "rejected" | "unavailable";

export async function readRegistrationFinality(txId: string, base: string): Promise<RegistrationFinality> {
  if (!String(txId || "").trim()) return "unavailable";
  try {
    const result = await weall.txStatus(txId, base);
    const status = String(result?.status || "").toLowerCase();
    const outbound = result?.outbound_propagation;
    const queueSynced = outbound?.local_state_synced;
    if (status === "confirmed" && result?.local_state_synced === true && queueSynced !== false) {
      return "confirmed";
    }
    if (["rejected", "failed", "invalid", "expired"].includes(status)) return "rejected";
    return "pending";
  } catch {
    return "unavailable";
  }
}
