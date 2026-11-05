import { weall } from "../api/weall";
import { ensureRecoveryAuthorityKeypair, normalizeAccount } from "../auth/keys";
import { ensureEvidenceKemKeypair } from "../auth/evidenceCrypto";
import { getKeypair, submitSignedTxWithNonce } from "../auth/session";
import {
  fetchAccountRegistrationWorkPolicy,
  solveAccountRegistrationWork,
} from "./accountRegistrationWork";

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
    if (pubkey && pubkey !== keypair.pubkeyB64) return "key_mismatch";
    const nonce = Number(state.nonce || 0);
    if (pubkey && nonce > 0) return "registered";
    if (nonce === 0 && !pubkey) return "not_registered";
    return "unavailable";
  } catch {
    // A failed read is not permission to submit a second registration.
    return "unavailable";
  }
}

export async function submitBasicAccountRegistration(account: string, base: string, onBeforeSubmit?: () => void): Promise<string> {
  const acct = normalizeAccount(account);
  const keypair = acct ? getKeypair(acct) : null;
  if (!acct || !keypair?.secretKeyB64 || !keypair.pubkeyB64) {
    throw new Error("Restore your local account key before registering.");
  }
  const recovery = ensureRecoveryAuthorityKeypair(acct);
  const evidence = ensureEvidenceKemKeypair(acct);
  const policyResponse = await fetchAccountRegistrationWorkPolicy(base);
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
    onBeforeSubmit,
  });
  const txId = String(submitted?.result?.tx_id || submitted?.result?.result?.tx_id || "").trim();
  if (!txId) throw new Error("Registration was submitted but no transaction ID was returned. Check your account before retrying.");
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
