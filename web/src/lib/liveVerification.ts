import { sha256HexText } from "./verificationEvidence";

export type LiveVerificationCommitments = {
  session_commitment: string;
  room_commitment: string;
  prompt_commitment: string;
  device_pairing_commitment?: string;
};

function cleanAccount(account: string): string {
  const a = String(account || "").trim();
  return a || "@unknown";
}

function randomNonce(): string {
  const cryptoObj = typeof crypto !== "undefined" ? crypto : undefined;
  const bytes = new Uint8Array(16);
  if (cryptoObj?.getRandomValues) {
    cryptoObj.getRandomValues(bytes);
    return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
  }
  return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`;
}

export async function createLiveVerificationCommitments(input: {
  account: string;
  pubkeyB64?: string;
  purpose?: string;
}): Promise<LiveVerificationCommitments> {
  const account = cleanAccount(input.account);
  const publicKey = String(input.pubkeyB64 || "").trim() || "unknown-public-key";
  const issuedAtMs = Date.now();
  const nonce = randomNonce();
  const purpose = String(input.purpose || "live_verification_request").trim() || "live_verification_request";
  const base = `weall-live-verification|v1|${purpose}|${account}|${publicKey}|${issuedAtMs}|${nonce}`;

  const session = await sha256HexText(`${base}|session`);
  const room = await sha256HexText(`${base}|room`);
  const prompt = await sha256HexText(`${base}|prompt`);
  const device = await sha256HexText(`${base}|device-pairing`);

  return {
    session_commitment: session,
    room_commitment: room,
    prompt_commitment: prompt,
    device_pairing_commitment: device,
  };
}

export function hasRequiredLiveVerificationCommitments(value: Partial<LiveVerificationCommitments> | null | undefined): boolean {
  return Boolean(
    String(value?.session_commitment || "").trim() &&
      String(value?.room_commitment || "").trim() &&
      String(value?.prompt_commitment || "").trim(),
  );
}
