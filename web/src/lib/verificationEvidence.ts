export const ASYNC_VIDEO_MIN_SECONDS = 60;
export const ASYNC_VIDEO_MAX_SECONDS = 120;

export type AsyncVerificationChallenge = {
  challengeId: string;
  phrase: string;
};

function cleanHandle(handle: string): string {
  const h = String(handle || "").trim();
  if (!h) return "@unknown";
  return h.startsWith("@") ? h : `@${h}`;
}

function randomToken(): string {
  const cryptoObj = typeof crypto !== "undefined" ? crypto : undefined;
  if (cryptoObj?.randomUUID) {
    return cryptoObj.randomUUID().replace(/-/g, "").slice(0, 12).toUpperCase();
  }
  const bytes = new Uint8Array(8);
  if (cryptoObj?.getRandomValues) {
    cryptoObj.getRandomValues(bytes);
    return Array.from(bytes)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("")
      .slice(0, 12)
      .toUpperCase();
  }
  return `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 8)}`.slice(0, 12).toUpperCase();
}

export function createAsyncVerificationChallenge(handle: string): AsyncVerificationChallenge {
  const token = randomToken();
  const challengeId = `async-${token}`;
  const phrase = `WeAll verification ${token}. My handle is ${cleanHandle(handle)}. I am recording this for async human review.`;
  return { challengeId, phrase };
}

export function validateAsyncVideoDuration(seconds: number): string | null {
  if (!Number.isFinite(seconds) || seconds <= 0) return "Record a fresh video before submitting account verification.";
  if (seconds < ASYNC_VIDEO_MIN_SECONDS) return "The verification video must be at least 1 minute long.";
  if (seconds > ASYNC_VIDEO_MAX_SECONDS) return "The verification video must be no more than 2 minutes long.";
  return null;
}

export function canSubmitAsyncEvidence(input: {
  recordedBlob?: Blob | null;
  durationSeconds: number;
  about: string;
  whyJoining: string;
  consent: boolean;
  challenge?: AsyncVerificationChallenge | null;
}): { ok: true } | { ok: false; reason: string } {
  if (!input.challenge?.phrase || !input.challenge?.challengeId) {
    return { ok: false, reason: "Start a fresh verification challenge before recording." };
  }
  if (!input.recordedBlob || input.recordedBlob.size <= 0) {
    return { ok: false, reason: "Record a fresh in-app video before submitting account verification." };
  }
  const durationError = validateAsyncVideoDuration(input.durationSeconds);
  if (durationError) return { ok: false, reason: durationError };
  if (input.about.trim().length < 10) {
    return { ok: false, reason: "Add a short natural statement about yourself before submitting." };
  }
  if (input.whyJoining.trim().length < 10) {
    return { ok: false, reason: "Explain why you are joining WeAll before submitting." };
  }
  if (!input.consent) {
    return { ok: false, reason: "Confirm that assigned reviewers may view this evidence for account verification." };
  }
  return { ok: true };
}

export async function sha256HexText(value: string): Promise<string> {
  const cryptoObj = typeof crypto !== "undefined" ? crypto : undefined;
  if (!cryptoObj?.subtle) {
    // Non-consensus browser fallback for old environments/tests. The protocol
    // still validates canonical commitments server-side where needed.
    const encoded = btoa(unescape(encodeURIComponent(value)));
    return `browser-fallback-${encoded}`.slice(0, 96);
  }
  const data = new TextEncoder().encode(value);
  const digest = await cryptoObj.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
