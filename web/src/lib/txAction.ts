import { createFeedback, type FrontendErrorCategory } from "./txFeedback";

export type ActionableTxError = {
  msg: string;
  details: any;
  category: FrontendErrorCategory;
  retryable: boolean;
  safeToRetry: boolean;
  title: string;
};

function pickPayload(error: any): any {
  return error?.body || error?.data || error?.payload || error;
}

function codeOf(payload: any): string {
  return String(payload?.error?.code || payload?.code || payload?.detail?.code || "").trim().toLowerCase();
}

function firstNonEmpty(values: any[]): string {
  for (const value of values) {
    const s = String(value || "").trim();
    if (s) return s;
  }
  return "";
}

function messageOf(error: any, payload: any): string {
  const detail = payload?.error?.details && typeof payload.error.details === "object" ? payload.error.details : {};
  const nested = detail?.details && typeof detail.details === "object" ? detail.details : {};
  const gateMeta = detail?.gate_meta && typeof detail.gate_meta === "object" ? detail.gate_meta : {};
  const parts = [
    payload?.message,
    payload?.error?.message,
    detail?.reason,
    detail?.error,
    detail?.code,
    nested?.reason,
    nested?.error,
    nested?.code,
    gateMeta?.error,
    gateMeta?.reason,
    error?.message,
  ];
  const primary = firstNonEmpty(parts);
  if (!primary) return "error";
  const code = firstNonEmpty([payload?.error?.code, payload?.code, detail?.code, nested?.code]);
  if (code && !primary.toLowerCase().includes(String(code).toLowerCase())) {
    return `${primary} (${code})`;
  }
  return primary;
}


export function txPendingKey(parts: Array<string | number | null | undefined>): string {
  return parts
    .map((part) => String(part ?? "").trim())
    .filter(Boolean)
    .join(":");
}

export function actionableTxError(error: any, fallback = "Transaction failed."): ActionableTxError {
  const details = pickPayload(error);
  const code = codeOf(details);
  const rawMessage = messageOf(error, details);
  const msgNeedle = rawMessage.toLowerCase();

  if (code === "duplicate_submission_blocked" || msgNeedle.includes("already submitting")) {
    const feedback = createFeedback(
      "recorded_not_yet_visible",
      "That exact action is already being submitted. Wait for the existing attempt to settle before clicking again.",
      details,
      {
        title: "Action already in flight",
        retryable: false,
        safeToRetry: false,
      },
    );
    return { msg: feedback.message, details: feedback.details, category: feedback.category, retryable: feedback.retryable, safeToRetry: feedback.safeToRetry, title: feedback.title };
  }

  if (
    ["bad_nonce", "mempool_signer_nonce_conflict", "tx_id_conflict", "nonce_retry_exhausted"].includes(code) ||
    msgNeedle.includes("nonce") ||
    msgNeedle.includes("already used") ||
    msgNeedle.includes("stale")
  ) {
    const feedback = createFeedback(
      "recorded_not_yet_visible",
      "Another signed action is still settling or this page was slightly behind chain nonce state. Refresh the affected object, wait a moment, and try again.",
      details,
      {
        title: "Signed action still settling",
        retryable: true,
        safeToRetry: true,
      },
    );
    return { msg: feedback.message, details: feedback.details, category: feedback.category, retryable: feedback.retryable, safeToRetry: feedback.safeToRetry, title: feedback.title };
  }

  if (code === "signer_submission_busy" || msgNeedle.includes("still settling")) {
    const feedback = createFeedback(
      "recorded_not_yet_visible",
      "This account already has a signed action in flight. Let that action settle before submitting the next one.",
      details,
      {
        title: "Signer is busy",
        retryable: false,
        safeToRetry: false,
      },
    );
    return { msg: feedback.message, details: feedback.details, category: feedback.category, retryable: feedback.retryable, safeToRetry: feedback.safeToRetry, title: feedback.title };
  }

  if (msgNeedle.includes("gated") || code.includes("gate")) {
    const feedback = createFeedback("capability_blocked", rawMessage || fallback, details, {
      retryable: false,
      safeToRetry: false,
      title: "Capability requirement not met",
    });
    return { msg: feedback.message, details: feedback.details, category: feedback.category, retryable: feedback.retryable, safeToRetry: feedback.safeToRetry, title: feedback.title };
  }

  if (code.includes("session") || msgNeedle.includes("session") || msgNeedle.includes("unauthorized")) {
    const feedback = createFeedback("auth_session_expired", rawMessage || fallback, details, {
      retryable: true,
      safeToRetry: true,
    });
    return { msg: feedback.message, details: feedback.details, category: feedback.category, retryable: feedback.retryable, safeToRetry: feedback.safeToRetry, title: feedback.title };
  }

  if (msgNeedle.includes("not ready") || code.includes("ready")) {
    const feedback = createFeedback("node_not_ready", rawMessage || fallback, details, {
      retryable: true,
      safeToRetry: true,
    });
    return { msg: feedback.message, details: feedback.details, category: feedback.category, retryable: feedback.retryable, safeToRetry: feedback.safeToRetry, title: feedback.title };
  }

  const feedback = createFeedback("backend_failure", rawMessage || fallback, details, {
    retryable: true,
    safeToRetry: false,
  });
  return { msg: feedback.message, details: feedback.details, category: feedback.category, retryable: feedback.retryable, safeToRetry: feedback.safeToRetry, title: feedback.title };
}
