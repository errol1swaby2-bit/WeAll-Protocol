export type TxLifecycleStatus = "validating" | "submitting" | "recorded" | "refreshing" | "confirmed" | "failed";

export type FrontendErrorCategory =
  | "capability_blocked"
  | "structurally_unavailable"
  | "auth_session_expired"
  | "node_not_ready"
  | "recorded_not_yet_visible"
  | "object_missing"
  | "backend_failure"
  | "index_visibility_lag";

export type FrontendFeedback = {
  category: FrontendErrorCategory;
  title: string;
  message: string;
  details?: any;
  retryable: boolean;
  safeToRetry: boolean;
};

const CATEGORY_META: Record<FrontendErrorCategory, { label: string; title: string; retryable: boolean; safeToRetry: boolean }> = {
  capability_blocked: {
    label: "Capability blocked",
    title: "Action blocked",
    retryable: false,
    safeToRetry: false,
  },
  structurally_unavailable: {
    label: "Unavailable here",
    title: "Action unavailable",
    retryable: false,
    safeToRetry: false,
  },
  auth_session_expired: {
    label: "Session expired",
    title: "Session needs attention",
    retryable: true,
    safeToRetry: true,
  },
  node_not_ready: {
    label: "Node not ready",
    title: "Node is not ready",
    retryable: true,
    safeToRetry: true,
  },
  recorded_not_yet_visible: {
    label: "Recorded",
    title: "Recorded but not yet visible",
    retryable: false,
    safeToRetry: false,
  },
  object_missing: {
    label: "Missing",
    title: "Object unavailable",
    retryable: true,
    safeToRetry: true,
  },
  backend_failure: {
    label: "Backend failure",
    title: "Backend failure",
    retryable: true,
    safeToRetry: false,
  },
  index_visibility_lag: {
    label: "Visibility lag",
    title: "Index or visibility lag",
    retryable: true,
    safeToRetry: false,
  },
};

export function txStatusLabel(status: TxLifecycleStatus): string {
  switch (status) {
    case "validating":
      return "Validating";
    case "submitting":
      return "Submitting";
    case "recorded":
      return "Recorded";
    case "refreshing":
      return "Refreshing";
    case "confirmed":
      return "Confirmed";
    case "failed":
    default:
      return "Failed";
  }
}

function asString(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

function messageNeedle(error: unknown, payload: any): string {
  const raw = [
    asString((payload as any)?.message),
    asString((payload as any)?.error?.message),
    error instanceof Error ? asString(error.message) : "",
    asString((payload as any)?.detail),
  ]
    .filter(Boolean)
    .join(" ");
  return raw.toLowerCase();
}

function codeNeedle(payload: any): string {
  return [
    asString((payload as any)?.code),
    asString((payload as any)?.error?.code),
    asString((payload as any)?.detail?.code),
    asString((payload as any)?.status),
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
}

export function normalizeStoredTxStatus(value: unknown): TxLifecycleStatus {
  const raw = asString(value).toLowerCase();
  switch (raw) {
    case "preparing":
    case "validating":
      return "validating";
    case "submitted":
    case "submitting":
      return "submitting";
    case "recorded":
      return "recorded";
    case "refreshing":
      return "refreshing";
    case "confirmed":
      return "confirmed";
    case "error":
    case "failed":
      return "failed";
    case "unknown":
      return "recorded";
    default:
      return "failed";
  }
}

export function createFeedback(category: FrontendErrorCategory, message: string, details?: any, overrides?: Partial<Pick<FrontendFeedback, "retryable" | "safeToRetry" | "title">>): FrontendFeedback {
  const meta = CATEGORY_META[category];
  return {
    category,
    title: overrides?.title || meta.title,
    message,
    details,
    retryable: overrides?.retryable ?? meta.retryable,
    safeToRetry: overrides?.safeToRetry ?? meta.safeToRetry,
  };
}

export function feedbackBadgeLabel(category: FrontendErrorCategory): string {
  return CATEGORY_META[category].label;
}

export function inferFeedbackFromUnknown(error: unknown, fallback = "Something failed."): FrontendFeedback {
  const payload = (error as any)?.body || (error as any)?.data || (error as any)?.payload || error;
  const code = codeNeedle(payload);
  const needle = messageNeedle(error, payload);
  const rawMessage =
    asString((payload as any)?.message) ||
    asString((payload as any)?.error?.message) ||
    (error instanceof Error ? asString(error.message) : "") ||
    fallback;

  if (
    code.includes("gate") ||
    needle.includes("not eligible") ||
    needle.includes("requires tier") ||
    needle.includes("capability") ||
    needle.includes("gated")
  ) {
    return createFeedback("capability_blocked", rawMessage, payload, { retryable: false, safeToRetry: false });
  }

  if (
    needle.includes("not available on this page") ||
    needle.includes("not allowed in this state") ||
    needle.includes("not permitted for this object")
  ) {
    return createFeedback("structurally_unavailable", rawMessage, payload, { retryable: false, safeToRetry: false });
  }

  if (
    code.includes("session") ||
    code.includes("auth") ||
    needle.includes("login") ||
    needle.includes("session expired") ||
    needle.includes("revoked") ||
    needle.includes("unauthorized")
  ) {
    return createFeedback("auth_session_expired", rawMessage, payload, { retryable: true, safeToRetry: true });
  }

  if (
    code.includes("ready") ||
    code.includes("unavailable") ||
    needle.includes("not ready") ||
    needle.includes("backend unavailable") ||
    needle.includes("service unavailable")
  ) {
    return createFeedback("node_not_ready", rawMessage, payload, { retryable: true, safeToRetry: true });
  }

  if (needle.includes("not yet visible") || needle.includes("recorded") || needle.includes("check the affected object")) {
    return createFeedback("recorded_not_yet_visible", rawMessage, payload, { retryable: false, safeToRetry: false });
  }

  if (
    code.includes("not_found") ||
    needle.includes("not found") ||
    needle.includes("no longer exists") ||
    needle.includes("missing")
  ) {
    return createFeedback("object_missing", rawMessage, payload, { retryable: true, safeToRetry: true });
  }

  if (needle.includes("index") || needle.includes("lag") || needle.includes("visibility")) {
    return createFeedback("index_visibility_lag", rawMessage, payload, { retryable: true, safeToRetry: false });
  }

  return createFeedback("backend_failure", rawMessage || fallback, payload, { retryable: true, safeToRetry: false });
}
