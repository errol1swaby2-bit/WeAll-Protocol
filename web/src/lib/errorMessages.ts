export type PlainErrorCode =
  | "needs_verification"
  | "needs_responsibility"
  | "not_assigned"
  | "decision_closed"
  | "already_recorded"
  | "needs_refresh"
  | "session_needs_attention"
  | "service_unavailable"
  | "not_found"
  | "account_restricted"
  | "action_unavailable"
  | "could_not_complete";

export type PlainError = {
  code: PlainErrorCode;
  title: string;
  message: string;
  technicalMessage?: string;
};

function asString(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

function compact(values: unknown[]): string[] {
  return values.map(asString).filter(Boolean);
}

function pickPayload(error: unknown): any {
  return (error as any)?.body || (error as any)?.data || (error as any)?.payload || error;
}

export function backendCodeOf(value: unknown): string {
  const payload = pickPayload(value);
  return compact([
    (payload as any)?.error?.code,
    (payload as any)?.code,
    (payload as any)?.detail?.code,
    (payload as any)?.details?.code,
    (payload as any)?.status,
    (value as any)?.code,
  ])
    .join(" ")
    .toLowerCase();
}

export function backendMessageOf(error: unknown): string {
  const payload = pickPayload(error);
  const detail = (payload as any)?.error?.details && typeof (payload as any).error.details === "object" ? (payload as any).error.details : {};
  const nested = detail?.details && typeof detail.details === "object" ? detail.details : {};
  const gateMeta = detail?.gate_meta && typeof detail.gate_meta === "object" ? detail.gate_meta : {};
  return compact([
    (payload as any)?.message,
    (payload as any)?.error?.message,
    (payload as any)?.detail?.message,
    (payload as any)?.detail,
    detail?.reason,
    detail?.error,
    detail?.code,
    nested?.reason,
    nested?.error,
    nested?.code,
    gateMeta?.reason,
    gateMeta?.error,
    (error as any)?.message,
  ]).join(" ");
}

function includesAny(needle: string, words: string[]): boolean {
  return words.some((word) => needle.includes(word));
}

export function sanitizeUserFacingMessage(message: string): string {
  const raw = String(message || "").trim();
  if (!raw) return "This action could not be completed.";

  const lower = raw.toLowerCase();
  if (includesAny(lower, ["bad_nonce", "nonce", "mempool", "tx_id", "tx id", "transaction id", "invalid tx", "canonical", "schema"])) {
    return "Something changed. Refresh and try again.";
  }
  if (includesAny(lower, ["tier3", "tier 3", "tier2", "tier 2", "tier1", "tier 1", "tier0", "tier 0", "poh", "requires tier", "insufficient tier"])) {
    if (includesAny(lower, ["tier2", "tier 2", "tier3", "tier 3"])) return "Complete live verification to use this action.";
    return "Complete account verification to use this action.";
  }
  if (includesAny(lower, ["juror", "not assigned", "missing role", "role gate"])) {
    return lower.includes("not assigned") ? "You were not selected to review this item." : "You need the required trusted responsibility before using this action.";
  }
  if (includesAny(lower, ["cloud" + "flare", "sm" + "tp", "d" + "ns verification", "or" + "acle", "captcha", "oauth", "kyc"])) {
    return "This verification path is not available in the normal app.";
  }
  return raw;
}

export function translateBackendError(error: unknown, fallback = "This action could not be completed."): PlainError {
  const code = backendCodeOf(error);
  const rawMessage = backendMessageOf(error) || fallback;
  const needle = `${code} ${rawMessage}`.toLowerCase();
  const technicalMessage = rawMessage && rawMessage !== fallback ? rawMessage : undefined;


  if (includesAny(needle, ["non_public_group_unsupported", "opaque_protocol_payload_unsupported", "protocol_read_visibility_must_be_public", "public_read_visibility_required"])) {
    return {
      code: "action_unavailable",
      title: "Public-only protocol rule",
      message: "WeAll protocol content is publicly inspectable. Restricted-read groups and non-inspectable protocol payloads are not supported.",
      technicalMessage,
    };
  }

  if (includesAny(needle, ["rate_limited", "too many requests", "429"])) {
    return {
      code: "rate_limited",
      title: "Node is catching up",
      message: "The local node is receiving actions too quickly. Wait a moment for the current action to settle before trying again.",
      technicalMessage,
    };
  }


  if (includesAny(needle, ["duplicate_submission_blocked", "already submitting", "signer_submission_busy", "signed action", "busy"])) {
    return {
      code: "already_recorded",
      title: "Action already in progress",
      message: "That action is already being saved. Let it finish before clicking again.",
      technicalMessage,
    };
  }

  if (includesAny(needle, ["bad_nonce", "nonce_retry_exhausted", "nonce", "stale", "already used", "tx_id_conflict", "mempool_signer_nonce_conflict"])) {
    return {
      code: "needs_refresh",
      title: "Refresh and try again",
      message: "Something changed. Refresh and try again.",
      technicalMessage,
    };
  }

  if (includesAny(needle, ["not assigned", "not selected"])) {
    return {
      code: "not_assigned",
      title: "Not selected for this review",
      message: "You were not selected to review this item.",
      technicalMessage,
    };
  }

  if (includesAny(needle, ["missing juror", "juror role", "reviewer role", "community reviewer", "missing role", "required role", "role gate"])) {
    return {
      code: "needs_responsibility",
      title: "Trusted responsibility required",
      message: "You need the required trusted responsibility before using this action.",
      technicalMessage,
    };
  }

  if (includesAny(needle, ["requires tier2", "requires tier 2", "tier2", "tier 2", "requires tier3", "requires tier 3", "tier3", "tier 3"])) {
    return {
      code: "needs_verification",
      title: "Live verification required",
      message: "Complete live verification to use this action.",
      technicalMessage,
    };
  }

  if (includesAny(needle, ["requires tier", "insufficient tier", "not eligible", "poh", "gated", "capability", "verification required"])) {
    return {
      code: "needs_verification",
      title: "Account verification required",
      message: "Complete account verification to use this action.",
      technicalMessage,
    };
  }

  if (includesAny(needle, ["duplicate vote", "already voted", "vote already", "already recorded"])) {
    return {
      code: "already_recorded",
      title: "Already recorded",
      message: "Your vote has already been recorded.",
      technicalMessage,
    };
  }

  if (includesAny(needle, ["closed proposal", "proposal closed", "decision closed", "not open", "voting closed", "closed decision"])) {
    return {
      code: "decision_closed",
      title: "Decision closed",
      message: "This decision is no longer open.",
      technicalMessage,
    };
  }

  if (includesAny(needle, ["session_invalid", "session expired", "session", "unauthorized", "forbidden", "pubkey_not_authorized", "active key", "local signer", "device signer", "login"])) {
    return {
      code: "session_needs_attention",
      title: "Session needs attention",
      message: "Your session needs attention. Sign in again or refresh your device session.",
      technicalMessage,
    };
  }

  if (includesAny(needle, ["banned", "suspended", "locked", "account restricted", "account locked"])) {
    return {
      code: "account_restricted",
      title: "Account restricted",
      message: "This account is restricted. Resolve the account issue before continuing.",
      technicalMessage,
    };
  }

  if (includesAny(needle, ["not found", "404", "missing", "no longer exists"])) {
    return {
      code: "not_found",
      title: "Item unavailable",
      message: "This item is no longer available or has not loaded yet.",
      technicalMessage,
    };
  }

  if (includesAny(needle, ["not ready", "service unavailable", "backend unavailable", "fetch failed", "network", "timeout", "connection"])) {
    return {
      code: "service_unavailable",
      title: "Service needs a moment",
      message: "WeAll is having trouble reaching the node. Refresh and try again.",
      technicalMessage,
    };
  }

  return {
    code: "could_not_complete",
    title: "Action could not be completed",
    message: sanitizeUserFacingMessage(rawMessage || fallback),
    technicalMessage,
  };
}
