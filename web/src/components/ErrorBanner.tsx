import React from "react";

import { currentHashPath, navWithReturn } from "../lib/router";
import { feedbackBadgeLabel, inferFeedbackFromUnknown, type FrontendErrorCategory } from "../lib/txFeedback";

type Props = {
  message?: string | null;
  details?: any;
  onRetry?: (() => void) | null;
  onDismiss?: (() => void) | null;
  category?: FrontendErrorCategory;
  title?: string | null;
};

function normalizeCategory(category?: FrontendErrorCategory, message?: string | null, details?: any): ReturnType<typeof inferFeedbackFromUnknown> {
  if (category) {
    return {
      category,
      title: titleForCategory(category),
      message: message || "Something needs attention.",
      details,
      retryable: category !== "capability_blocked" && category !== "structurally_unavailable",
      safeToRetry: category === "auth_session_expired" || category === "node_not_ready" || category === "object_missing",
    };
  }
  return inferFeedbackFromUnknown({ message, payload: details }, message || "Something needs attention.");
}

function titleForCategory(category: FrontendErrorCategory): string {
  switch (category) {
    case "capability_blocked":
      return "Action blocked";
    case "structurally_unavailable":
      return "Action unavailable";
    case "auth_session_expired":
      return "Session needs attention";
    case "node_not_ready":
      return "Node is not ready";
    case "recorded_not_yet_visible":
      return "Recorded but not yet visible";
    case "object_missing":
      return "Object unavailable";
    case "index_visibility_lag":
      return "Index or visibility lag";
    case "backend_failure":
    default:
      return "Backend failure";
  }
}

function toneClass(category: FrontendErrorCategory): string {
  if (category === "recorded_not_yet_visible" || category === "index_visibility_lag") return "warn";
  if (category === "capability_blocked" || category === "structurally_unavailable") return "neutral";
  return "danger";
}

export default function ErrorBanner({ message, details, onRetry, onDismiss, category, title }: Props): JSX.Element | null {
  if (!message) return null;

  const normalized = normalizeCategory(category, message, details);
  const detailText = typeof details === "string" ? details : details ? JSON.stringify(details, null, 2) : "";
  const effectiveTitle = title || normalized.title;
  const allowRetry = !!onRetry && normalized.retryable;
  const tone = toneClass(normalized.category);
  const returnTo = currentHashPath();

  return (
    <div className={`card feedbackBanner feedbackBanner-${tone}`} data-feedback-category={normalized.category}>
      <div className="cardBody formStack">
        <div className="sectionHead feedbackBannerHead">
          <div>
            <div className="eyebrow">Something needs attention</div>
            <h2 className="cardTitle">{effectiveTitle}</h2>
          </div>
          <span className={`statusPill ${tone === "neutral" ? "" : tone === "warn" ? "warning" : "danger"}`.trim()}>
            {feedbackBadgeLabel(normalized.category)}
          </span>
        </div>

        <div className={`inlineMessage inlineMessage-${tone}`}>{normalized.message}</div>

        {detailText ? <pre className="codePanel mono">{detailText}</pre> : null}

        <div className="buttonRow">
          {allowRetry ? (
            <button className="btn btnPrimary" onClick={onRetry}>
              {normalized.safeToRetry ? "Retry" : "Reload and retry"}
            </button>
          ) : null}
          {normalized.category === "auth_session_expired" ? (
            <button className="btn" onClick={() => navWithReturn("/session", returnTo)}>
              Open session recovery
            </button>
          ) : null}
          {normalized.category === "recorded_not_yet_visible" ? (
            <button className="btn" onClick={() => navWithReturn("/transactions", returnTo)}>
              Open transaction queue
            </button>
          ) : null}
          {onDismiss ? (
            <button className="btn" onClick={onDismiss}>
              Dismiss
            </button>
          ) : null}
        </div>
      </div>
    </div>
  );
}
