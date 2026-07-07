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
    const inferred = inferFeedbackFromUnknown({ message, payload: details }, message || "Something needs attention.");
    return {
      category,
      title: inferred.title,
      message: inferred.message,
      details,
      retryable: category !== "capability_blocked" && category !== "structurally_unavailable",
      safeToRetry: category === "auth_session_expired" || category === "node_not_ready" || category === "object_missing",
    };
  }
  return inferFeedbackFromUnknown({ message, payload: details }, message || "Something needs attention.");
}

function toneClass(category: FrontendErrorCategory): string {
  if (category === "recorded_not_yet_visible" || category === "index_visibility_lag") return "warn";
  if (category === "capability_blocked" || category === "structurally_unavailable") return "neutral";
  return "danger";
}

function detailsToText(details: any): string {
  if (!details) return "";
  if (typeof details === "string") return details;
  try {
    return JSON.stringify(details, null, 2);
  } catch {
    return String(details);
  }
}

export default function ErrorBanner({ message, details, onRetry, onDismiss, category, title }: Props): JSX.Element | null {
  if (!message) return null;

  const normalized = normalizeCategory(category, message, details);
  const detailText = detailsToText(details);
  const effectiveTitle = title || normalized.title;
  const allowRetry = !!onRetry && normalized.retryable;
  const tone = toneClass(normalized.category);
  const returnTo = currentHashPath();

  return (
    <div className={`card feedbackBanner feedbackBanner-${tone}`} role="alert" aria-live="assertive" data-feedback-category={normalized.category}>
      <div className="cardBody formStack">
        <div className="sectionHead feedbackBannerHead">
          <div>
            <div className="eyebrow">Needs attention</div>
            <h2 className="cardTitle">{effectiveTitle}</h2>
          </div>
          <span className={`statusPill ${tone === "neutral" ? "" : tone === "warn" ? "warning" : "danger"}`.trim()}>
            {feedbackBadgeLabel(normalized.category)}
          </span>
        </div>

        <div className={`inlineMessage inlineMessage-${tone}`}>{normalized.message}</div>

        {detailText ? (
          <details className="advancedDisclosure">
            <summary>View technical details</summary>
            <pre className="codePanel mono">{detailText}</pre>
          </details>
        ) : null}

        <div className="buttonRow">
          {allowRetry ? (
            <button className="btn btnPrimary" onClick={onRetry}>
              {normalized.safeToRetry ? "Retry" : "Refresh and retry"}
            </button>
          ) : null}
          {normalized.category === "auth_session_expired" ? (
            <button className="btn" onClick={() => navWithReturn("/session", returnTo)}>
              Open session recovery
            </button>
          ) : null}
          {normalized.category === "recorded_not_yet_visible" ? (
            <button className="btn" onClick={() => navWithReturn("/transactions", returnTo)}>
              View action history
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
