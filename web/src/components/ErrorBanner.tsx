import React from "react";

type Props = {
  message?: string | null;
  details?: any;
  onRetry?: (() => void) | null;
  onDismiss?: (() => void) | null;
};

export default function ErrorBanner({ message, details, onRetry, onDismiss }: Props): JSX.Element | null {
  if (!message) return null;

  const detailText =
    typeof details === "string"
      ? details
      : details
        ? JSON.stringify(details, null, 2)
        : "";

  return (
    <div className="card">
      <div className="cardBody formStack">
        <div className="sectionHead">
          <div>
            <div className="eyebrow">Something needs attention</div>
            <h2 className="cardTitle">Action failed</h2>
          </div>
          <span className="statusPill danger">Error</span>
        </div>

        <div className="inlineError">{message}</div>

        {detailText ? <pre className="codePanel mono">{detailText}</pre> : null}

        <div className="buttonRow">
          {onRetry ? (
            <button className="btn btnPrimary" onClick={onRetry}>
              Retry
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
