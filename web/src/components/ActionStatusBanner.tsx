import React from "react";

export type HumanActionStatus = "ready" | "saving" | "done" | "needs_attention" | "failed";

function statusTone(status: HumanActionStatus): string {
  switch (status) {
    case "done":
      return "ok";
    case "saving":
    case "needs_attention":
      return "warn";
    case "failed":
      return "danger";
    case "ready":
    default:
      return "neutral";
  }
}

function statusLabel(status: HumanActionStatus): string {
  switch (status) {
    case "saving":
      return "Saving";
    case "done":
      return "Done";
    case "needs_attention":
      return "Needs attention";
    case "failed":
      return "Failed";
    case "ready":
    default:
      return "Ready";
  }
}

export default function ActionStatusBanner({
  status,
  title,
  message,
  children,
}: {
  status: HumanActionStatus;
  title?: string;
  message: string;
  children?: React.ReactNode;
}): JSX.Element {
  const tone = statusTone(status);
  return (
    <div className={`actionStatusBanner actionStatusBanner-${tone}`} data-action-status={status}>
      <div className="actionStatusHeader">
        <div>
          <div className="eyebrow">{statusLabel(status)}</div>
          {title ? <h3 className="actionStatusTitle">{title}</h3> : null}
        </div>
        <span className={`statusPill ${tone === "ok" ? "ok" : tone === "warn" ? "warning" : tone === "danger" ? "danger" : ""}`.trim()}>{statusLabel(status)}</span>
      </div>
      <div className={`inlineMessage inlineMessage-${tone === "danger" ? "danger" : tone === "warn" ? "warn" : "neutral"}`}>{message}</div>
      {children ? <div className="actionStatusBody">{children}</div> : null}
    </div>
  );
}
