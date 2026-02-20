import React, { useState } from "react";

type Props = {
  message?: string;
  details?: any;
  onRetry?: () => void;
  onDismiss?: () => void;
};

export default function ErrorBanner({ message, details, onRetry, onDismiss }: Props) {
  const [open, setOpen] = useState(false);

  if (!message) return null;

  return (
    <div
      style={{
        background: "#fff5f5",
        border: "1px solid #f5c2c2",
        color: "#8b0000",
        padding: 12,
        borderRadius: 8,
        marginBottom: 12,
      }}
    >
      <div style={{ fontWeight: 600 }}>{message}</div>

      <div style={{ marginTop: 8, display: "flex", gap: 8, flexWrap: "wrap" }}>
        {onRetry && (
          <button onClick={onRetry} style={{ padding: "6px 10px", borderRadius: 6 }}>
            Retry
          </button>
        )}

        {details && (
          <button onClick={() => setOpen(!open)} style={{ padding: "6px 10px", borderRadius: 6 }}>
            {open ? "Hide details" : "Show details"}
          </button>
        )}

        <button
          onClick={() => {
            navigator.clipboard.writeText(
              typeof details === "string" ? details : JSON.stringify(details, null, 2)
            );
          }}
          style={{ padding: "6px 10px", borderRadius: 6 }}
        >
          Copy
        </button>

        {onDismiss && (
          <button onClick={onDismiss} style={{ padding: "6px 10px", borderRadius: 6 }}>
            Dismiss
          </button>
        )}
      </div>

      {open && details && (
        <pre
          style={{
            marginTop: 10,
            background: "#fff",
            padding: 10,
            borderRadius: 6,
            fontSize: 12,
            overflowX: "auto",
          }}
        >
          {typeof details === "string" ? details : JSON.stringify(details, null, 2)}
        </pre>
      )}
    </div>
  );
}
