import React from "react";

export type TxToastItem = {
  id: string;
  title: string;
  status: "pending" | "success" | "error";
  message?: string;
  txId?: string;
  createdAt: number;
};

export default function TxStatusToast({
  items,
  onDismiss,
}: {
  items: TxToastItem[];
  onDismiss: (id: string) => void;
}): JSX.Element | null {
  if (!items.length) return null;

  return (
    <div className="txToastStack" aria-live="polite" aria-atomic="false">
      {items.map((item) => (
        <div key={item.id} className={`txToast txToast-${item.status}`}>
          <div className="txToastHead">
            <strong>{item.title}</strong>
            <button className="txToastClose" onClick={() => onDismiss(item.id)} aria-label="Dismiss">
              ×
            </button>
          </div>

          <div className="txToastBody">
            <div className="txToastBadge">
              {item.status === "pending" ? "Pending" : item.status === "success" ? "Confirmed" : "Failed"}
            </div>

            {item.message ? <div className="txToastMessage">{item.message}</div> : null}

            {item.txId ? (
              <div className="txToastMeta">
                Tx <span className="mono">{item.txId}</span>
              </div>
            ) : null}
          </div>
        </div>
      ))}
    </div>
  );
}
