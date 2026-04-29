import React from "react";

import { txStatusLabel, type TxLifecycleStatus } from "../lib/txFeedback";

export type TxToastStatus = TxLifecycleStatus;

export type TxToastItem = {
  id: string;
  title: string;
  status: TxToastStatus;
  message?: string;
  txId?: string;
  createdAt: number;
  updatedAt?: number;
};

function statusHint(status: TxToastStatus): string {
  switch (status) {
    case "validating":
      return "Checking the action before a signed submission is attempted.";
    case "submitting":
      return "Submitting the signed action to the node.";
    case "recorded":
      return "The action was accepted, but the affected surface may still be catching up.";
    case "refreshing":
      return "Refreshing dependent state so the page can show the result visibly.";
    case "confirmed":
      return "The action has been confirmed and the dependent surface reconciled.";
    case "failed":
    default:
      return "The action did not complete successfully.";
  }
}

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
        <div key={item.id} className={`txToast txToast-${item.status}`} data-tx-status={item.status}>
          <div className="txToastHead">
            <strong>{item.title}</strong>
            <button className="txToastClose" onClick={() => onDismiss(item.id)} aria-label="Dismiss transaction status">
              ×
            </button>
          </div>

          <div className="txToastBody">
            <div className="txToastBadgeRow">
              <div className={`txToastBadge txToastBadge-${item.status}`}>{txStatusLabel(item.status)}</div>
              <div className="txToastHint">{statusHint(item.status)}</div>
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
