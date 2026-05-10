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
      return "Checking the action before it is saved.";
    case "submitting":
      return "Saving the action.";
    case "recorded":
      return "Recorded by the backend. Waiting for confirmation or visible state.";
    case "refreshing":
      return "Confirmed or partly visible. Updating this page so the result is clear.";
    case "confirmed":
      return "The action is confirmed and visible.";
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
            <button className="txToastClose" onClick={() => onDismiss(item.id)} aria-label="Dismiss action status">
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
              <details className="advancedDisclosure txToastDetails">
                <summary>View technical details</summary>
                <div className="txToastMeta">
                  Action ID <span className="mono">{item.txId}</span>
                </div>
              </details>
            ) : null}
          </div>
        </div>
      ))}
    </div>
  );
}
