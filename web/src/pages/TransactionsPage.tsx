import React, { useEffect, useMemo, useState } from "react";

import { getApiBaseUrl, weall } from "../api/weall";
import ErrorBanner from "../components/ErrorBanner";
import { getSession } from "../auth/session";
import { normalizeAccount } from "../auth/keys";
import { useTxQueue } from "../hooks/useTxQueue";
import { normalizeTxStatus } from "../lib/status";

type TxHistoryItem = {
  id: string;
  title: string;
  status: "preparing" | "submitted" | "confirmed" | "error" | "unknown";
  message?: string;
  txId?: string;
  createdAt: number;
  updatedAt: number;
};

const TX_HISTORY_KEY = "weall_tx_activity_v1";

function loadHistory(): TxHistoryItem[] {
  try {
    const raw = localStorage.getItem(TX_HISTORY_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed as TxHistoryItem[];
  } catch {
    return [];
  }
}

function fmtTs(value: number | undefined): string {
  if (!Number.isFinite(Number(value))) return "—";
  try {
    return new Date(Number(value)).toLocaleString();
  } catch {
    return String(value);
  }
}

export default function TransactionsPage(): JSX.Element {
  const tx = useTxQueue();
  const base = useMemo(() => getApiBaseUrl(), []);
  const session = getSession();
  const account = session?.account ? normalizeAccount(session.account) : "";
  const [history, setHistory] = useState<TxHistoryItem[]>(() => loadHistory());
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<{ msg: string; details: any } | null>(null);

  useEffect(() => {
    const sync = () => setHistory(loadHistory());
    window.addEventListener("storage", sync);
    const timer = window.setInterval(sync, 1200);
    return () => {
      window.removeEventListener("storage", sync);
      window.clearInterval(timer);
    };
  }, []);

  const queueItems = tx.items;
  const pendingCount = history.filter((item) => item.status === "preparing" || item.status === "submitted").length;
  const terminalCount = history.filter((item) => item.status === "confirmed" || item.status === "error" || item.status === "unknown").length;

  async function refreshPendingStatuses(): Promise<void> {
    setRefreshing(true);
    setError(null);
    try {
      const next = [...history];
      for (let idx = 0; idx < next.length; idx += 1) {
        const item = next[idx];
        if (!item?.txId) continue;
        if (!(item.status === "submitted" || item.status === "unknown")) continue;
        try {
          const raw = await weall.txStatus(item.txId, base);
          const normalized = normalizeTxStatus(raw, item.txId);
          next[idx] = {
            ...item,
            status: normalized.phase === "failed" ? "error" : normalized.phase,
            message: normalized.detail,
            updatedAt: Date.now(),
          };
        } catch {
          // keep previous state
        }
      }
      localStorage.setItem(TX_HISTORY_KEY, JSON.stringify(next));
      setHistory(next);
    } catch (e: any) {
      setError({ msg: e?.message || "Failed to refresh pending transaction statuses.", details: e });
    } finally {
      setRefreshing(false);
    }
  }

  function clearHistory(): void {
    localStorage.removeItem(TX_HISTORY_KEY);
    setHistory([]);
  }

  return (
    <div className="stack pageStack">
      <section className="surfaceSummary surfaceSummarySpacious">
        <div className="surfaceSummaryHeader">
          <div>
            <div className="eyebrow">Protocol</div>
            <h1 className="surfaceTitle">Transaction activity</h1>
            <p className="surfaceSummaryHint">
              This page keeps local submission history separate from backend-confirmed transaction status so the interface does not overstate finality.
            </p>
          </div>
          <div className="statusRowWrap">
            <span className={`statusPill ${queueItems.length ? "ok" : ""}`}>{queueItems.length ? `${queueItems.length} live queue item${queueItems.length === 1 ? "" : "s"}` : "No live queue items"}</span>
            <span className={`statusPill ${pendingCount ? "warn" : "ok"}`}>{pendingCount ? `${pendingCount} pending` : "No pending txs"}</span>
            <span className="statusPill ok">{account || "No session account"}</span>
          </div>
        </div>
        <div className="summaryCardGrid summaryCardGridThree">
          <article className="summaryCard">
            <span className="summaryCardLabel">Tracked history</span>
            <div className="summaryCardValue">{history.length}</div>
            <div className="summaryCardHint">Recent local submission history stored by this browser.</div>
          </article>
          <article className="summaryCard">
            <span className="summaryCardLabel">Pending lifecycle</span>
            <div className="summaryCardValue">{pendingCount}</div>
            <div className="summaryCardHint">These items still need backend or later surface confirmation.</div>
          </article>
          <article className="summaryCard">
            <span className="summaryCardLabel">Terminal records</span>
            <div className="summaryCardValue">{terminalCount}</div>
            <div className="summaryCardHint">Confirmed, failed, or unknown outcomes already recorded by this client.</div>
          </article>
        </div>
      </section>

      {error ? <ErrorBanner message={error.msg} details={error.details} /> : null}

      <section className="infoGrid twoCol">
        <article className="card">
          <div className="cardHeaderRow">
            <div>
              <div className="eyebrow">Live queue</div>
              <h2 className="cardTitle">Current toast-backed activity</h2>
            </div>
          </div>
          <p className="cardDesc">
            This is the same live queue surfaced through toast notifications. It reflects the current browser runtime, not canonical chain history.
          </p>
          {queueItems.length ? (
            <div className="txRecordList compact">
              {queueItems.map((item) => (
                <article key={item.id} className={`txRecordCard ${item.status}`}>
                  <div className="txRecordHeader">
                    <strong>{item.title}</strong>
                    <span className={`statusPill tx-${item.status}`}>{item.status}</span>
                  </div>
                  <div className="txRecordMeta">{item.message || "No message available."}</div>
                  {item.txId ? <div className="mono wrapAnywhere">{item.txId}</div> : null}
                </article>
              ))}
            </div>
          ) : (
            <div className="emptyState">No live queue entries are active right now.</div>
          )}
        </article>

        <article className="card">
          <div className="cardHeaderRow">
            <div>
              <div className="eyebrow">Explorer-lite</div>
              <h2 className="cardTitle">What this page is and is not</h2>
            </div>
            <div className="row gap8">
              <button className="btn" disabled={refreshing || !history.length} onClick={() => void refreshPendingStatuses()}>
                Refresh pending
              </button>
              <button className="btn ghost" disabled={!history.length} onClick={clearHistory}>Clear local history</button>
            </div>
          </div>
          <div className="stack gap12">
            <div className="summaryCallout">
              <strong>Local history:</strong> this browser remembers recent submission attempts and the last known lifecycle state.
            </div>
            <div className="summaryCallout subtle">
              <strong>Not canonical history:</strong> a transaction appearing here does not by itself prove inclusion, execution, or long-term index retention. Use account, content, or protocol surfaces to verify authoritative outcome.
            </div>
          </div>
        </article>
      </section>

      <section className="card">
        <div className="cardHeaderRow">
          <div>
            <div className="eyebrow">Recent local history</div>
            <h2 className="cardTitle">Stored transaction records</h2>
          </div>
          <div className="miniTag">{history.length} records</div>
        </div>
        {history.length ? (
          <div className="txRecordList">
            {history.map((item) => (
              <article key={item.id} className={`txRecordCard ${item.status}`}>
                <div className="txRecordHeader">
                  <div>
                    <div className="txRecordTitle">{item.title}</div>
                    <div className="txRecordMeta">Created {fmtTs(item.createdAt)} · Updated {fmtTs(item.updatedAt)}</div>
                  </div>
                  <span className={`statusPill tx-${item.status}`}>{item.status}</span>
                </div>
                <div className="txRecordMessage">{item.message || "No lifecycle detail stored."}</div>
                {item.txId ? <div className="mono wrapAnywhere">{item.txId}</div> : <div className="mutedText">No tx id captured for this local record.</div>}
              </article>
            ))}
          </div>
        ) : (
          <div className="emptyState">This browser has not stored any transaction history yet.</div>
        )}
      </section>
    </div>
  );
}
