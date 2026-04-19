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

type TxCatalogSummaryRow = {
  name: string;
  count: number;
};

type TxCatalogItem = {
  id: string;
  name: string;
  origin: string;
  context: string;
  domain: string;
  receipt_only: boolean;
  subject_gate?: string;
  api_entrypoints?: string[];
};

type TxCatalogResponse = {
  ok: boolean;
  total: number;
  count: number;
  filters?: { context?: string; domain?: string; search?: string };
  summary?: { by_context?: TxCatalogSummaryRow[]; by_domain?: TxCatalogSummaryRow[] };
  items?: TxCatalogItem[];
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

function summarizeList(rows: TxCatalogSummaryRow[] | undefined, limit = 4): string {
  if (!rows?.length) return "—";
  return rows
    .slice(0, limit)
    .map((row) => `${row.name} (${row.count})`)
    .join(" · ");
}

function summarizeEntrypoints(item: TxCatalogItem): string {
  const routes = Array.isArray(item.api_entrypoints) ? item.api_entrypoints.filter(Boolean) : [];
  if (!routes.length) {
    return item.context === "block" ? "System or consensus-owned path" : "No public HTTP entrypoint exposed";
  }
  return routes.join(" · ");
}

export default function TransactionsPage(): JSX.Element {
  const tx = useTxQueue();
  const base = useMemo(() => getApiBaseUrl(), []);
  const session = getSession();
  const account = session?.account ? normalizeAccount(session.account) : "";
  const [history, setHistory] = useState<TxHistoryItem[]>(() => loadHistory());
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<{ msg: string; details: any } | null>(null);
  const [catalogError, setCatalogError] = useState<{ msg: string; details: any } | null>(null);
  const [catalogLoading, setCatalogLoading] = useState(false);
  const [catalog, setCatalog] = useState<TxCatalogResponse | null>(null);
  const [catalogSearch, setCatalogSearch] = useState("");
  const [catalogContext, setCatalogContext] = useState("");
  const [catalogDomain, setCatalogDomain] = useState("");

  useEffect(() => {
    const sync = () => setHistory(loadHistory());
    window.addEventListener("storage", sync);
    const timer = window.setInterval(sync, 1200);
    return () => {
      window.removeEventListener("storage", sync);
      window.clearInterval(timer);
    };
  }, []);

  useEffect(() => {
    let cancelled = false;
    const run = async () => {
      setCatalogLoading(true);
      setCatalogError(null);
      try {
        const result = await weall.txCatalog(
          {
            context: catalogContext || undefined,
            domain: catalogDomain || undefined,
            search: catalogSearch.trim() || undefined,
          },
          base,
        );
        if (!cancelled) {
          setCatalog(result as TxCatalogResponse);
        }
      } catch (e: any) {
        if (!cancelled) {
          setCatalogError({ msg: e?.message || "Failed to load transaction catalog.", details: e });
        }
      } finally {
        if (!cancelled) setCatalogLoading(false);
      }
    };
    void run();
    return () => {
      cancelled = true;
    };
  }, [base, catalogContext, catalogDomain, catalogSearch]);

  const queueItems = tx.items;
  const pendingCount = history.filter((item) => item.status === "preparing" || item.status === "submitted").length;
  const terminalCount = history.filter((item) => item.status === "confirmed" || item.status === "error" || item.status === "unknown").length;

  const availableContexts = useMemo(() => catalog?.summary?.by_context?.map((row) => row.name) || [], [catalog]);
  const availableDomains = useMemo(() => catalog?.summary?.by_domain?.map((row) => row.name) || [], [catalog]);

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
              This page keeps local submission history separate from backend-confirmed transaction status and now also exposes the canonical transaction catalog, including the public HTTP entrypoints that wire frontend flows to backend tx surfaces.
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
            <span className="summaryCardLabel">Canonical tx catalog</span>
            <div className="summaryCardValue">{catalog?.count ?? "—"}</div>
            <div className="summaryCardHint">Filtered backend tx surfaces currently visible through the catalog route.</div>
          </article>
          <article className="summaryCard">
            <span className="summaryCardLabel">Top contexts</span>
            <div className="summaryCardValue" style={{ fontSize: "1rem" }}>{summarizeList(catalog?.summary?.by_context)}</div>
            <div className="summaryCardHint">Useful for seeing which flows originate in mempool versus block/system phases.</div>
          </article>
        </div>
      </section>

      {error ? <ErrorBanner message={error.msg} details={error.details} /> : null}
      {catalogError ? <ErrorBanner message={catalogError.msg} details={catalogError.details} /> : null}

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
              <strong>Canonical tx catalog:</strong> the backend now exposes transaction surface metadata so frontend work can be explicitly aligned to real protocol tx types, contexts, gate expectations, and concrete public HTTP entrypoints.
            </div>
          </div>
        </article>
      </section>

      <section className="card">
        <div className="cardHeaderRow">
          <div>
            <div className="eyebrow">Transaction catalog</div>
            <h2 className="cardTitle">Backend tx surface map</h2>
          </div>
          <div className="miniTag">{catalog?.count ?? 0} shown / {catalog?.total ?? 0} total</div>
        </div>
        <p className="cardDesc">
          Use this to connect frontend builders and review flows to canonical backend transaction types instead of relying on implicit assumptions.
        </p>
        <div className="row gap8 wrap" style={{ marginBottom: 12 }}>
          <input
            className="input"
            placeholder="Search tx type, domain, or gate"
            value={catalogSearch}
            onChange={(ev) => setCatalogSearch(ev.target.value)}
            style={{ minWidth: 260 }}
          />
          <select className="input" value={catalogContext} onChange={(ev) => setCatalogContext(ev.target.value)} style={{ minWidth: 160 }}>
            <option value="">All contexts</option>
            {availableContexts.map((name) => (
              <option key={name} value={name}>{name}</option>
            ))}
          </select>
          <select className="input" value={catalogDomain} onChange={(ev) => setCatalogDomain(ev.target.value)} style={{ minWidth: 180 }}>
            <option value="">All domains</option>
            {availableDomains.map((name) => (
              <option key={name} value={name}>{name}</option>
            ))}
          </select>
          {catalogLoading ? <span className="statusPill warn">Loading catalog…</span> : null}
        </div>
        <div className="summaryCardGrid summaryCardGridThree" style={{ marginBottom: 16 }}>
          <article className="summaryCard">
            <span className="summaryCardLabel">Top domains</span>
            <div className="summaryCardValue" style={{ fontSize: "1rem" }}>{summarizeList(catalog?.summary?.by_domain)}</div>
            <div className="summaryCardHint">Shows where the biggest transaction surface areas live.</div>
          </article>
          <article className="summaryCard">
            <span className="summaryCardLabel">Top contexts</span>
            <div className="summaryCardValue" style={{ fontSize: "1rem" }}>{summarizeList(catalog?.summary?.by_context)}</div>
            <div className="summaryCardHint">Mempool and block context are the primary execution entry points.</div>
          </article>
          <article className="summaryCard">
            <span className="summaryCardLabel">Frontend connection</span>
            <div className="summaryCardValue" style={{ fontSize: "1rem" }}>{catalogContext || catalogDomain || catalogSearch ? "Filtered" : "Full map"}</div>
            <div className="summaryCardHint">Use filters to focus implementation work on a single domain or flow family.</div>
          </article>
        </div>
        {catalog?.items?.length ? (
          <div className="txRecordList compact">
            {catalog.items.slice(0, 80).map((item) => (
              <article key={item.id || item.name} className="txRecordCard unknown">
                <div className="txRecordHeader">
                  <strong>{item.name}</strong>
                  <span className="statusPill ok">{item.context || "—"}</span>
                </div>
                <div className="txRecordMeta">
                  Domain: {item.domain || "—"} · Origin: {item.origin || "—"} · Gate: {item.subject_gate || "—"}
                </div>
                <div className="mutedText">HTTP entrypoints: {summarizeEntrypoints(item)}</div>
                <div className="mutedText">{item.receipt_only ? "Receipt/system surface" : "Client-signable or validator surface"}</div>
              </article>
            ))}
          </div>
        ) : (
          <div className="emptyState">No catalog entries matched the current filters.</div>
        )}
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
