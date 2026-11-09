import React from "react";

type Props = {
  asyncCases: any[];
  liveCases: any[];
  liveSessions: any[];
  asyncHistoryReady: boolean;
  liveHistoryReady: boolean;
  loading: boolean;
  casesBusy: boolean;
  onRefresh: () => void;
  renderAsyncCase: (item: any) => React.ReactNode;
  renderLiveCase: (item: any) => React.ReactNode;
  accountState: unknown;
  registrationView: unknown;
  lastResult: unknown;
};

function JsonDetails({ title, value }: { title: string; value: unknown }): JSX.Element | null {
  if (value === null || value === undefined) return null;
  return (
    <details className="advancedDisclosure">
      <summary>{title}</summary>
      <pre style={{ whiteSpace: "pre-wrap", marginTop: 10 }}>{JSON.stringify(value, null, 2)}</pre>
    </details>
  );
}

/**
 * Read-only, status-first presentation. Failed account/case reads are unknown:
 * an empty visible array is NOT proof that no case exists while any of the
 * corresponding histories are unavailable.
 */
export default function VerificationHistoryPanel({
  asyncCases,
  liveCases,
  liveSessions,
  asyncHistoryReady,
  liveHistoryReady,
  loading,
  casesBusy,
  onRefresh,
  renderAsyncCase,
  renderLiveCase,
  accountState,
  registrationView,
  lastResult,
}: Props): JSX.Element {
  const allReady = asyncHistoryReady && liveHistoryReady;
  const visibleCount = asyncCases.length + liveCases.length;
  return (
    <section className="grid2" data-testid="poh-verification-history-panel">
      <article className="card">
        <div className="cardBody formStack">
          <div className="sectionHead">
            <div>
              <div className="eyebrow">Verification History</div>
              <h2 className="cardTitle">Requests, reviews, and live sessions</h2>
            </div>
            <span className="statusPill" data-testid="poh-visible-history-count">
              {visibleCount} visible item(s){allReady ? "" : " (possibly stale)"}
            </span>
          </div>
          <p className="cardDesc">
            Track visible requests and reviewer decisions. A case record does not
            by itself confirm review, finality or a higher verification tier.
          </p>

          {!allReady ? (
            <div className="calloutDanger" role="status" data-testid="poh-history-unavailable">
              {casesBusy ? "Checking the original node for verification history…" :
                "One or more case histories could not be verified. Previously displayed cases may be stale; zero visible items is not proof of no previous requests."}
            </div>
          ) : null}

          <button
            type="button"
            className="btn"
            disabled={loading || casesBusy}
            onClick={onRefresh}
          >
            {loading || casesBusy ? "Checking…" : "Refresh verification history"}
          </button>

          {liveCases.length > 0 ? (
            <div className="infoGrid" data-testid="poh-live-case-history">
              {liveCases.map((item: any, idx: number) => (
                <React.Fragment key={String(item?.case_id || idx)}>{renderLiveCase(item)}</React.Fragment>
              ))}
            </div>
          ) : null}
          {asyncCases.length > 0 ? (
            <div className="infoGrid" data-testid="poh-async-case-history">
              {asyncCases.map((item: any, idx: number) => (
                <React.Fragment key={String(item?.case_id || idx)}>{renderAsyncCase(item)}</React.Fragment>
              ))}
            </div>
          ) : null}

          {!visibleCount && allReady ? (
            <div className="emptyState compactEmpty" data-testid="poh-confirmed-empty-history">
              <div className="emptyTitle">No verification cases are visible in the current node history.</div>
              <p className="miniMuted">This is a successful read, not proof that an unacknowledged submission never reached another node.</p>
            </div>
          ) : null}

          {liveSessions.length > 0 ? (
            <JsonDetails title="Advanced: live session payloads" value={liveSessions} />
          ) : null}
        </div>
      </article>

      <article className="card">
        <div className="cardBody formStack">
          <details className="advancedDisclosure" data-testid="poh-technical-records">
            <summary>Advanced: technical verification records</summary>
            <p className="cardDesc">
              Inspect authoritative API responses for auditing. These local
              records do not grant reviewer or network authority.
            </p>
            <JsonDetails title="Advanced: current account state" value={accountState} />
            <JsonDetails title="Advanced: registration payload" value={registrationView} />
            {lastResult ? (
              <JsonDetails title="Advanced: last API result" value={lastResult} />
            ) : (
              <p className="miniMuted">No recent action payload.</p>
            )}
          </details>
        </div>
      </article>
    </section>
  );
}
