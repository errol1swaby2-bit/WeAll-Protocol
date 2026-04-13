import React, { useEffect, useMemo, useState } from "react";

import { getApiBaseUrl, weall } from "../api/weall";
import { getSession } from "../auth/session";
import { normalizeAccount } from "../auth/keys";
import {
  summarizeAccountStanding,
  summarizeNodeConnection,
  summarizeSessionState,
  type AccountStandingSummary,
  type NodeConnectionState,
  type SessionStateSummary,
} from "../lib/status";
import { nav } from "../lib/router";

type SummaryState = {
  node: NodeConnectionState;
  session: SessionStateSummary;
  standing: AccountStandingSummary;
};

function stateTone(kind: string): string {
  if (kind === "offline" || kind === "failed") return "danger";
  if (kind === "degraded" || kind === "unknown") return "warn";
  return "ok";
}

export default function ProtocolStatusSummary(): JSX.Element {
  const base = useMemo(() => getApiBaseUrl(), []);
  const session = getSession();
  const account = session ? normalizeAccount(session.account) : "";

  const [accountView, setAccountView] = useState<any | null>(null);
  const [registrationView, setRegistrationView] = useState<any | null>(null);
  const [statusView, setStatusView] = useState<any | null>(null);

  useEffect(() => {
    let cancelled = false;

    async function load() {
      try {
        const status = await weall.status(base);
        if (!cancelled) setStatusView(status);
      } catch {
        if (!cancelled) setStatusView(null);
      }

      if (!account) {
        if (!cancelled) {
          setAccountView(null);
          setRegistrationView(null);
        }
        return;
      }

      try {
        const [acct, registration] = await Promise.all([
          weall.account(account, base),
          weall.accountRegistered(account, base).catch(() => ({ registered: false })),
        ]);
        if (!cancelled) {
          setAccountView(acct);
          setRegistrationView(registration);
        }
      } catch {
        if (!cancelled) {
          setAccountView(null);
          setRegistrationView(null);
        }
      }
    }

    void load();
    const timer = window.setInterval(() => {
      void load();
    }, 15000);

    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [account, base]);

  const summary: SummaryState = useMemo(() => {
    const node = summarizeNodeConnection(statusView, base);
    const sessionSummary = summarizeSessionState({ accountView, registrationView });
    const standing = summarizeAccountStanding({ accountView, registrationView });
    return {
      node,
      session: sessionSummary,
      standing,
    };
  }, [accountView, base, registrationView, statusView]);

  const localSignerTone = !summary.session.account
    ? "warn"
    : summary.session.hasLocalSigner
      ? "ok"
      : "danger";

  return (
    <section className="protocolSummary" aria-label="Protocol and session status summary">
      <button className={`protocolSummaryCard ${stateTone(summary.node.phase)}`} onClick={() => nav("/tools")}>
        <div className="protocolSummaryLabel">Node connection</div>
        <strong>{summary.node.label}</strong>
        <div className="protocolSummaryDetail">{summary.node.detail || base}</div>
      </button>

      <button className={`protocolSummaryCard ${localSignerTone}`} onClick={() => nav(summary.session.account ? `/account/${encodeURIComponent(summary.session.account)}` : "/login")}>
        <div className="protocolSummaryLabel">Local device</div>
        <strong>{summary.session.account || "No account selected"}</strong>
        <div className="protocolSummaryDetail">{summary.session.detail}</div>
      </button>

      <button className={`protocolSummaryCard ${summary.session.hasBrowserSession ? "ok" : "warn"}`} onClick={() => nav(summary.session.account ? `/account/${encodeURIComponent(summary.session.account)}` : "/login")}>
        <div className="protocolSummaryLabel">Browser session</div>
        <strong>{summary.session.hasBrowserSession ? "Session active" : "Session not established"}</strong>
        <div className="protocolSummaryDetail">
          {summary.session.expiresAtMs
            ? `Expires ${new Date(summary.session.expiresAtMs).toLocaleString()}`
            : "No backend-issued session key is stored locally."}
        </div>
      </button>

      <button className={`protocolSummaryCard ${summary.standing.banned || summary.standing.locked ? "danger" : summary.standing.registered ? "ok" : "warn"}`} onClick={() => nav(summary.standing.account ? `/account/${encodeURIComponent(summary.standing.account)}` : "/login")}>
        <div className="protocolSummaryLabel">On-chain standing</div>
        <strong>{summary.standing.label}</strong>
        <div className="protocolSummaryDetail">{summary.standing.detail}</div>
      </button>
    </section>
  );
}
