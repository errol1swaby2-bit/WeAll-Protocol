import React from "react";

import { summarizeSessionState } from "../lib/status";
import { nav } from "../lib/router";

export default function SessionPill(): JSX.Element {
  const summary = summarizeSessionState({});

  if (!summary.account) {
    return (
      <button className="statusPill" onClick={() => nav("/login")}>
        <span>No session</span>
        <span>{summary.detail}</span>
      </button>
    );
  }

  return (
    <button
      className={`statusPill ${summary.hasLocalSigner && summary.hasBrowserSession ? "ok" : ""}`}
      onClick={() => nav(`/account/${encodeURIComponent(summary.account || "")}`)}
    >
      <span className="mono">{summary.account}</span>
      <span>{summary.hasLocalSigner ? "local signer ready" : "no signer"}</span>
      <span>{summary.hasBrowserSession ? "session key active" : "no session key"}</span>
    </button>
  );
}
