import React, { useEffect, useState } from "react";

import { getApiBaseUrl, weall } from "../api/weall";
import { summarizeNodeConnection } from "../lib/status";
import { nav } from "../lib/router";
import { WEALL_API_BASE_CHANGED_EVENT } from "../lib/nodeConnectionManager";

function statusClass(kind: "online" | "degraded" | "offline"): string {
  if (kind === "online") return "ok";
  if (kind === "offline") return "danger";
  return "";
}

export default function ConnectionPill(): JSX.Element {
  const [base, setBase] = useState<string>(() => getApiBaseUrl());
  const [statusView, setStatusView] = useState<any | null>(null);

  useEffect(() => {
    let cancelled = false;

    const refreshBase = () => setBase(getApiBaseUrl());

    async function run() {
      try {
        const r = await weall.status(base);
        if (!cancelled) setStatusView(r);
      } catch {
        if (!cancelled) setStatusView(null);
      }
    }

    window.addEventListener(WEALL_API_BASE_CHANGED_EVENT, refreshBase);
    window.addEventListener("storage", refreshBase);

    void run();
    const timer = window.setInterval(() => {
      void run();
    }, 15000);

    return () => {
      cancelled = true;
      window.clearInterval(timer);
      window.removeEventListener(WEALL_API_BASE_CHANGED_EVENT, refreshBase);
      window.removeEventListener("storage", refreshBase);
    };
  }, [base]);

  const summary = summarizeNodeConnection(statusView, base);

  return (
    <button className={`statusPill ${statusClass(summary.phase)}`} title={base} onClick={() => nav("/tools")}>
      <span>{summary.label}</span>
      <span className="mono connectionMeta">{summary.detail || base}</span>
    </button>
  );
}
