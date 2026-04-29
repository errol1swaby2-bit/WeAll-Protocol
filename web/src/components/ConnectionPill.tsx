import React, { useEffect, useMemo, useState } from "react";

import { getApiBaseUrl, weall } from "../api/weall";
import { summarizeNodeConnection } from "../lib/status";
import { nav } from "../lib/router";

function statusClass(kind: "online" | "degraded" | "offline"): string {
  if (kind === "online") return "ok";
  if (kind === "offline") return "danger";
  return "";
}

export default function ConnectionPill(): JSX.Element {
  const base = useMemo(() => getApiBaseUrl(), []);
  const [statusView, setStatusView] = useState<any | null>(null);

  useEffect(() => {
    let cancelled = false;

    async function run() {
      try {
        const r = await weall.status(base);
        if (!cancelled) setStatusView(r);
      } catch {
        if (!cancelled) setStatusView(null);
      }
    }

    void run();
    const timer = window.setInterval(() => {
      void run();
    }, 15000);

    return () => {
      cancelled = true;
      window.clearInterval(timer);
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
