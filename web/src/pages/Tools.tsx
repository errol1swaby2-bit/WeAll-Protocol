import React, { useEffect, useMemo, useState } from "react";
import { getApiBaseUrl, weall } from "../api/weall";
import ErrorBanner from "../components/ErrorBanner";
import { nav } from "../lib/router";
import { config } from "../lib/config";

function prettyErr(e: any): { msg: string; details: any } {
  const details = e?.data || e;
  const msg = details?.message || e?.message || "error";
  return { msg, details };
}

export default function Tools(): JSX.Element {
  const base = useMemo(() => getApiBaseUrl(), []);
  const [status, setStatus] = useState<any>(null);
  const [snap, setSnap] = useState<any>(null);
  const [err, setErr] = useState<{ msg: string; details: any } | null>(null);

  async function load() {
    setErr(null);
    try {
      const s = await weall.status(base);
      setStatus(s);
    } catch (e: any) {
      setErr(prettyErr(e));
      setStatus(null);
    }
  }

  async function snapshot() {
    setErr(null);
    try {
      const r = await weall.snapshot(base);
      setSnap(r);
    } catch (e: any) {
      setErr(prettyErr(e));
      setSnap(null);
    }
  }

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  if (!config.enableDevTools) {
    return (
      <div style={{ maxWidth: 980, margin: "0 auto" }}>
        <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
          <button onClick={() => nav("/home")}>← Home</button>
          <h2 style={{ margin: 0 }}>Tools</h2>
        </div>

        <div style={{ marginTop: 12, background: "#fff5f5", border: "1px solid #f5c2c2", borderRadius: 12, padding: 14 }}>
          <b>Tools are disabled in production builds.</b>
          <div style={{ marginTop: 8, fontSize: 13, opacity: 0.85 }}>
            Set <code>VITE_WEALL_ENABLE_DEV_TOOLS=1</code> for local/dev only.
          </div>
        </div>
      </div>
    );
  }

  return (
    <div style={{ maxWidth: 980, margin: "0 auto" }}>
      <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
        <button onClick={() => nav("/home")}>← Home</button>
        <h2 style={{ margin: 0 }}>Tools</h2>
        <button onClick={load}>Refresh status</button>
        <button onClick={snapshot}>Snapshot</button>
      </div>

      <div style={{ marginTop: 10 }}>
        <ErrorBanner message={err?.msg} details={err?.details} onDismiss={() => setErr(null)} />
      </div>

      <div style={{ marginTop: 12, background: "#fff", border: "1px solid #ddd", borderRadius: 12, padding: 14 }}>
        <div style={{ fontWeight: 800, marginBottom: 8 }}>Status</div>
        <pre style={{ margin: 0, whiteSpace: "pre-wrap" }}>{JSON.stringify(status, null, 2)}</pre>
      </div>

      <div style={{ marginTop: 12, background: "#fff", border: "1px solid #ddd", borderRadius: 12, padding: 14 }}>
        <div style={{ fontWeight: 800, marginBottom: 8 }}>Snapshot</div>
        <pre style={{ margin: 0, whiteSpace: "pre-wrap" }}>{JSON.stringify(snap, null, 2)}</pre>
      </div>
    </div>
  );
}
