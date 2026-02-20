import React, { useEffect, useMemo, useState } from "react";
import { getApiBaseUrl, setApiBaseUrl, weall } from "../api/weall";
import { ensureNodeSelection } from "../lib/nodeSelect";
import { getCanonMismatchFlag } from "../lib/canonGuard";
import { config } from "../lib/config";
import { webBuildLabel } from "../lib/version";

export default function ConnectionPill() {
  const envLabel = useMemo(() => config.envLabel, []);
  const buildLabel = useMemo(() => webBuildLabel(), []);
  const [base, setBase] = useState(getApiBaseUrl());
  const [height, setHeight] = useState<number | null>(null);
  const [ok, setOk] = useState<boolean | null>(null);
  const [editing, setEditing] = useState(false);
  const [tempBase, setTempBase] = useState(base);
  const [canonMismatch, setCanonMismatch] = useState(false);

  async function ping() {
    try {
      const r = await weall.status(base);
      setHeight(r?.height ?? 0);
      setOk(true);
    } catch {
      setOk(false);
      setHeight(null);
    } finally {
      setCanonMismatch(getCanonMismatchFlag());
    }
  }

  async function autoPick() {
    const sel = await ensureNodeSelection({ force: true, timeoutMs: 2000 });
    const best = sel?.primary || getApiBaseUrl();
    setApiBaseUrl(best);
    setBase(best);
    await ping();
  }

  useEffect(() => {
    ping();
    const id = setInterval(ping, 8000);
    return () => clearInterval(id);
  }, [base]);

  const dotColor = ok === null ? "#999" : ok ? "green" : "red";

  return (
    <div
      style={{
        display: "flex",
        gap: 10,
        alignItems: "center",
        background: "#f4f4f4",
        padding: "6px 10px",
        borderRadius: 20,
        fontSize: 13,
        flexWrap: "wrap",
      }}
    >
      <span style={{ width: 8, height: 8, borderRadius: "50%", background: dotColor }} />

      <span style={{ fontWeight: 700 }}>{envLabel}</span>

      <span style={{ opacity: 0.75, fontFamily: "monospace", fontSize: 12 }} title="web build">
        {buildLabel}
      </span>

      {canonMismatch ? (
        <span
          style={{
            background: "#fff5d6",
            border: "1px solid #f0d48a",
            padding: "2px 8px",
            borderRadius: 999,
            fontSize: 12,
          }}
          title="Canon changed mid-session. Writes are blocked until reload."
        >
          ⚠ canon changed
        </span>
      ) : null}

      {editing ? (
        <>
          <input value={tempBase} onChange={(e) => setTempBase(e.target.value)} style={{ fontSize: 12 }} />
          <button
            onClick={() => {
              const v = tempBase.trim();
              setApiBaseUrl(v);
              setBase(v);
              setEditing(false);
            }}
          >
            Save
          </button>
        </>
      ) : (
        <>
          <span style={{ fontFamily: "monospace" }}>{base}</span>
          <span style={{ opacity: 0.7 }}>{height !== null ? `h:${height}` : ""}</span>
          <button onClick={() => setEditing(true)}>Edit</button>
          <button onClick={ping}>Ping</button>
          <button onClick={autoPick}>Auto</button>
        </>
      )}
    </div>
  );
}
