import React, { useEffect, useMemo, useState } from "react";
import { getApiBaseUrl, weall } from "../api/weall";
import ErrorBanner from "../components/ErrorBanner";
import { nav } from "../lib/router";

function prettyErr(e: any): { msg: string; details: any } {
  const details = e?.data || e;
  const msg = details?.message || e?.message || "error";
  return { msg, details };
}

export default function Groups(): JSX.Element {
  const base = useMemo(() => getApiBaseUrl(), []);
  const [items, setItems] = useState<any[]>([]);
  const [err, setErr] = useState<{ msg: string; details: any } | null>(null);
  const [query, setQuery] = useState("");

  async function load() {
    setErr(null);
    try {
      const r: any = await weall.groups(base);
      setItems(r?.groups || r?.items || []);
    } catch (e: any) {
      setErr(prettyErr(e));
      setItems([]);
    }
  }

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return items;
    return items.filter((g) => {
      const id = String(g?.id || g?.group_id || "").toLowerCase();
      const name = String(g?.name || g?.title || "").toLowerCase();
      return id.includes(q) || name.includes(q);
    });
  }, [items, query]);

  return (
    <div style={{ maxWidth: 980, margin: "0 auto" }}>
      <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
        <button onClick={() => nav("/home")}>← Home</button>
        <h2 style={{ margin: 0 }}>Groups</h2>
        <button onClick={load}>Refresh</button>
        <div style={{ flex: 1 }} />
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search groups..."
          style={{ padding: 8, borderRadius: 8, border: "1px solid #ccc", minWidth: 240 }}
        />
      </div>

      <div style={{ marginTop: 10 }}>
        <ErrorBanner message={err?.msg} details={err?.details} onRetry={load} onDismiss={() => setErr(null)} />
      </div>

      <div style={{ marginTop: 12, display: "grid", gap: 10 }}>
        {!filtered.length ? (
          <div style={{ opacity: 0.7 }}>(no groups)</div>
        ) : (
          filtered.map((g) => <GroupCard key={g.id || g.group_id || JSON.stringify(g)} group={g} />)
        )}
      </div>
    </div>
  );
}

function GroupCard({ group }: { group: any }) {
  const id = String(group?.id || group?.group_id || "");
  const name = group?.name || group?.title || id || "(group)";
  const desc = group?.desc || group?.description || "";

  return (
    <div style={{ background: "#fff", border: "1px solid #ddd", borderRadius: 12, padding: 14 }}>
      <div style={{ display: "flex", gap: 10, flexWrap: "wrap", alignItems: "baseline" }}>
        <button onClick={() => nav(`/groups/${encodeURIComponent(id)}`)} style={{ fontWeight: 800, fontSize: 16 }}>
          {String(name)}
        </button>
        <span style={{ opacity: 0.65, fontFamily: "monospace", fontSize: 12 }}>
          {id}
        </span>
      </div>

      {desc ? (
        <div style={{ marginTop: 8, whiteSpace: "pre-wrap", opacity: 0.9 }}>{String(desc)}</div>
      ) : (
        <div style={{ marginTop: 8, opacity: 0.6 }}>(no description)</div>
      )}
    </div>
  );
}
