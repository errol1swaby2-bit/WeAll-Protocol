// web/src/pages/Group.tsx
import React, { useEffect, useMemo, useState } from "react";

import { getApiBaseUrl, weall } from "../api/weall";
import ErrorBanner from "../components/ErrorBanner";
import FeedView from "../components/FeedView";
import { nav } from "../lib/router";

function prettyErr(e: any): { msg: string; details: any } {
  const details = e?.data || e;
  const msg = details?.message || e?.message || "error";
  return { msg, details };
}

export default function Group({ id }: { id: string }): JSX.Element {
  const base = useMemo(() => getApiBaseUrl(), []);
  const [group, setGroup] = useState<any>(null);
  const [err, setErr] = useState<{ msg: string; details: any } | null>(null);

  async function loadMeta() {
    setErr(null);
    try {
      const g: any = await weall.group(id, base);
      setGroup((g as any)?.group ?? g);
    } catch (e: any) {
      setErr(prettyErr(e));
      setGroup(null);
    }
  }

  useEffect(() => {
    loadMeta();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id]);

  const name = group?.name || group?.title || id;
  const desc = group?.desc || group?.description || "";

  return (
    <div style={{ maxWidth: 980, margin: "0 auto" }}>
      <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
        <button onClick={() => nav("/groups")}>← Groups</button>
        <h2 style={{ margin: 0 }}>{String(name)}</h2>
        <button onClick={loadMeta}>Refresh</button>
      </div>

      <div style={{ marginTop: 10 }}>
        <ErrorBanner message={err?.msg} details={err?.details} onRetry={loadMeta} onDismiss={() => setErr(null)} />
      </div>

      <div style={{ background: "#fff", border: "1px solid #ddd", borderRadius: 12, padding: 14, marginTop: 12 }}>
        <div style={{ opacity: 0.65, fontFamily: "monospace", fontSize: 12 }}>{id}</div>
        {desc ? <div style={{ marginTop: 8, whiteSpace: "pre-wrap" }}>{String(desc)}</div> : <div style={{ marginTop: 8, opacity: 0.6 }}>(no description)</div>}
      </div>

      <div style={{ marginTop: 12 }}>
        <FeedView
          base={base}
          title="Posts"
          scope={{ kind: "group", groupId: id }}
          allowCompose={true}
          defaultFilters={{
            tags: `group:${id}`,
          }}
          defaultSort="newest"
          showRaw={false}
        />
      </div>

      <div style={{ marginTop: 12, background: "#fff", border: "1px solid #ddd", borderRadius: 12, padding: 14 }}>
        <div style={{ fontWeight: 700, marginBottom: 6 }}>Raw</div>
        <pre style={{ margin: 0, whiteSpace: "pre-wrap" }}>{JSON.stringify({ group }, null, 2)}</pre>
      </div>
    </div>
  );
}
