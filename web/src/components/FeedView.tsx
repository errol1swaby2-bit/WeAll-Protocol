// projects/web/src/components/FeedView.tsx
import React, { useEffect, useState } from "react";
import { weall } from "../api/weall";
import { getAuthHeaders } from "../auth/session";
import { nav } from "../lib/router";

export default function FeedView({
  base,
  scope,
  defaultSort = "new",
  defaultFilters = { visibility: "all" },
}: any) {
  const [items, setItems] = useState<any[]>([]);
  const [sort, setSort] = useState(defaultSort);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function load() {
    setErr(null);
    setLoading(true);
    try {
      const params: any = {
        limit: 25,
        sort,
        visibility: defaultFilters.visibility,
      };

      if (scope?.kind === "following") params.scope = "following";
      if (scope?.kind === "mine") params.scope = "mine";
      if (scope?.kind === "group") {
        params.scope = "group";
        params.group_id = scope.groupId;
      }

      const headers = getAuthHeaders();
      const r = await weall.feed(params, base, headers);
      setItems(r.items || []);
    } catch (e: any) {
      setErr(e?.data?.message || e?.message || "error");
      setItems([]);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sort, scope]);

  return (
    <div>
      <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
        <select value={sort} onChange={(e) => setSort(e.target.value)}>
          <option value="new">New</option>
          <option value="top">Top</option>
          <option value="hot">Hot</option>
        </select>
        <button onClick={load} disabled={loading}>
          {loading ? "Loading…" : "Refresh"}
        </button>
        {err ? <span style={{ color: "#b00020", fontSize: 13 }}>{err}</span> : null}
      </div>

      <div style={{ marginTop: 10, display: "flex", flexDirection: "column", gap: 10 }}>
        {items.map((it) => {
          const id = it.post_id || it.id;
          const media = Array.isArray(it.media_items) ? it.media_items : [];
          return (
            <div key={id} style={{ background: "#fff", border: "1px solid #ddd", borderRadius: 12, padding: 12 }}>
              <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
                <b>{it.author}</b>
                <span style={{ fontSize: 12, opacity: 0.7 }}>
                  {it.visibility || "public"}
                  {it.reaction_count != null ? ` • ${it.reaction_count} reacts` : ""}
                  {it.comment_count != null ? ` • ${it.comment_count} replies` : ""}
                </span>
                <div style={{ flex: 1 }} />
                {id ? (
                  <button onClick={() => nav(`/content/${encodeURIComponent(id)}`)} style={{ fontSize: 13 }}>
                    Open
                  </button>
                ) : null}
              </div>

              <div style={{ marginTop: 8, whiteSpace: "pre-wrap" }}>{it.body}</div>

              {media.length ? (
                <div style={{ marginTop: 10, display: "flex", gap: 10, flexWrap: "wrap" }}>
                  {media.map((m: any) => {
                    const url = m.gateway_url || "";
                    const mime = String(m.mime || m.payload?.mime || "");
                    const isImage = mime.startsWith("image/") || (m.kind || "").toLowerCase() === "image";
                    return (
                      <div key={m.media_id} style={{ border: "1px solid #eee", borderRadius: 10, padding: 8, maxWidth: 320 }}>
                        {isImage && url ? (
                          <a href={url} target="_blank" rel="noreferrer">
                            <img src={url} alt={m.media_id} style={{ maxWidth: 300, maxHeight: 220, borderRadius: 8 }} />
                          </a>
                        ) : url ? (
                          <a href={url} target="_blank" rel="noreferrer" style={{ fontSize: 13 }}>
                            Open media ({m.cid})
                          </a>
                        ) : (
                          <span style={{ fontSize: 13, opacity: 0.75 }}>Media: {m.cid || m.media_id}</span>
                        )}
                      </div>
                    );
                  })}
                </div>
              ) : null}
            </div>
          );
        })}
      </div>
    </div>
  );
}
