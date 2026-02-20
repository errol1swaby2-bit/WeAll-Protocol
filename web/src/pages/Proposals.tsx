import React, { useEffect, useMemo, useState } from "react";
import { getApiBaseUrl, weall } from "../api/weall";
import ErrorBanner from "../components/ErrorBanner";
import { nav } from "../lib/router";
import { getSession, submitSignedTx, getKeypair } from "../auth/session";
import { normalizeAccount } from "../auth/keys";

function prettyErr(e: any): { msg: string; details: any } {
  const details = e?.data || e;
  const msg = details?.message || e?.message || "error";
  return { msg, details };
}

export default function Proposals(): JSX.Element {
  const base = useMemo(() => getApiBaseUrl(), []);
  const [items, setItems] = useState<any[]>([]);
  const [err, setErr] = useState<{ msg: string; details: any } | null>(null);

  const [query, setQuery] = useState("");

  // Create tx box
  const [txType, setTxType] = useState<string>("GOV_PROPOSAL_CREATE");
  const [payloadJson, setPayloadJson] = useState<string>(
    JSON.stringify({ proposal_id: "", title: "", body: "" }, null, 2)
  );
  const [createErr, setCreateErr] = useState<{ msg: string; details: any } | null>(null);
  const [createRes, setCreateRes] = useState<any>(null);

  const session = getSession();
  const acct = session ? normalizeAccount(session.account) : null;
  const canSign = acct ? !!getKeypair(acct)?.secretKeyB64 : false;

  async function load() {
    setErr(null);
    try {
      const r = await weall.proposals({ limit: 50 }, base);
      setItems((r as any).items || []);
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
    const q = (query || "").trim().toLowerCase();
    if (!q) return items;
    return items.filter((p) => {
      const id = String(p?.id || "").toLowerCase();
      const title = String(p?.title || "").toLowerCase();
      return id.includes(q) || title.includes(q);
    });
  }, [items, query]);

  async function createProposal() {
    setCreateErr(null);
    setCreateRes(null);

    try {
      const s = getSession();
      if (!s) throw new Error("not_logged_in");
      const a = normalizeAccount(s.account);
      const kp = getKeypair(a);
      if (!kp?.secretKeyB64) throw new Error("no_local_key_for_account");

      let payload: any;
      try {
        payload = JSON.parse(payloadJson || "{}");
      } catch {
        throw new Error("invalid_payload_json");
      }

      const r = await submitSignedTx({
        account: a,
        tx_type: txType.trim(),
        payload,
        parent: null,
        base,
      });

      setCreateRes(r);
      await load();
    } catch (e: any) {
      setCreateErr(prettyErr(e));
      setCreateRes(e?.data || null);
    }
  }

  return (
    <div style={{ maxWidth: 980, margin: "0 auto" }}>
      <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
        <button onClick={() => nav("/home")}>← Home</button>
        <h2 style={{ margin: 0 }}>Proposals</h2>
        <button onClick={load}>Refresh</button>
        <div style={{ flex: 1 }} />
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search by id/title..."
          style={{ padding: 8, borderRadius: 8, border: "1px solid #ccc", minWidth: 240 }}
        />
      </div>

      <div style={{ marginTop: 10 }}>
        <ErrorBanner
          message={err?.msg}
          details={err?.details}
          onRetry={load}
          onDismiss={() => setErr(null)}
        />
      </div>

      <div style={{ background: "#fff", border: "1px solid #ddd", borderRadius: 12, padding: 14, marginTop: 12 }}>
        <div style={{ fontWeight: 800, marginBottom: 6 }}>Create proposal (signed tx)</div>

        {!acct ? (
          <div style={{ opacity: 0.75 }}>
            You’re not logged in. Go to <button onClick={() => nav("/poh")}>PoH</button> to bootstrap keys + session.
          </div>
        ) : !canSign ? (
          <div style={{ opacity: 0.75 }}>
            Logged in as <b>{acct}</b>, but you have <b>no local secret key</b> for signing. (Recovery-mode session)
          </div>
        ) : (
          <div style={{ opacity: 0.75 }}>
            Logged in as <b>{acct}</b> — ready to sign.
          </div>
        )}

        <div style={{ marginTop: 10, display: "grid", gridTemplateColumns: "180px 1fr", gap: 8, alignItems: "center" }}>
          <div>tx_type</div>
          <input
            value={txType}
            onChange={(e) => setTxType(e.target.value)}
            style={{ padding: 8, fontFamily: "monospace" }}
          />
        </div>

        <div style={{ marginTop: 10 }}>
          <div style={{ fontWeight: 700, marginBottom: 6 }}>payload (JSON)</div>
          <textarea
            value={payloadJson}
            onChange={(e) => setPayloadJson(e.target.value)}
            rows={10}
            style={{ width: "100%", fontFamily: "monospace", fontSize: 12, padding: 10 }}
          />
        </div>

        <div style={{ display: "flex", gap: 8, marginTop: 10, flexWrap: "wrap" }}>
          <button onClick={createProposal} disabled={!acct || !canSign}>
            Sign + submit
          </button>
          <button onClick={() => setPayloadJson(JSON.stringify({ proposal_id: "", title: "", body: "" }, null, 2))}>
            Reset payload
          </button>
        </div>

        <div style={{ marginTop: 10 }}>
          <ErrorBanner
            message={createErr?.msg}
            details={createErr?.details}
            onDismiss={() => setCreateErr(null)}
          />
        </div>

        {createRes ? (
          <div style={{ marginTop: 10 }}>
            <div style={{ fontWeight: 700, marginBottom: 6 }}>Result</div>
            <pre style={{ margin: 0, whiteSpace: "pre-wrap" }}>{JSON.stringify(createRes, null, 2)}</pre>
          </div>
        ) : null}
      </div>

      <div style={{ marginTop: 12 }}>
        <div style={{ display: "flex", gap: 10, alignItems: "baseline", flexWrap: "wrap" }}>
          <h3 style={{ margin: 0 }}>List</h3>
          <span style={{ opacity: 0.7 }}>({items.length})</span>
        </div>

        <div style={{ marginTop: 10, display: "grid", gap: 10 }}>
          {!filtered.length ? (
            <div style={{ opacity: 0.7 }}>(none)</div>
          ) : (
            filtered.map((p) => <ProposalCard key={p.id} p={p} />)
          )}
        </div>
      </div>
    </div>
  );
}

function ProposalCard({ p }: { p: any }) {
  const id = String(p?.id || "");
  const title = p?.title || id || "(proposal)";
  const status = p?.status ? String(p.status) : "";

  return (
    <div style={{ background: "#fff", border: "1px solid #ddd", borderRadius: 12, padding: 14 }}>
      <div style={{ display: "flex", gap: 10, flexWrap: "wrap", alignItems: "baseline" }}>
        <button onClick={() => nav(`/proposal/${encodeURIComponent(id)}`)} style={{ fontWeight: 800, fontSize: 16 }}>
          {String(title)}
        </button>
        <span style={{ opacity: 0.65, fontFamily: "monospace", fontSize: 12 }}>{id}</span>
        {status ? <span style={{ opacity: 0.8 }}>• {status}</span> : null}
      </div>

      {p?.body ? <div style={{ marginTop: 8, whiteSpace: "pre-wrap" }}>{String(p.body).slice(0, 360)}{String(p.body).length > 360 ? "…" : ""}</div> : null}
    </div>
  );
}
