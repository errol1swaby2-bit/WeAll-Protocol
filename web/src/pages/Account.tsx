// web/src/pages/Account.tsx
import React, { useEffect, useMemo, useState } from "react";

import { getApiBaseUrl, weall } from "../api/weall";
import ErrorBanner from "../components/ErrorBanner";
import FeedView from "../components/FeedView";
import { nav } from "../lib/router";
import { normalizeAccount } from "../auth/keys";

function prettyErr(e: any): { msg: string; details: any } {
  const details = e?.data || e;
  const msg = details?.message || e?.message || "error";
  return { msg, details };
}

export default function Account({ account }: { account: string }): JSX.Element {
  const base = useMemo(() => getApiBaseUrl(), []);
  const acct = useMemo(() => normalizeAccount(account), [account]);

  const [poh, setPoh] = useState<any>(null);
  const [nonce, setNonce] = useState<any>(null);
  const [acctView, setAcctView] = useState<any>(null);
  const [err, setErr] = useState<{ msg: string; details: any } | null>(null);

  async function load() {
    setErr(null);
    try {
      const [p, n, a] = await Promise.all([weall.pohState(acct, base), weall.accountNonce(acct, base), weall.account(acct, base)]);
      setPoh(p);
      setNonce(n);
      setAcctView(a);
    } catch (e: any) {
      setErr(prettyErr(e));
      setPoh(null);
      setNonce(null);
      setAcctView(null);
    }
  }

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [acct]);

  const tier = Number(poh?.tier ?? 0);

  return (
    <div style={{ maxWidth: 980, margin: "0 auto" }}>
      <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
        <button onClick={() => nav("/home")}>← Home</button>
        <h2 style={{ margin: 0 }}>{acct}</h2>
        <button onClick={load}>Refresh</button>
      </div>

      <div style={{ marginTop: 10 }}>
        <ErrorBanner message={err?.msg} details={err?.details} onRetry={load} onDismiss={() => setErr(null)} />
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginTop: 12 }}>
        <div style={{ background: "#fff", border: "1px solid #ddd", borderRadius: 12, padding: 14 }}>
          <div style={{ fontWeight: 800, marginBottom: 8 }}>PoH</div>
          <div style={{ fontSize: 14 }}>
            Tier: <b>{tier}</b>
          </div>
          <pre style={{ marginTop: 10, whiteSpace: "pre-wrap" }}>{JSON.stringify(poh, null, 2)}</pre>
        </div>

        <div style={{ background: "#fff", border: "1px solid #ddd", borderRadius: 12, padding: 14 }}>
          <div style={{ fontWeight: 800, marginBottom: 8 }}>Nonce</div>
          <div style={{ fontSize: 14 }}>
            Current: <b>{String(nonce?.nonce ?? "(unknown)")}</b>
          </div>
          <pre style={{ marginTop: 10, whiteSpace: "pre-wrap" }}>{JSON.stringify(nonce, null, 2)}</pre>
        </div>
      </div>

      <div style={{ marginTop: 12, background: "#fff", border: "1px solid #ddd", borderRadius: 12, padding: 14 }}>
        <div style={{ fontWeight: 800, marginBottom: 8 }}>Account state</div>
        <pre style={{ margin: 0, whiteSpace: "pre-wrap" }}>{JSON.stringify(acctView?.state ?? null, null, 2)}</pre>
      </div>

      <div style={{ marginTop: 12, background: "#fff", border: "1px solid #ddd", borderRadius: 12, padding: 14 }}>
        <div style={{ fontWeight: 800, marginBottom: 8 }}>Quick links</div>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          <button onClick={() => nav("/feed")}>Feed</button>
          <button onClick={() => nav("/groups")}>Groups</button>
          <button onClick={() => nav("/proposals")}>Proposals</button>
          <button onClick={() => nav("/poh")}>PoH</button>
        </div>
      </div>

      <div style={{ marginTop: 12 }}>
        <FeedView
          base={base}
          title="Posts by account"
          scope={{ kind: "account", account: acct }}
          allowCompose={false}
          defaultFilters={{ author: acct }}
          defaultSort="newest"
        />
      </div>

      <div style={{ marginTop: 12 }}>
        <FeedView
          base={base}
          title="Private posts by account"
          scope={{ kind: "private", account: acct }}
          allowCompose={false}
          defaultFilters={{ visibility: "private", author: acct }}
          defaultSort="newest"
        />
      </div>
    </div>
  );
}
