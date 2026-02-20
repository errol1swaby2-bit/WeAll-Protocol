import React from "react";
import { nav } from "../lib/router";
import { config } from "../lib/config";

export default function Home(): JSX.Element {
  return (
    <div style={{ maxWidth: 980, margin: "0 auto" }}>
      <h1 style={{ marginTop: 0 }}>
        {config.appName} — {config.envLabel}
      </h1>

      <div style={{ opacity: 0.8, marginBottom: 14 }}>
        Minimal UI for core protocol flows. Production mode hides dev-only tooling and blocks unsafe writes on canon drift.
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
        <Card title="Proof of Humanity" desc="Email verification, keys bootstrap / recovery, tier status">
          <button onClick={() => nav("/poh")}>Open PoH</button>
        </Card>

        <Card title="Feed" desc="Browse content, post (Tier 3), comment/react (Tier 2)">
          <button onClick={() => nav("/feed")}>Open Feed</button>
        </Card>

        <Card title="Groups" desc="Browse groups and open group detail pages">
          <button onClick={() => nav("/groups")}>Open Groups</button>
        </Card>

        <Card title="Governance" desc="Browse proposals, open proposal detail, sign + submit txs">
          <button onClick={() => nav("/proposals")}>Open Proposals</button>
        </Card>

        {config.enableDevTools ? (
          <Card title="Tools" desc="Developer utilities (status, snapshot, produce blocks)">
            <button onClick={() => nav("/tools")}>Open Tools</button>
          </Card>
        ) : (
          <Card title="Tools" desc="Disabled in production builds">
            <button onClick={() => nav("/tools")} disabled style={{ opacity: 0.6 }}>
              Tools disabled
            </button>
          </Card>
        )}

        <Card title="Account" desc="Open an account page">
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            <button onClick={() => nav("/account/@satoshi")}>@satoshi</button>
            <button onClick={() => nav("/account/@alice")}>@alice</button>
          </div>
        </Card>
      </div>
    </div>
  );
}

function Card({ title, desc, children }: { title: string; desc: string; children: React.ReactNode }) {
  return (
    <div style={{ background: "#fff", border: "1px solid #ddd", borderRadius: 12, padding: 14 }}>
      <div style={{ fontWeight: 800, fontSize: 16 }}>{title}</div>
      <div style={{ opacity: 0.75, marginTop: 6, marginBottom: 10 }}>{desc}</div>
      <div>{children}</div>
    </div>
  );
}
