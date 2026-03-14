import React, { useEffect, useMemo, useState } from "react";

import { getApiBaseUrl, weall } from "../api/weall";
import ErrorBanner from "../components/ErrorBanner";
import { getKeypair, getSession } from "../auth/session";
import { normalizeAccount } from "../auth/keys";
import { useAccount } from "../context/AccountContext";
import {
  getBootstrapTier3Enabled,
  getDurableOperatorTarget,
  getMediaReplicationTarget,
  getTier2VideoUploadEnabled,
} from "../lib/capabilities";
import { nav } from "../lib/router";

function prettyErr(e: any): { msg: string; details: any } {
  const details = e?.body || e?.data || e;
  const msg = details?.message || e?.error?.message || e?.message || "error";
  return { msg, details };
}

function StatusPill({
  ok,
  label,
}: {
  ok: boolean;
  label: string;
}): JSX.Element {
  return <span className={`statusPill ${ok ? "ok" : ""}`}>{label}</span>;
}

function JsonCard({
  title,
  value,
}: {
  title: string;
  value: any;
}): JSX.Element {
  return (
    <article className="card">
      <div className="cardBody formStack">
        <div className="sectionHead">
          <div>
            <div className="eyebrow">Diagnostics</div>
            <h2 className="cardTitle">{title}</h2>
          </div>
        </div>
        <pre className="codePanel mono">{JSON.stringify(value, null, 2)}</pre>
      </div>
    </article>
  );
}

export default function Tools(): JSX.Element {
  const base = useMemo(() => getApiBaseUrl(), []);
  const session = getSession();
  const acct = session ? normalizeAccount(session.account) : "";
  const kp = acct ? getKeypair(acct) : null;
  const { state: sharedAccount, refresh: refreshAccount } = useAccount();

  const [statusRes, setStatusRes] = useState<any>(null);
  const [readyzRes, setReadyzRes] = useState<any>(null);
  const [feedRes, setFeedRes] = useState<any>(null);
  const [sampleMediaCid, setSampleMediaCid] = useState<string>("");
  const [mediaStatusRes, setMediaStatusRes] = useState<any>(null);
  const [err, setErr] = useState<{ msg: string; details: any } | null>(null);
  const [busy, setBusy] = useState(false);

  const tier2UploadEnabled = getTier2VideoUploadEnabled();
  const bootstrapTier3Enabled = getBootstrapTier3Enabled();
  const replicationTarget = getMediaReplicationTarget();
  const durableOperatorTarget = getDurableOperatorTarget();

  async function refreshAll(): Promise<void> {
    setBusy(true);
    setErr(null);
    try {
      const [status, readyz, feed] = await Promise.all([
        weall.status(base).catch((e: any) => ({ ok: false, error: prettyErr(e) })),
        weall.readyz(base).catch((e: any) => ({ ok: false, error: prettyErr(e) })),
        weall.feed({ limit: 5 }, base).catch((e: any) => ({ ok: false, error: prettyErr(e) })),
        refreshAccount().catch(() => undefined),
      ]);

      setStatusRes(status);
      setReadyzRes(readyz);
      setFeedRes(feed);
    } catch (e: any) {
      setErr(prettyErr(e));
    } finally {
      setBusy(false);
    }
  }

  async function loadMediaStatus(): Promise<void> {
    const cid = String(sampleMediaCid || "").trim();
    if (!cid) {
      setMediaStatusRes(null);
      return;
    }
    try {
      const r = await weall.mediaStatus(cid, base);
      setMediaStatusRes(r);
    } catch (e: any) {
      setErr(prettyErr(e));
      setMediaStatusRes(null);
    }
  }

  useEffect(() => {
    void refreshAll();
  }, [base]);

  const feedItems = Array.isArray(feedRes?.items) ? feedRes.items : [];
  const sharedTier = Number(sharedAccount?.poh_tier || 0);
  const sharedRep = Number(sharedAccount?.reputation || 0);

  return (
    <div className="pageStack">
      <section className="card heroCard">
        <div className="cardBody heroBody compactHero">
          <div className="heroSplit">
            <div>
              <div className="eyebrow">Diagnostics</div>
              <h1 className="heroTitle heroTitleSm">Live stack visibility</h1>
              <p className="heroText">
                Use this page to verify API health, readiness, feed access, account state,
                PoH feature flags, and media durability expectations from inside the client.
              </p>
            </div>

            <div className="heroInfoPanel">
              <div className="heroInfoTitle">Quick state</div>
              <div className="heroInfoList">
                <StatusPill ok={!!statusRes?.ok} label={statusRes?.ok ? "Status OK" : "Status pending"} />
                <StatusPill ok={!!readyzRes?.ok} label={readyzRes?.ok ? "Ready" : "Not ready"} />
                <StatusPill ok={!!acct} label={acct ? "Session present" : "No session"} />
                <StatusPill ok={!!kp} label={kp ? "Keypair present" : "No keypair"} />
              </div>
            </div>
          </div>

          <div className="heroActions">
            <button className="btn btnPrimary" onClick={() => void refreshAll()} disabled={busy}>
              {busy ? "Refreshing…" : "Refresh diagnostics"}
            </button>
            <button className="btn" onClick={() => nav("/poh")}>
              Open PoH
            </button>
            <button className="btn" onClick={() => nav("/post")}>
              Create post
            </button>
            <button className="btn" onClick={() => nav("/feed")}>
              Open feed
            </button>
          </div>
        </div>
      </section>

      <ErrorBanner
        message={err?.msg}
        details={err?.details}
        onRetry={() => void refreshAll()}
        onDismiss={() => setErr(null)}
      />

      <section className="grid2">
        <article className="card">
          <div className="cardBody formStack">
            <div className="sectionHead">
              <div>
                <div className="eyebrow">Deployment</div>
                <h2 className="cardTitle">Frontend capability flags</h2>
              </div>
            </div>

            <div className="progressList">
              <div className="progressRow">
                <span>Tier 2 video upload UI</span>
                <StatusPill ok={tier2UploadEnabled} label={tier2UploadEnabled ? "Enabled" : "Disabled"} />
              </div>
              <div className="progressRow">
                <span>Bootstrap Tier 3 controls</span>
                <StatusPill ok={bootstrapTier3Enabled} label={bootstrapTier3Enabled ? "Enabled" : "Disabled"} />
              </div>
              <div className="progressRow">
                <span>Replication target</span>
                <span className="statusPill">{replicationTarget}</span>
              </div>
              <div className="progressRow">
                <span>Durable operator target</span>
                <span className="statusPill">{durableOperatorTarget}</span>
              </div>
            </div>
          </div>
        </article>

        <article className="card">
          <div className="cardBody formStack">
            <div className="sectionHead">
              <div>
                <div className="eyebrow">Account</div>
                <h2 className="cardTitle">Shared account context</h2>
              </div>
            </div>

            <div className="statsGrid statsGridCompact">
              <div className="statCard">
                <span className="statLabel">Account</span>
                <span className="statValue mono">{sharedAccount?.account || acct || "None"}</span>
              </div>
              <div className="statCard">
                <span className="statLabel">PoH tier</span>
                <span className="statValue">{sharedTier}</span>
              </div>
              <div className="statCard">
                <span className="statLabel">Reputation</span>
                <span className="statValue">{sharedRep}</span>
              </div>
              <div className="statCard">
                <span className="statLabel">Account flags</span>
                <span className="statValue">
                  {sharedAccount?.banned ? "Banned" : sharedAccount?.locked ? "Locked" : "Normal"}
                </span>
              </div>
            </div>
          </div>
        </article>
      </section>

      <section className="grid3">
        <article className="card">
          <div className="cardBody formStack">
            <div className="sectionHead">
              <div>
                <div className="eyebrow">API</div>
                <h2 className="cardTitle">Status</h2>
              </div>
              <StatusPill ok={!!statusRes?.ok} label={statusRes?.ok ? "OK" : "Missing"} />
            </div>
            <div className="cardDesc">
              Chain ID: <span className="mono">{String(statusRes?.chain_id || "—")}</span>
            </div>
            <div className="cardDesc">
              Height: <span className="mono">{String(statusRes?.height ?? "—")}</span>
            </div>
          </div>
        </article>

        <article className="card">
          <div className="cardBody formStack">
            <div className="sectionHead">
              <div>
                <div className="eyebrow">API</div>
                <h2 className="cardTitle">Readyz</h2>
              </div>
              <StatusPill ok={!!readyzRes?.ok} label={readyzRes?.ok ? "Ready" : "Not ready"} />
            </div>
            <div className="cardDesc">
              Block loop: <span className="mono">{String(readyzRes?.block_loop ?? "—")}</span>
            </div>
            <div className="cardDesc">
              Net loop: <span className="mono">{String(readyzRes?.net_loop ?? "—")}</span>
            </div>
          </div>
        </article>

        <article className="card">
          <div className="cardBody formStack">
            <div className="sectionHead">
              <div>
                <div className="eyebrow">API</div>
                <h2 className="cardTitle">Feed reachability</h2>
              </div>
              <StatusPill
                ok={feedRes?.ok !== false}
                label={feedRes?.ok === false ? "Feed issue" : "Feed reachable"}
              />
            </div>
            <div className="cardDesc">
              Items returned: <span className="mono">{feedItems.length}</span>
            </div>
          </div>
        </article>
      </section>

      <section className="grid2">
        <article className="card">
          <div className="cardBody formStack">
            <div className="sectionHead">
              <div>
                <div className="eyebrow">IPFS</div>
                <h2 className="cardTitle">Media durability probe</h2>
              </div>
            </div>

            <label className="fieldLabel">
              CID
              <input
                value={sampleMediaCid}
                onChange={(e) => setSampleMediaCid(e.target.value)}
                placeholder="bafy..."
              />
            </label>

            <div className="buttonRow">
              <button className="btn btnPrimary" onClick={() => void loadMediaStatus()}>
                Check media status
              </button>
              <button className="btn" onClick={() => setMediaStatusRes(null)}>
                Clear
              </button>
            </div>

            {mediaStatusRes ? (
              <div className="progressList">
                <div className="progressRow">
                  <span>Durable</span>
                  <StatusPill
                    ok={!!mediaStatusRes?.durable}
                    label={mediaStatusRes?.durable ? "Yes" : "No"}
                  />
                </div>
                <div className="progressRow">
                  <span>Replication factor</span>
                  <span className="statusPill">
                    {String(mediaStatusRes?.replication_factor ?? "—")}
                  </span>
                </div>
                <div className="progressRow">
                  <span>Confirmed operators</span>
                  <span className="statusPill">
                    {String(mediaStatusRes?.ok_unique_ops ?? "—")}
                  </span>
                </div>
              </div>
            ) : (
              <div className="cardDesc">Enter a CID to inspect the durability view seen by the frontend.</div>
            )}
          </div>
        </article>

        <article className="card">
          <div className="cardBody formStack">
            <div className="sectionHead">
              <div>
                <div className="eyebrow">Quick links</div>
                <h2 className="cardTitle">Flow jump points</h2>
              </div>
            </div>

            <div className="buttonRow buttonRowWide">
              <button className="btn" onClick={() => nav("/settings")}>
                Settings
              </button>
              <button className="btn" onClick={() => nav("/poh")}>
                PoH
              </button>
              <button className="btn" onClick={() => nav("/post")}>
                Create Post
              </button>
              <button className="btn" onClick={() => nav("/juror")}>
                Juror
              </button>
              <button className="btn" onClick={() => nav("/proposals")}>
                Governance
              </button>
            </div>
          </div>
        </article>
      </section>

      <JsonCard title="GET /v1/status" value={statusRes} />
      <JsonCard title="GET /v1/readyz" value={readyzRes} />
      <JsonCard title="GET /v1/feed?limit=5" value={feedRes} />
      {mediaStatusRes ? <JsonCard title="GET /v1/media/status/{cid}" value={mediaStatusRes} /> : null}
    </div>
  );
}
