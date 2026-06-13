import React, { useEffect, useMemo, useState } from "react";

import { getApiBaseUrl, weall } from "../api/weall";
import ErrorBanner from "../components/ErrorBanner";
import NodeConnectionPanel from "../components/NodeConnectionPanel";
import { getAuthHeaders, getSession } from "../auth/session";
import { normalizeAccount } from "../auth/keys";
import { nav } from "../lib/router";

type LoadState = "idle" | "loading" | "loaded" | "error";

type StorageContributionPreference = {
  enabled: boolean;
  paused: boolean;
  quotaGb: string;
  nodeLabel: string;
  updatedAtMs: number;
};

const STORAGE_PREF_KEY = "weall.node.storageContribution.v1";
const DEFAULT_STORAGE_PREF: StorageContributionPreference = {
  enabled: false,
  paused: false,
  quotaGb: "100",
  nodeLabel: "Primary local node",
  updatedAtMs: 0,
};

function asRecord(value: unknown): Record<string, any> {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, any>) : {};
}

function asArray(value: unknown): any[] {
  return Array.isArray(value) ? value : [];
}

function num(value: unknown, fallback = 0): number {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function str(value: unknown, fallback = ""): string {
  const out = String(value ?? "").trim();
  return out || fallback;
}

function formatBytes(value: unknown): string {
  const n = num(value, 0);
  if (n <= 0) return "—";
  const units = ["B", "KB", "MB", "GB", "TB", "PB"];
  let v = n;
  let idx = 0;
  while (v >= 1024 && idx < units.length - 1) {
    v /= 1024;
    idx += 1;
  }
  return `${v >= 10 || idx === 0 ? v.toFixed(0) : v.toFixed(1)} ${units[idx]}`;
}

function compact(value: unknown): string {
  const raw = str(value, "—");
  if (raw === "—" || raw.length <= 18) return raw;
  return `${raw.slice(0, 10)}…${raw.slice(-6)}`;
}

function statusLabel(value: unknown, fallback = "Unknown"): string {
  const raw = str(value, fallback);
  return raw.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

function statusClass(okish: boolean, warn = false): string {
  if (okish) return "statusPill ok";
  if (warn) return "statusPill warn";
  return "statusPill";
}

function loadStoragePreference(): StorageContributionPreference {
  try {
    const raw = localStorage.getItem(STORAGE_PREF_KEY);
    if (!raw) return { ...DEFAULT_STORAGE_PREF };
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return { ...DEFAULT_STORAGE_PREF };
    return {
      enabled: parsed.enabled === true,
      paused: parsed.paused === true,
      quotaGb: str(parsed.quotaGb, DEFAULT_STORAGE_PREF.quotaGb),
      nodeLabel: str(parsed.nodeLabel, DEFAULT_STORAGE_PREF.nodeLabel),
      updatedAtMs: num(parsed.updatedAtMs, 0),
    };
  } catch {
    return { ...DEFAULT_STORAGE_PREF };
  }
}

function saveStoragePreference(next: StorageContributionPreference): void {
  localStorage.setItem(STORAGE_PREF_KEY, JSON.stringify(next));
}

function storagePreferenceError(pref: StorageContributionPreference): string {
  if (!pref.enabled) return "";
  const quota = Number(pref.quotaGb);
  if (!Number.isFinite(quota) || quota <= 0) return "Enter a storage quota above 0 GB before offering storage.";
  if (quota > 10_000) return "Quota is capped at 10,000 GB in the browser control surface to avoid accidental overclaims.";
  return "";
}

function StatCard({ label, value, note, ok, warn }: { label: string; value: string; note: string; ok?: boolean; warn?: boolean }): JSX.Element {
  return (
    <article className="summaryCard">
      <div className="summaryCardLabel">{label}</div>
      <div className="summaryCardValue">{value}</div>
      <div className="summaryCardText">{note}</div>
      <div className="buttonRow">
        <span className={statusClass(!!ok, !!warn)}>{ok ? "Ready" : warn ? "Needs attention" : "Observed"}</span>
      </div>
    </article>
  );
}

function DetailRow({ label, value, ok, warn }: { label: string; value: React.ReactNode; ok?: boolean; warn?: boolean }): JSX.Element {
  return (
    <div className="progressRow">
      <span>{label}</span>
      <span className={statusClass(!!ok, !!warn)}>{value}</span>
    </div>
  );
}

export default function NodeDashboard(): JSX.Element {
  const base = useMemo(() => getApiBaseUrl(), []);
  const session = getSession();
  const account = session ? normalizeAccount(session.account) : "";
  const headers = account ? getAuthHeaders(account) : undefined;

  const [loadState, setLoadState] = useState<LoadState>("idle");
  const [error, setError] = useState<{ msg: string; details: unknown } | null>(null);
  const [data, setData] = useState<Record<string, any>>({});
  const [pref, setPref] = useState<StorageContributionPreference>(() => loadStoragePreference());
  const [storageEstimate, setStorageEstimate] = useState<StorageEstimate | null>(null);
  const [prefSaved, setPrefSaved] = useState<string>("");

  async function load(): Promise<void> {
    setLoadState("loading");
    setError(null);
    const calls: Record<string, Promise<any>> = {
      status: weall.status(base),
      readyz: weall.readyz(base),
      operator: weall.operatorStatus(base),
      consensus: weall.consensusStatus(base),
      mempool: weall.mempoolStatus(base),
      storage: weall.storageIpfsOps(base),
      chainHead: weall.chainHead(base),
      chainIdentity: weall.chainIdentity(base),
      launchMatrix: weall.launchMatrix(base),
      testnetCapabilities: weall.testnetCapabilities(base),
      blockProduction: weall.blockProductionReadiness(base),
      helperReadiness: weall.helperReadiness(base),
      netSelf: weall.netSelf(base),
    };
    if (account) {
      calls.accountOperator = weall.accountOperatorStatus(account, base, headers);
    }

    const entries = Object.entries(calls);
    const settled = await Promise.allSettled(entries.map(([, promise]) => promise));
    const next: Record<string, any> = {};
    const failures: Array<{ key: string; message: string }> = [];
    settled.forEach((res, index) => {
      const key = entries[index][0];
      if (res.status === "fulfilled") {
        next[key] = res.value;
      } else {
        failures.push({ key, message: res.reason?.message || String(res.reason || "failed") });
      }
    });

    setData(next);
    setLoadState(failures.length ? "error" : "loaded");
    if (failures.length) {
      setError({
        msg: `Some node surfaces did not load: ${failures.map((f) => f.key).join(", ")}`,
        details: failures,
      });
    }
  }

  useEffect(() => {
    void load();
  }, [base, account]);

  useEffect(() => {
    if (!navigator.storage?.estimate) return;
    void navigator.storage.estimate().then((estimate) => setStorageEstimate(estimate)).catch(() => setStorageEstimate(null));
  }, []);

  const status = asRecord(data.status);
  const readyz = asRecord(data.readyz);
  const operator = asRecord(data.operator);
  const operatorInner = asRecord(operator.operator);
  const consensus = asRecord(data.consensus);
  const mempool = asRecord(data.mempool);
  const storage = asRecord(data.storage);
  const chainHead = asRecord(data.chainHead);
  const chainIdentity = asRecord(data.chainIdentity);
  const launchMatrix = asRecord(data.launchMatrix);
  const testnetCapabilities = asRecord(data.testnetCapabilities);
  const helperReadiness = asRecord(data.helperReadiness);
  const netSelf = asRecord(data.netSelf);
  const accountOperator = asRecord(asRecord(data.accountOperator).node_operator);
  const accountStorage = asRecord(accountOperator.storage);
  const accountValidator = asRecord(accountOperator.validator);

  const chainId = str(status.chain_id || chainIdentity.chain_id, "—");
  const height = num(status.height ?? chainHead.height ?? chainIdentity.height, 0);
  const stateRoot = str(chainHead.state_root || chainIdentity.state_root || chainIdentity.snapshot_anchor, "");
  const mempoolSize = num(mempool.size ?? mempool.mempool_size ?? operator.mempool_size, 0);
  const peerCounts = asRecord(asRecord(operator.net).peer_counts);
  const peerCount = num(peerCounts.connected_peers ?? peerCounts.connected ?? peerCounts.total ?? asArray(netSelf.peers).length, 0);
  const blockLoop = asRecord(operator.block_loop);
  const profileCompatibility = asRecord(operator.profile_compatibility || operatorInner.profile_compatibility);
  const authorityContract = asRecord(operatorInner.authority_contract);
  const helperSummary = asRecord(asRecord(operator.helper).helper_summary || operatorInner.helper_summary || helperReadiness.summary);
  const helperEffective = authorityContract.helper_effective === true || asRecord(operator.consensus).helper_effective === true;
  const validatorEffective = authorityContract.validator_effective === true || asRecord(operator.consensus).validator_effective === true;
  const observerMode = asRecord(operatorInner.startup_posture).observer_mode === true;
  const storageDurability = asRecord(storage.durability);
  const pinStatusCounts = asRecord(storage.pin_status_counts);
  const enabledStorageOperators = asArray(storage.enabled_operators);
  const accountStorageDetails = asRecord(accountStorage.details);
  const declaredCapacity = num(accountStorageDetails.declared_capacity_bytes, 0);
  const provenCapacity = num(accountStorageDetails.proven_capacity_bytes, 0);
  const storageOptedIn = accountStorage.active === true || str(accountStorage.status).length > 0 && str(accountStorage.status) !== "not_opted_in";
  const validatorOptedIn = accountValidator.active === true || str(accountValidator.status).length > 0 && str(accountValidator.status) !== "not_opted_in";
  const launchPhase = str(launchMatrix.phase || testnetCapabilities.phase || status.mode, "controlled/local");
  const publicBetaClaimed = testnetCapabilities.public_beta_ready_claimed === true;
  const prefError = storagePreferenceError(pref);
  const browserStorageUsage = storageEstimate ? formatBytes(storageEstimate.usage) : "—";
  const browserStorageQuota = storageEstimate ? formatBytes(storageEstimate.quota) : "—";

  function updatePref(partial: Partial<StorageContributionPreference>): void {
    setPref((current) => ({ ...current, ...partial }));
    setPrefSaved("");
  }

  function persistPref(): void {
    const next = { ...pref, updatedAtMs: Date.now() };
    const err = storagePreferenceError(next);
    if (err) {
      setPrefSaved(err);
      return;
    }
    saveStoragePreference(next);
    setPref(next);
    setPrefSaved("Saved local storage contribution preference. This does not submit or change protocol responsibility by itself.");
  }

  return (
    <div className="pageStack pageNarrow nodeDashboardPage">
      <section className="card heroCard">
        <div className="cardBody heroBody compactHero">
          <div className="heroSplit">
            <div>
              <div className="eyebrow">Personal node</div>
              <h1 className="heroTitle heroTitleSm">Local node control surface</h1>
              <p className="heroText">
                View your local backend, chain identity, sync posture, validator/helper/storage readiness, and safe local storage contribution preferences from one normal-user dashboard.
              </p>
            </div>
            <div className="heroInfoPanel" aria-live="polite">
              <div className="heroInfoTitle">Connection</div>
              <div className="heroInfoList">
                <span className={statusClass(loadState === "loaded", loadState === "error")}>{loadState === "loading" ? "Loading" : loadState === "error" ? "Partial" : "Loaded"}</span>
                <span className="statusPill">{base || "/"}</span>
              </div>
            </div>
          </div>
          <div className="heroActions">
            <button className="btn btnPrimary" onClick={() => void load()} disabled={loadState === "loading"}>
              {loadState === "loading" ? "Refreshing…" : "Refresh node status"}
            </button>
            <button className="btn" onClick={() => nav("/settings")}>Change backend URL</button>
            <button className="btn" onClick={() => nav("/profile")}>Manage account operator setup</button>
          </div>
        </div>
      </section>

      <ErrorBanner message={error?.msg} details={error?.details} onRetry={() => void load()} onDismiss={() => setError(null)} />

      <section className="summaryCardGrid" aria-label="Node status summary">
        <StatCard label="Node health" value={readyz.ready === false ? "Degraded" : status.ok === true ? "Online" : "Unknown"} note="Backend status and readiness are read from the connected node." ok={status.ok === true && readyz.ready !== false} warn={readyz.ready === false || loadState === "error"} />
        <StatCard label="Sync height" value={String(height || "0")} note={`Tip ${compact(status.tip || chainHead.tip || chainIdentity.tip_hash)}`} ok={height >= 0 && status.ok === true} />
        <StatCard label="Mempool" value={`${mempoolSize} tx`} note="Pending transaction pressure exposed by the node status surface." ok={mempoolSize === 0} warn={mempoolSize > 0} />
        <StatCard label="Launch boundary" value={statusLabel(launchPhase)} note={publicBetaClaimed ? "Unexpected public beta claim detected." : "This surface does not claim public beta or production readiness."} ok={!publicBetaClaimed} warn={publicBetaClaimed} />
      </section>

      <NodeConnectionPanel compact={false} />

      <section className="grid2">
        <article className="card">
          <div className="cardBody formStack">
            <div className="sectionHead">
              <div>
                <div className="eyebrow">Chain identity</div>
                <h2 className="cardTitle">Network and sync anchor</h2>
              </div>
              <span className={statusClass(!!chainId && chainId !== "—")}>{chainId !== "—" ? "Pinned" : "Missing"}</span>
            </div>
            <div className="progressList">
              <DetailRow label="Chain ID" value={<span className="mono">{chainId}</span>} ok={chainId !== "—"} />
              <DetailRow label="Genesis hash" value={<span className="mono">{compact(chainIdentity.genesis_hash)}</span>} ok={!!chainIdentity.genesis_hash} />
              <DetailRow label="Manifest" value={asRecord(chainIdentity.chain_manifest).enabled ? "Enabled" : "Not enabled"} ok={asRecord(chainIdentity.chain_manifest).enabled === true} warn={asArray(asRecord(chainIdentity.chain_manifest).issues).length > 0} />
              <DetailRow label="State root" value={<span className="mono">{compact(stateRoot)}</span>} ok={!!stateRoot} />
              <DetailRow label="Schema" value={<span className="mono">{str(status.schema_version || chainIdentity.schema_version, "—")}</span>} ok={!!status.schema_version || !!chainIdentity.schema_version} />
              <DetailRow label="Protocol profile" value={<span className="mono">{compact(status.protocol_profile_hash || chainIdentity.protocol_profile_hash)}</span>} ok={!!status.protocol_profile_hash || !!chainIdentity.protocol_profile_hash} />
            </div>
          </div>
        </article>

        <article className="card">
          <div className="cardBody formStack">
            <div className="sectionHead">
              <div>
                <div className="eyebrow">Runtime posture</div>
                <h2 className="cardTitle">Local node responsibilities</h2>
              </div>
              <span className={statusClass(profileCompatibility.authority_ready === true, profileCompatibility.authority_ready === false)}>Authority contract</span>
            </div>
            <div className="progressList">
              <DetailRow label="Runtime mode" value={statusLabel(status.mode || profileCompatibility.effective_state || "unknown")} ok={status.ok === true} />
              <DetailRow label="Observer mode" value={observerMode ? "Observer" : "Not observer-only"} ok={!observerMode} warn={observerMode} />
              <DetailRow label="Validator readiness" value={validatorEffective || validatorOptedIn ? (validatorEffective ? "Effective" : "Opted in") : "Not active"} ok={validatorEffective} warn={validatorOptedIn && !validatorEffective} />
              <DetailRow label="Helper readiness" value={helperEffective ? "Effective" : statusLabel(helperSummary.status || helperReadiness.status || "Not active")} ok={helperEffective || helperReadiness.ready === true} warn={helperReadiness.ready === false} />
              <DetailRow label="Block production" value={blockLoop.running === true ? "Running" : blockLoop.unhealthy === true ? "Unhealthy" : "Not running"} ok={blockLoop.running === true && blockLoop.unhealthy !== true} warn={blockLoop.unhealthy === true} />
              <DetailRow label="Peer count" value={String(peerCount)} ok={peerCount > 0} warn={peerCount === 0} />
            </div>
          </div>
        </article>
      </section>

      <section className="card" aria-labelledby="storage-control-heading">
        <div className="cardBody formStack">
          <div className="sectionHead">
            <div>
              <div className="eyebrow">IPFS / storage contribution</div>
              <h2 id="storage-control-heading" className="cardTitle">Storage operator control surface</h2>
              <p className="cardDesc">
                Use this panel to inspect storage readiness and set a local contribution preference. Protocol allocation still requires signed account operator setup and capacity proof; the browser cannot grant storage authority by itself.
              </p>
            </div>
            <span className={statusClass(storage.ok === true, storage.ok !== true)}>Read-only protocol status</span>
          </div>

          <div className="summaryCardGrid">
            <StatCard label="Storage operators" value={String(num(storage.enabled_operator_count, enabledStorageOperators.length))} note="Operators enabled in the current read model." ok={num(storage.enabled_operator_count, enabledStorageOperators.length) > 0} />
            <StatCard label="Durable CIDs" value={`${num(storageDurability.cids_durable, 0)} / ${num(storageDurability.cids_total, 0)}`} note="Durability is based on the configured replication factor and pin confirmations." ok={num(storageDurability.cids_pending, 0) === 0 && num(storageDurability.cids_total, 0) > 0} warn={num(storageDurability.cids_pending, 0) > 0} />
            <StatCard label="Pinned / queued" value={`${num(pinStatusCounts.pinned || pinStatusCounts.ok, 0)} / ${num(pinStatusCounts.pending || pinStatusCounts.queued, 0)}`} note="Pin status counts are reported by the node, when available." ok={num(pinStatusCounts.pending || pinStatusCounts.queued, 0) === 0} warn={num(pinStatusCounts.pending || pinStatusCounts.queued, 0) > 0} />
            <StatCard label="Account storage" value={storageOptedIn ? "Opted in" : "Not opted in"} note={`Declared ${formatBytes(declaredCapacity)} · Proven ${formatBytes(provenCapacity)}`} ok={storageOptedIn && provenCapacity > 0} warn={storageOptedIn && provenCapacity <= 0} />
          </div>

          <div className="grid2">
            <div className="formStack">
              <label>
                <div className="eyebrow">Node label</div>
                <input
                  aria-describedby="node-label-help"
                  value={pref.nodeLabel}
                  onChange={(event) => updatePref({ nodeLabel: event.target.value })}
                  placeholder="Primary local node"
                />
              </label>
              <div id="node-label-help" className="cardDesc">This label is local to this browser and helps you identify the node you intend to operate.</div>

              <label>
                <div className="eyebrow">Offered storage quota in GB</div>
                <input
                  aria-describedby="storage-quota-help"
                  inputMode="decimal"
                  value={pref.quotaGb}
                  onChange={(event) => updatePref({ quotaGb: event.target.value })}
                  placeholder="100"
                />
              </label>
              <div id="storage-quota-help" className="cardDesc">
                This local quota is an operator preference. It is not a protocol claim until you submit the signed storage responsibility action and pass capacity proof.
              </div>

              <div className="buttonRow buttonRowWide">
                <button className={pref.enabled ? "btn btnPrimary" : "btn"} onClick={() => updatePref({ enabled: !pref.enabled, paused: pref.enabled ? pref.paused : false })}>
                  {pref.enabled ? "Disable local storage intent" : "Offer storage from this node"}
                </button>
                <button className="btn" disabled={!pref.enabled} onClick={() => updatePref({ paused: !pref.paused })}>
                  {pref.paused ? "Resume storage contribution" : "Pause storage contribution"}
                </button>
                <button className="btn" onClick={persistPref}>Save local preference</button>
              </div>
              {prefError ? <div className="calloutWarn" role="alert">{prefError}</div> : null}
              {prefSaved ? <div className={prefSaved.startsWith("Saved") ? "calloutInfo" : "calloutWarn"} role="status">{prefSaved}</div> : null}
            </div>

            <div className="formStack">
              <div className="infoCard compact">
                <div className="feedMediaTitle">Local preference status</div>
                <div className="progressList">
                  <DetailRow label="Contribution intent" value={pref.enabled ? "Enabled" : "Disabled"} ok={pref.enabled} />
                  <DetailRow label="Pause state" value={pref.paused ? "Paused" : "Active if enabled"} ok={pref.enabled && !pref.paused} warn={pref.enabled && pref.paused} />
                  <DetailRow label="Saved quota" value={`${pref.quotaGb || "0"} GB`} ok={!storagePreferenceError(pref)} warn={!!storagePreferenceError(pref)} />
                  <DetailRow label="Browser storage estimate" value={`${browserStorageUsage} used / ${browserStorageQuota} quota`} />
                </div>
              </div>
              <div className="calloutInfo">
                <strong>Safety boundary:</strong> Pause/resume and quota here are local controls for your webfront. To change committed protocol responsibility, use account operator setup and submit signed storage transactions after reviewing capacity proof requirements.
              </div>
              <div className="buttonRow">
                <button className="btn" onClick={() => nav("/profile")}>Open account operator setup</button>
                <button className="btn" onClick={() => nav("/settings")}>Review API endpoint</button>
              </div>
            </div>
          </div>

          <details className="detailsPanel">
            <summary>Raw storage/IPFS diagnostics</summary>
            <pre className="codePanel mono">{JSON.stringify(storage, null, 2)}</pre>
          </details>
        </div>
      </section>

      <section className="card">
        <div className="cardBody formStack">
          <div className="sectionHead">
            <div>
              <div className="eyebrow">Operator diagnostics</div>
              <h2 className="cardTitle">Plain-language readiness boundaries</h2>
            </div>
          </div>
          <div className="infoGrid">
            <div className="infoCard compact">
              <div className="infoCardHeader"><span className="statusPill">Controlled</span><strong>Public readiness</strong></div>
              <div className="infoCardText">This dashboard never claims public beta, public validator, or production readiness. It displays readiness boundaries reported by the node.</div>
            </div>
            <div className="infoCard compact">
              <div className="infoCardHeader"><span className="statusPill">Diagnostics</span><strong>Missing surfaces are visible</strong></div>
              <div className="infoCardText">If a route is offline, stale, or missing, the partial-load warning stays visible instead of silently hiding the failure.</div>
            </div>
            <div className="infoCard compact">
              <div className="infoCardHeader"><span className="statusPill">Authority</span><strong>Frontend cannot grant roles</strong></div>
              <div className="infoCardText">Validator, helper, and storage responsibilities must come from committed protocol state and signed transactions.</div>
            </div>
          </div>
          <details className="detailsPanel">
            <summary>Raw node diagnostics</summary>
            <pre className="codePanel mono">{JSON.stringify(data, null, 2)}</pre>
          </details>
        </div>
      </section>
    </div>
  );
}
