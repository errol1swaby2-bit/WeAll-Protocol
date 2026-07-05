import React, { useEffect, useMemo, useState } from "react";

import { getApiBaseUrl, weall } from "../api/weall";
import ErrorBanner from "../components/ErrorBanner";
import NodeConnectionPanel from "../components/NodeConnectionPanel";
import OperatorCommandWizard from "../components/OperatorCommandWizard";
import OperatorIncidentTimeline, { type OperatorIncidentItem } from "../components/OperatorIncidentTimeline";
import ValidatorReadinessWizard from "../components/ValidatorReadinessWizard";
import { getAuthHeaders, getSession } from "../auth/session";
import { normalizeAccount } from "../auth/keys";
import { nav } from "../lib/router";
// Operator wizard: Fix readiness blockers in order · Backend-derived

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
  const hasAccountSession = !!account;
  const accountOperatorSetupHref = account ? `/account/${encodeURIComponent(account)}?operator=1` : "/login";
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
      publicSeeds: weall.publicSeeds(base),
      publicValidators: weall.publicValidators(base),
      observerEdge: weall.observerEdgeStatus(base, headers),
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
  const protocolUpgradeLifecycle = asRecord(testnetCapabilities.protocol_upgrade_lifecycle);
  const governanceLifecycle = asRecord(testnetCapabilities.governance_lifecycle);
  const disputeLifecycle = asRecord(testnetCapabilities.dispute_lifecycle);
  const minimumCivicLoop = asRecord(testnetCapabilities.minimum_reviewer_civic_loop);
  const civicLoopEntrypoints = asRecord(minimumCivicLoop.frontend_entrypoints);
  const civicLoopApiSurfaces = asRecord(minimumCivicLoop.api_evidence_surfaces);
  const civicLoopRouteBoundary = asRecord(minimumCivicLoop.canonical_route_boundary);
  const helperReadiness = asRecord(data.helperReadiness);
  const netSelf = asRecord(data.netSelf);
  const nat = asRecord(netSelf.nat || asRecord(netSelf.net).nat);
  const natAdvertise = asRecord(nat.advertise);
  const natRelay = asRecord(nat.relay);
  const natWarnings = asArray(nat.warnings);
  const natActions = asArray(nat.recovery_actions);
  const seedDiscovery = asRecord(asRecord(netSelf.net).seed_discovery);
  const publicSeeds = asRecord(data.publicSeeds);
  const publicValidators = asRecord(data.publicValidators);
  const observerEdge = asRecord(data.observerEdge);
  const accountOperator = asRecord(asRecord(data.accountOperator).node_operator);
  const accountStorage = asRecord(accountOperator.storage);
  const accountValidator = asRecord(accountOperator.validator);
  const accountHelper = asRecord(accountOperator.helper);

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
  const helperOptedIn = accountHelper.active === true || (str(accountHelper.status).length > 0 && str(accountHelper.status) !== "not_opted_in");
  const incidentTimeline = asArray(operatorInner.incident_timeline);
  const validatorRows = asArray(publicValidators.validators);
  const activeValidatorCount = num(publicValidators.active_validator_count, validatorRows.length);
  const verifiedEndpointCount = num(publicValidators.verified_endpoint_count, 0);
  const verifiedFreshEndpointCount = num(publicValidators.verified_fresh_endpoint_count, 0);
  const staleVerifiedEndpointCount = num(publicValidators.stale_verified_endpoint_count, 0);
  const missingFreshEndpointCount = num(publicValidators.active_validators_missing_verified_fresh_endpoint_count, 0);
  const allValidatorsFresh = publicValidators.all_active_validators_have_verified_fresh_endpoint === true;
  const seedNodes = asArray(publicSeeds.nodes);
  const seedP2pUrls = asArray(publicSeeds.seed_p2p_urls);
  const seedRegistrySig = asRecord(publicSeeds.seed_registry_signature_status || asRecord(publicValidators.registry).seed_registry_signature_status);
  const seedRegistrySourceKind = str(publicSeeds.registry_source_kind || asRecord(publicValidators.registry).registry_source_kind || "unknown", "unknown");
  const observerTxQueue = asRecord(observerEdge.tx_queue);
  const observerTxQueueCounts = asRecord(observerTxQueue.counts);
  const observerQueued = num(observerTxQueue.count, 0);
  const observerAccepted = num(observerTxQueueCounts.accepted, 0);
  const observerConfirmed = num(observerTxQueueCounts.confirmed, 0);
  const upstreamCount = num(observerEdge.upstream_count, 0);
  const readinessSteps: Array<{ label: string; ok: boolean; warn?: boolean; value: string }> = [
    { label: "1. Genesis or observer node booted", ok: status.ok === true, value: status.ok === true ? "Node API responding" : "Node API unavailable" },
    { label: "2. Chain identity pinned", ok: !!chainId && chainId !== "—", value: chainId },
    { label: "3. Peers visible", ok: peerCount > 0 || observerMode, warn: peerCount === 0 && !observerMode, value: observerMode ? "Observer-safe posture" : `${peerCount} peer(s)` },
    { label: "3a. Public validator reachability", ok: allValidatorsFresh, warn: activeValidatorCount > 0 && !allValidatorsFresh, value: allValidatorsFresh ? "Fresh verified endpoints" : `${missingFreshEndpointCount} active validator(s) missing fresh endpoint` },
    { label: "4. Baseline node operator", ok: accountOperator.baseline?.active === true, warn: str(asRecord(accountOperator.baseline).status) !== "not_opted_in", value: str(asRecord(accountOperator.baseline).status || "not opted in") },
    { label: "5. Validator responsibility", ok: validatorEffective, warn: validatorOptedIn && !validatorEffective, value: validatorEffective ? "Effective" : validatorOptedIn ? "Opted in, waiting on readiness" : "Not opted in" },
    { label: "6. Helper responsibility", ok: helperEffective, warn: helperOptedIn && !helperEffective, value: helperEffective ? "Effective" : helperOptedIn ? "Opted in, release gate or authority pending" : "Not opted in" },
    { label: "7. Storage/IPFS capacity", ok: storageOptedIn && provenCapacity > 0, warn: storageOptedIn && provenCapacity <= 0, value: storageOptedIn ? `Declared ${formatBytes(declaredCapacity)} · Proven ${formatBytes(provenCapacity)}` : "Not opted in" },
    { label: "8. Mempool and block progression", ok: mempoolSize === 0 && blockLoop.unhealthy !== true, warn: mempoolSize > 0 || blockLoop.unhealthy === true, value: blockLoop.unhealthy === true ? "Block loop unhealthy" : mempoolSize > 0 ? `${mempoolSize} tx pending` : "No pending tx" },
  ];
  const publicBetaBlockerReport = asRecord(testnetCapabilities.public_beta_blocker_report);
  const publicBetaRemaining = num(publicBetaBlockerReport.remaining_blocker_count, 0);
  const blockedCapabilities = asArray(testnetCapabilities.blocked_capabilities);
  const launchPhase = str(launchMatrix.phase || testnetCapabilities.phase || status.mode, "controlled/local");
  const publicBetaClaimed = testnetCapabilities.public_beta_ready_claimed === true || publicBetaBlockerReport.public_beta_ready === true;
  const reviewerRouteRows = [
    { key: "account", label: "Account / identity", href: str(civicLoopEntrypoints.account, "/profile") },
    { key: "identity_verification", label: "Human verification", href: str(civicLoopEntrypoints.identity_verification, "/verification") },
    { key: "feed", label: "Public feed", href: str(civicLoopEntrypoints.feed, "/feed") },
    { key: "groups", label: "Public groups", href: str(civicLoopEntrypoints.groups, "/groups") },
    { key: "governance", label: "Decisions / governance", href: str(civicLoopEntrypoints.governance, "/decisions") },
    { key: "disputes", label: "Reports / disputes", href: str(civicLoopEntrypoints.disputes, "/reports") },
    { key: "reviews", label: "Review center", href: str(civicLoopEntrypoints.review_center, "/reviews") },
    { key: "reputation", label: "Reputation / activity", href: str(civicLoopEntrypoints.reputation_visibility, "/activity") },
    { key: "node", label: "Observer / node status", href: str(civicLoopEntrypoints.node_status, "/node") },
    { key: "economics", label: "Economics locked status", href: str(civicLoopEntrypoints.economics, "/economics") },
  ].filter((row) => row.href.startsWith("/") && !row.href.includes(":"));
  const reviewerApiRows = [
    { key: "account_identity_state", label: "Account / identity API" },
    { key: "human_verification_state", label: "Human verification API" },
    { key: "public_posting_or_social_activity", label: "Public feed/social API" },
    { key: "public_group_read_with_member_gated_participation", label: "Public groups API" },
    { key: "governance_create_vote_finalize", label: "Decisions/governance API" },
    { key: "dispute_review_outcome_visibility", label: "Reports/disputes API" },
    { key: "reputation_outcome_visibility", label: "Reputation/activity API" },
    { key: "protocol_upgrade_record_lifecycle", label: "Protocol-upgrade API" },
    { key: "observer_node_status", label: "Observer/node API" },
    { key: "economics_locked_status", label: "Economics-locked API" },
  ].map((row) => ({
    ...row,
    endpoints: asArray(civicLoopApiSurfaces[row.key]).map((value) => String(value)),
  })).filter((row) => row.endpoints.length > 0);
  const prefError = storagePreferenceError(pref);
  const browserStorageUsage = storageEstimate ? formatBytes(storageEstimate.usage) : "—";
  const browserStorageQuota = storageEstimate ? formatBytes(storageEstimate.quota) : "—";
  const operatorModeLabel = validatorEffective
    ? "Validator authority effective"
    : validatorOptedIn
      ? "Validator-candidate / readiness pending"
      : asRecord(accountOperator.baseline).active === true
        ? "Node operator"
        : observerMode
          ? "Observer"
          : "Local node";
  const safeStatusCurl = `curl -fsS ${(base || "http://127.0.0.1:8000").replace(/\/$/, "")}/v1/status | python -m json.tool`;
  const safeMempoolCurl = `curl -fsS ${(base || "http://127.0.0.1:8000").replace(/\/$/, "")}/v1/status/mempool | python -m json.tool`;
  const safeOperatorCurl = `curl -fsS ${(base || "http://127.0.0.1:8000").replace(/\/$/, "")}/v1/status/operator | python -m json.tool`;
  const safeReadyzCurl = `curl -fsS ${(base || "http://127.0.0.1:8000").replace(/\/$/, "")}/readyz | python -m json.tool`;
  const incidentItems: OperatorIncidentItem[] = [
    {
      label: "Node mode and chain identity",
      status: chainId !== "—" && status.ok === true ? "ok" : "warn",
      detail: `mode ${statusLabel(status.mode || operatorModeLabel)} · chain ${chainId}`,
      command: safeStatusCurl,
    },
    {
      label: "Peer, seed, and validator reachability",
      status: peerCount > 0 || allValidatorsFresh || observerMode ? "ok" : "warn",
      detail: `${peerCount} peer(s), ${seedNodes.length} seed record(s), ${verifiedFreshEndpointCount}/${activeValidatorCount} fresh validator endpoint(s)`,
      command: `curl -fsS ${(base || "http://127.0.0.1:8000").replace(/\/$/, "")}/v1/nodes/validators | python -m json.tool`,
    },
    {
      label: "Backend readiness endpoint",
      status: readyz.ok === true || readyz.status === "ok" ? "ok" : "warn",
      detail: readyz.ok === true || readyz.status === "ok" ? "readyz reports healthy" : "readyz is missing, stale, or not healthy; capture before continuing",
      command: safeReadyzCurl,
    },
    {
      label: "Mempool and tx propagation",
      status: mempoolSize === 0 && observerQueued === 0 ? "ok" : "warn",
      detail: `${mempoolSize} mempool tx, ${observerQueued} observer queue item(s), ${observerAccepted} upstream accepted, ${observerConfirmed} confirmed`,
      command: safeMempoolCurl,
    },
    {
      label: "Block and finalized-height progress",
      status: height > 0 ? "ok" : "info",
      detail: `height ${height || 0}; finalized status remains backend-derived and local browser time is not protocol authority`,
      command: `curl -fsS ${(base || "http://127.0.0.1:8000").replace(/\/$/, "")}/v1/chain/head | python -m json.tool`,
    },
    {
      label: "BFT / validator authority",
      status: validatorEffective ? "ok" : validatorOptedIn ? "warn" : "info",
      detail: validatorEffective ? "validator authority effective in backend state" : validatorOptedIn ? "validator responsibility opted in, readiness or activation still pending" : "validator signing disabled or not active",
      command: safeOperatorCurl,
    },
    {
      label: "Storage, helper, economics, and protocol-upgrade blockers",
      status: publicBetaClaimed ? "warn" : "ok",
      detail: `storage ${storageOptedIn ? "opted-in" : "not opted-in"}; helper ${helperEffective ? "effective" : "disabled/gated"}; economics locked; automatic protocol upgrades disabled`,
      command: `cd ~/WeAll-Protocol/Weall-Protocol && PYTHONPATH=src python scripts/check_v15_public_readiness_artifacts.py`,
    },
  ];

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
            {hasAccountSession ? (
              <button className="btn" onClick={() => nav(accountOperatorSetupHref)}>Manage validator/storage opt-ins</button>
            ) : (
              <button className="btn" onClick={() => nav("/login")}>Set up account operator path</button>
            )}
          </div>
        </div>
      </section>

      <ErrorBanner message={error?.msg} details={error?.details} onRetry={() => void load()} onDismiss={() => setError(null)} />

      {!hasAccountSession ? (
        <div className="calloutInfo" role="status">
          <strong>Read-only observer view:</strong> node health, seed discovery, validator freshness, NAT posture, mempool status, and launch boundaries are available before account setup. Signed account, Tier 2, storage, helper, and validator actions unlock only after local session setup and protocol eligibility checks.
        </div>
      ) : null}

      <section className="summaryCardGrid" aria-label="Node status summary">
        <StatCard label="Node health" value={readyz.ready === false ? "Degraded" : status.ok === true ? "Online" : "Unknown"} note="Backend status and readiness are read from the connected node." ok={status.ok === true && readyz.ready !== false} warn={readyz.ready === false || loadState === "error"} />
        <StatCard label="Sync height" value={String(height || "0")} note={`Tip ${compact(status.tip || chainHead.tip || chainIdentity.tip_hash)}`} ok={height >= 0 && status.ok === true} />
        <StatCard label="Mempool" value={`${mempoolSize} tx`} note="Pending transaction pressure exposed by the node status surface." ok={mempoolSize === 0} warn={mempoolSize > 0} />
        <StatCard label="Active validators" value={String(activeValidatorCount)} note={`${verifiedEndpointCount} verified endpoint(s) advertised by /v1/nodes/validators.`} ok={activeValidatorCount > 0 && verifiedEndpointCount > 0} warn={activeValidatorCount > 0 && verifiedEndpointCount === 0} />
        <StatCard label="Reachable validators" value={`${verifiedFreshEndpointCount}/${activeValidatorCount}`} note="Fresh signed endpoint advertisements required before claiming all validators are reachable." ok={allValidatorsFresh} warn={activeValidatorCount > 0 && !allValidatorsFresh} />
        <StatCard label="Tx propagation" value={observerQueued ? `${observerQueued} local` : "No local queue"} note={`${upstreamCount} verified upstream(s); ${observerAccepted} accepted, ${observerConfirmed} confirmed in observer tx queue.`} ok={observerQueued === 0 || observerConfirmed > 0 || observerAccepted > 0} warn={observerQueued > 0 && observerAccepted === 0 && observerConfirmed === 0} />
        <StatCard label="Launch boundary" value={statusLabel(launchPhase)} note={publicBetaClaimed ? "Unexpected public beta claim detected." : "This surface does not claim public beta or production readiness."} ok={!publicBetaClaimed} warn={publicBetaClaimed} />
        <StatCard label="Public beta blockers" value={`${publicBetaRemaining || blockedCapabilities.length} open`} note={publicBetaBlockerReport.present === false ? "Blocker report artifact not loaded from this node." : "Remaining public-beta blockers are shown as evidence gates, not readiness claims."} ok={!publicBetaClaimed && publicBetaRemaining > 0} warn={publicBetaClaimed || publicBetaRemaining === 0} />
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

      <section className="card" aria-labelledby="operator-mode-matrix-heading">
        <div className="cardBody formStack">
          <div className="sectionHead">
            <div>
              <div className="eyebrow">Operator journey</div>
              <h2 id="operator-mode-matrix-heading" className="cardTitle">Mode matrix and incident response</h2>
              <p className="cardDesc">
                Use this matrix before running any operator command. It separates observer, node operator, validator-candidate, and validator authority; shows safe next actions; and records which blocker class still requires external evidence.
              </p>
            </div>
            <span className="statusPill">Bounded testnet only</span>
          </div>
          <div className="summaryCardGrid summaryCardGridThree">
            <article className="summaryCard">
              <span className="summaryCardLabel">Current mode</span>
              <div className="summaryCardValue" style={{ fontSize: "1rem" }}>{operatorModeLabel}</div>
              <div className="summaryCardHint">Displayed from backend/account state. Browser navigation and copied commands cannot upgrade authority.</div>
            </article>
            <article className="summaryCard">
              <span className="summaryCardLabel">Safe next action</span>
              <div className="summaryCardValue" style={{ fontSize: "1rem" }}>{mempoolSize > 0 || observerQueued > 0 ? "Capture queue evidence" : peerCount === 0 && !observerMode ? "Inspect seed/peer reachability" : validatorOptedIn && !validatorEffective ? "Capture validator blockers" : "Continue read-only checks"}</div>
              <div className="summaryCardHint">Diagnostics first: capture status, readyz, chain head, mempool, peer/seed, and operator output before changing settings.</div>
            </article>
            <article className="summaryCard">
              <span className="summaryCardLabel">External evidence gate</span>
              <div className="summaryCardValue" style={{ fontSize: "1rem" }}>{publicBetaRemaining ? `${publicBetaRemaining} blocker(s)` : "Unknown"}</div>
              <div className="summaryCardHint">Public beta remains blocked by external observer, replay, validator/operator, storage/IPFS, legal, upgrade, and helper gates.</div>
            </article>
          </div>
          <div className="calloutWarn">
            <strong>Incident boundary:</strong> chain mismatch, stale validator endpoints, mempool backlog, missing readyz, storage/helper/economics/protocol-upgrade blockers, or validator-candidate warnings are evidence-capture events. They are not permission to bypass protocol state or enable local flags.
          </div>
        </div>
      </section>

      <OperatorCommandWizard
        nodeMode={operatorModeLabel}
        chainId={chainId}
        baseUrl={base}
        observerMode={observerMode}
        validatorEffective={validatorEffective}
        validatorCandidate={validatorOptedIn}
      />

      <ValidatorReadinessWizard
        steps={readinessSteps}
        observerMode={observerMode}
        validatorEffective={validatorEffective}
        helperEffective={helperEffective}
        chainId={chainId}
        baseUrl={base}
      />

      <OperatorIncidentTimeline items={incidentItems} />

      <div className="calloutInfo">
        <strong>Validator promotion path:</strong> a fresh observer must sync, reach Tier 2 through protocol PoH, activate node-operator responsibility, explicitly opt into validation, pass validator readiness verification, and only then reboot with production validator service flags. This dashboard displays backend-derived blockers and never flips signing authority locally.
      </div>

      <section className="card" aria-label="Launch evidence still required">
        <div className="cardBody formStack">
          <div className="sectionHead">
            <div>
              <div className="eyebrow">What happens next</div>
              <h2 className="cardTitle">Evidence sequence before broader claims</h2>
              <div className="cardDesc">
                Operator evidence still required: external observer transcript → cross-machine replay transcript → full local proof bundle. This dashboard helps collect those facts; it does not replace them.
              </div>
            </div>
          </div>
          <div className="summaryCardGrid">
            <article className="summaryCard">
              <div className="summaryCardLabel">Observer claim</div>
              <div className="summaryCardValue">Bounded until transcripted</div>
              <div className="summaryCardText">A clean-machine public observer boot transcript is still required before calling the observer experience reviewer-ready.</div>
            </article>
            <article className="summaryCard">
              <div className="summaryCardLabel">Replay claim</div>
              <div className="summaryCardValue">Cross-machine proof needed</div>
              <div className="summaryCardText">Two independent machines should replay the same blocks and compare state roots before public beta determinism claims expand.</div>
            </article>
            <article className="summaryCard">
              <div className="summaryCardLabel">Upgrade claim</div>
              <div className="summaryCardValue">Record-only</div>
              <div className="summaryCardText">Protocol and constitution upgrade records are scheduled, public, record-only metadata; they do not fetch artifacts, execute migrations, restart nodes, or change economics.</div>
            </article>
          </div>
        </div>
      </section>

      <section className="card" aria-labelledby="public-observer-discovery-heading">
        <div className="cardBody formStack">
          <div className="sectionHead">
            <div>
              <div className="eyebrow">Public observer testnet</div>
              <h2 id="public-observer-discovery-heading" className="cardTitle">Seed, validator, and tx propagation visibility</h2>
              <p className="cardDesc">
                These values come from backend protocol/discovery routes. A browser selection cannot grant validator authority, and local tx acceptance is shown separately from upstream validator acceptance.
              </p>
            </div>
            <span className={statusClass(publicSeeds.ok === true && publicValidators.ok === true, publicSeeds.ok !== true || publicValidators.ok !== true)}>Discovery routes</span>
          </div>

          <div className="grid2">
            <div className="infoCard compact">
              <div className="feedMediaTitle">Seed registry and commitments</div>
              <div className="progressList">
                <DetailRow label="Public testnet" value={publicSeeds.public_testnet === true ? "Enabled" : "Not enabled"} ok={publicSeeds.public_testnet === true} warn={publicSeeds.public_testnet !== true && publicSeeds.ok === true} />
                <DetailRow label="Registry signature" value={seedRegistrySig.verified === true ? `Verified (${str(seedRegistrySig.trust, "signed")})` : "Unsigned / not loaded"} ok={seedRegistrySig.verified === true} warn={publicSeeds.public_testnet === true && seedRegistrySig.verified !== true} />
                <DetailRow label="Registry source" value={statusLabel(seedRegistrySourceKind)} ok={seedRegistrySig.verified === true && seedRegistrySourceKind !== "unknown"} warn={publicSeeds.public_testnet === true && seedRegistrySourceKind === "unknown"} />
                <DetailRow label="Seed API nodes" value={String(seedNodes.length)} ok={seedNodes.length > 0} warn={publicSeeds.public_testnet === true && seedNodes.length === 0} />
                <DetailRow label="Seed P2P URIs" value={String(seedP2pUrls.length)} ok={seedP2pUrls.length > 0} warn={publicSeeds.public_testnet === true && seedP2pUrls.length === 0} />
                <DetailRow label="Direct P2P priority" value={seedP2pUrls.length > 0 ? "Primary path" : "No direct seed URI"} ok={seedP2pUrls.length > 0} warn={publicSeeds.public_testnet === true && seedP2pUrls.length === 0} />
                <DetailRow label="Genesis hash" value={<span className="mono">{compact(publicSeeds.genesis_hash || chainIdentity.genesis_hash)}</span>} ok={!!(publicSeeds.genesis_hash || chainIdentity.genesis_hash)} />
              </div>
            </div>

            <div className="infoCard compact">
              <div className="feedMediaTitle">Observer tx propagation</div>
              <div className="progressList">
                <DetailRow label="Observer edge mode" value={observerEdge.observer_edge_mode === true ? "Enabled" : "Not enabled"} ok={observerEdge.observer_edge_mode === true} warn={observerMode && observerEdge.observer_edge_mode !== true} />
                <DetailRow label="Verified upstreams" value={String(upstreamCount)} ok={upstreamCount > 0} warn={observerEdge.observer_edge_mode === true && upstreamCount === 0} />
                <DetailRow label="Local tx_queue" value={`${observerQueued} queued/known`} ok={observerQueued === 0} warn={observerQueued > 0 && observerAccepted === 0 && observerConfirmed === 0} />
                <DetailRow label="Upstream accepted" value={String(observerAccepted)} ok={observerAccepted > 0 || observerQueued === 0} warn={observerQueued > 0 && observerAccepted === 0} />
                <DetailRow label="Upstream confirmed" value={String(observerConfirmed)} ok={observerConfirmed > 0 || observerQueued === 0} />
              </div>
            </div>
          </div>

          <div className="progressList" aria-label="Current validators from protocol state">
            <DetailRow label="Active validators" value={String(activeValidatorCount)} ok={activeValidatorCount > 0} warn={activeValidatorCount === 0 && publicValidators.ok === true} />
            <DetailRow label="Verified validator endpoints" value={String(verifiedEndpointCount)} ok={verifiedEndpointCount > 0 || activeValidatorCount === 0} warn={activeValidatorCount > 0 && verifiedEndpointCount === 0} />
            <DetailRow label="Fresh validator endpoints" value={`${verifiedFreshEndpointCount} fresh / ${staleVerifiedEndpointCount} stale`} ok={allValidatorsFresh} warn={activeValidatorCount > 0 && !allValidatorsFresh} />
            <DetailRow label="Missing fresh endpoint warnings" value={String(missingFreshEndpointCount)} ok={missingFreshEndpointCount === 0} warn={missingFreshEndpointCount > 0} />
            {validatorRows.slice(0, 8).map((row: any, idx: number) => (
              <DetailRow
                key={`${String(row.account_id || row.node_pubkey || "validator")}-${idx}`}
                label={String(row.account_id || "validator")}
                value={`${String(row.readiness_status || "active")} · ${num(row.verified_endpoint_count, 0)} verified · ${num(row.verified_fresh_endpoint_count, 0)} fresh`}
                ok={row.active_in_protocol_state === true && row.has_verified_fresh_endpoint === true}
                warn={row.active_in_protocol_state === true && row.has_verified_fresh_endpoint !== true}
              />
            ))}
          </div>

          <div className="grid2">
            <div className="infoCard compact">
              <div className="feedMediaTitle">NAT / firewall posture</div>
              <div className="progressList">
                <DetailRow label="Recommended network profile" value={statusLabel(nat.recommended_profile || "Unknown")} ok={nat.recommended_profile === "public_inbound" || nat.recommended_profile === "outbound_relay_only" || nat.recommended_profile === "relay_only"} warn={nat.recommended_profile === "needs_advertise_or_relay" || natWarnings.length > 0} />
                <DetailRow label="Advertised P2P URI" value={str(asRecord(netSelf.net).advertise_uri || natAdvertise.status, "Not published")} ok={nat.inbound_reachable_claim === true} warn={natAdvertise.configured === true && nat.inbound_reachable_claim !== true} />
                <DetailRow label="Relay client" value={natRelay.client_enabled === true ? (natRelay.client_ready === true ? "Configured" : "Needs recipient binding") : "Disabled"} ok={natRelay.client_ready === true} warn={natRelay.client_enabled === true && natRelay.client_ready !== true} />
                <DetailRow label="Seed discovery refresh" value={seedDiscovery.refresh_ms ? `${seedDiscovery.last_ok === true ? "OK" : statusLabel(seedDiscovery.last_error || "Waiting")} · ${seedDiscovery.refresh_ms} ms` : "One-shot / disabled"} ok={seedDiscovery.last_ok === true} warn={!!seedDiscovery.last_error && seedDiscovery.last_ok !== true} />
              </div>
            </div>
            <div className="infoCard compact">
              <div className="feedMediaTitle">Recovery guidance</div>
              {natWarnings.length ? (
                <ul className="compactList">
                  {natWarnings.slice(0, 4).map((warning, idx) => <li key={`${String(warning)}-${idx}`}>{statusLabel(warning)}</li>)}
                </ul>
              ) : (
                <p className="cardDesc">No NAT/firewall warnings reported by the local backend.</p>
              )}
              {natActions.length ? (
                <p className="cardDesc">{String(natActions[0])}</p>
              ) : null}
            </div>
          </div>

          <div className="calloutInfo">
            Public observer tx states are intentionally split: <strong>local accepted</strong> only means your node accepted the envelope; <strong>upstream accepted</strong> means a verified seed/validator API accepted it; <strong>confirmed</strong> means the tx was observed in a block/status response.
          </div>
          <div className="calloutWarn">
            <strong>Peer / NAT recovery:</strong> if validator endpoint freshness is good but peer count stays low, check outbound firewall rules, published TCP/TLS ports, relay configuration, and the public NAT/firewall recovery runbook before claiming full public observer connectivity.
          </div>
          <div className="calloutInfo">
            <strong>Incident response packet:</strong> for peer, seed, mempool, chain mismatch, or validator-authority issues, capture <span className="mono">/v1/status</span>, <span className="mono">/readyz</span>, <span className="mono">/v1/chain/head</span>, <span className="mono">/v1/status/mempool</span>, <span className="mono">/v1/nodes/seeds</span>, <span className="mono">/v1/nodes/validators</span>, and <span className="mono">/v1/status/operator</span> before attempting recovery.
          </div>
        </div>
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
                {hasAccountSession ? (
                  <button className="btn" onClick={() => nav(accountOperatorSetupHref)}>Open validator/storage opt-ins</button>
                ) : (
                  <button className="btn" onClick={() => nav("/login")}>Set up account before operator actions</button>
                )}
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
            <div className="infoCard compact">
              <div className="infoCardHeader"><span className="statusPill warn">Evidence gates</span><strong>Public beta remains blocked</strong></div>
              <div className="infoCardText">Public validator, storage/IPFS, protocol upgrade, helper execution, and legal/compliance readiness require external transcripts or attestations before any public beta claim.</div>
            </div>
          </div>
          {blockedCapabilities.length ? (
            <div className="progressList" aria-label="Public beta blocker snapshot">
              <DetailRow
                label="Blocked capabilities"
                value={blockedCapabilities.slice(0, 8).join(", ")}
                ok={!publicBetaClaimed}
                warn={publicBetaClaimed}
              />
              <DetailRow
                label="Remaining blocker gates"
                value={`${publicBetaRemaining || "unknown"}`}
                ok={!publicBetaClaimed && publicBetaRemaining > 0}
                warn={publicBetaRemaining === 0 || publicBetaClaimed}
              />
              <DetailRow
                label="Next allowed claim"
                value={str(publicBetaBlockerReport.next_allowed_claim, "controlled testnet candidate only")}
                ok={!publicBetaClaimed}
              />
              <DetailRow
                label="Protocol upgrade lifecycle"
                value={protocolUpgradeLifecycle.activation_record_only === true ? "Public record-only, block-height scheduled, governance-parent bound" : "Record-only boundary not reported"}
                ok={protocolUpgradeLifecycle.activation_record_only === true && protocolUpgradeLifecycle.automatic_software_apply_enabled === false}
                warn={protocolUpgradeLifecycle.automatic_software_apply_enabled === true}
              />
              <DetailRow
                label="Governance lifecycle clock"
                value={governanceLifecycle.progression_clock === "block_height" ? "Block-height scheduler; no wall-clock protocol mutation" : "Lifecycle clock not reported"}
                ok={governanceLifecycle.progression_clock === "block_height" && governanceLifecycle.manual_wall_clock_protocol_state_allowed === false}
                warn={governanceLifecycle.manual_wall_clock_protocol_state_allowed === true}
              />
              <DetailRow
                label="Dispute lifecycle clock"
                value={disputeLifecycle.progression_clock === "block_height" ? "Block-height dispute/review windows; private identity evidence protected" : "Lifecycle clock not reported"}
                ok={disputeLifecycle.progression_clock === "block_height" && disputeLifecycle.private_identity_evidence_publicly_exposed === false}
                warn={disputeLifecycle.private_identity_evidence_publicly_exposed === true}
              />
              <DetailRow
                label="Reviewer civic loop"
                value={Array.isArray(minimumCivicLoop.steps) ? `${minimumCivicLoop.steps.length} public-only steps mapped` : "Reviewer loop map not reported"}
                ok={minimumCivicLoop.public_only_visibility === true && minimumCivicLoop.economics_locked_by_default === true}
                warn={minimumCivicLoop.economics_locked_by_default === false}
              />
              <DetailRow
                label="Canonical governance route"
                value={`${str(civicLoopRouteBoundary.governance_label, "Decisions")} (${str(civicLoopRouteBoundary.governance_route, "/decisions")})`}
                ok={str(civicLoopRouteBoundary.governance_route, "/decisions") === "/decisions"}
              />
              <DetailRow
                label="Canonical dispute route"
                value={`${str(civicLoopRouteBoundary.dispute_label, "Reports")} (${str(civicLoopRouteBoundary.dispute_route, "/reports")})`}
                ok={str(civicLoopRouteBoundary.dispute_route, "/reports") === "/reports"}
              />
            </div>
          ) : null}
          {reviewerRouteRows.length ? (
            <div className="infoCard compact" aria-label="Reviewer civic loop route map">
              <div className="infoCardHeader"><span className="statusPill ok">Reviewer route map</span><strong>Minimum civic loop entrypoints</strong></div>
              <div className="infoCardText">
                Use these canonical routes for the first-pass reviewer walkthrough. Decisions replace legacy proposal aliases; Reports replace legacy dispute aliases.
              </div>
              <div className="buttonRow buttonRowWide">
                {reviewerRouteRows.map((row) => (
                  <button key={row.key} className="btn" type="button" onClick={() => nav(row.href)}>
                    {row.label}
                  </button>
                ))}
              </div>
              <div className="cardDesc">
                Legacy /proposals and /disputes aliases remain removed; route templates such as /account/:account require a concrete public identifier.
              </div>
            </div>
          ) : null}
          {reviewerApiRows.length ? (
            <div className="infoCard compact" aria-label="Reviewer civic loop API evidence map">
              <div className="infoCardHeader"><span className="statusPill ok">Reviewer API evidence map</span><strong>Canonical API surfaces for the civic loop</strong></div>
              <div className="infoCardText">
                These API surfaces back the reviewer walkthrough. They are evidence and read/action boundaries, not public beta or mainnet readiness claims.
              </div>
              <div className="progressList">
                {reviewerApiRows.slice(0, 6).map((row) => (
                  <DetailRow
                    key={row.key}
                    label={row.label}
                    value={row.endpoints.slice(0, 3).join(" · ")}
                    ok
                  />
                ))}
              </div>
              <div className="cardDesc">
                Full API route coverage is checked against the generated v1.5 API contract map; protocol-upgrade records and economics status remain non-activating surfaces.
              </div>
            </div>
          ) : null}
          {incidentTimeline.length ? (
            <div className="progressList" aria-label="Operator incident timeline">
              {incidentTimeline.map((row: any, idx: number) => (
                <DetailRow
                  key={`${String(row.event || "event")}-${idx}`}
                  label={String(row.event || "operator event")}
                  value={String(row.message || row.status || "observed")}
                  ok={String(row.severity || row.status || "").toLowerCase() === "ok"}
                  warn={["warn", "warning", "blocked", "stalled"].includes(String(row.severity || row.status || "").toLowerCase())}
                />
              ))}
            </div>
          ) : null}
          <details className="detailsPanel">
            <summary>Raw node diagnostics</summary>
            <pre className="codePanel mono">{JSON.stringify(data, null, 2)}</pre>
          </details>
        </div>
      </section>
    </div>
  );
}
