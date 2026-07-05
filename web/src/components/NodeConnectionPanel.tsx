import React, { useEffect, useState } from "react";

import {
  discoverNodeProbes,
  nodePhaseHint,
  nodePhaseLabel,
  NodeProbe,
  canSwitchToNode,
  switchToNode,
} from "../lib/nodeConnectionManager";

function phaseClass(phase: NodeProbe["phase"]): string {
  if (phase === "healthy") return "ok";
  if (phase === "offline" || phase === "incompatible") return "danger";
  return "warn";
}

function compactHash(value?: string): string {
  if (!value) return "—";
  if (value.length <= 18) return value;
  return `${value.slice(0, 8)}…${value.slice(-8)}`;
}

export default function NodeConnectionPanel({ compact = false }: { compact?: boolean }): JSX.Element {
  const [probes, setProbes] = useState<NodeProbe[]>([]);
  const [busy, setBusy] = useState<boolean>(false);
  const [err, setErr] = useState<string>("");
  const [switchedTo, setSwitchedTo] = useState<string>("");

  async function refresh(): Promise<void> {
    setBusy(true);
    setErr("");
    try {
      const next = await discoverNodeProbes({ timeoutMs: compact ? 2200 : 3200 });
      setProbes(next);
    } catch (e: any) {
      setErr(String(e?.message || e || "Failed to inspect nodes."));
    } finally {
      setBusy(false);
    }
  }

  useEffect(() => {
    void refresh();
  }, []);

  async function chooseNode(probe: NodeProbe): Promise<void> {
    setErr("");
    try {
      if (!canSwitchToNode(probe)) {
        throw new Error("Only healthy, compatible nodes can be selected from the normal connection manager.");
      }
      switchToNode(probe.baseUrl);
      setSwitchedTo(probe.baseUrl);
      await refresh();
    } catch (e: any) {
      setErr(String(e?.message || e || "Could not switch node."));
    }
  }

  const current = probes.find((probe) => probe.isCurrent) || probes[0] || null;
  const healthyAlternates = probes.filter((probe) => !probe.isCurrent && probe.phase === "healthy");
  const currentIsWeak = !!current && current.phase !== "healthy";

  return (
    <section className="card nodeConnectionPanel">
      <div className="cardBody formStack">
        <div className="sectionHead">
          <div>
            <div className="eyebrow">Browser API access node</div>
            <h2 className="cardTitle">Connection manager</h2>
            <div className="cardDesc">
              Switch the backend this browser reads from without changing your account identity or your local mesh node. P2P peers, validator connectivity, and signing authority remain controlled by the local node and protocol state.
              Chain mismatch warnings block switching; a browser target change is not a validator or operator role change.
            </div>
          </div>
          <button className="btn" onClick={() => void refresh()} disabled={busy}>
            {busy ? "Checking…" : "Refresh nodes"}
          </button>
        </div>

        {err ? <div className="calloutWarn"><strong>Node check failed.</strong> {err}</div> : null}
        {switchedTo ? <div className="calloutInfo"><strong>Connection target changed.</strong> This browser now points at <span className="mono">{switchedTo}</span>. Your account keys and on-chain identity were not changed.</div> : null}
        {currentIsWeak && healthyAlternates.length ? (
          <div className="calloutWarn">
            <strong>Current node may be stale or degraded.</strong> A healthier compatible node is available below.
          </div>
        ) : null}
        <div className="calloutInfo">
          <strong>Switching rule:</strong> only healthy compatible nodes may be selected. Incompatible chain id, genesis hash, tx index hash, or protocol profile hash should be treated as a chain mismatch incident, not as a normal fallback.
        </div>

        {probes.length === 0 && !busy ? (
          <div className="emptyPanel">
            <strong>No node list loaded.</strong>
            <span>The manager uses the current browser API node, the build default, the backend /v1/nodes/seeds route, and /seeds.json only as a frontend fallback.</span>
          </div>
        ) : null}

        <div className="progressList">
          {probes.map((probe) => (
            <div key={probe.baseUrl} className="progressRow" style={{ alignItems: "flex-start", gap: 14 }}>
              <span style={{ flex: 1, display: "grid", gap: 6 }}>
                <strong>{probe.label}</strong>
                <span className="mono" style={{ wordBreak: "break-word" }}>{probe.baseUrl}</span>
                <span className="cardDesc">{nodePhaseHint(probe)}</span>
                <span className="cardDesc">
                  Chain <span className="mono">{probe.chainId || "—"}</span> · Height <span className="mono">{probe.height ?? "—"}</span> · Latency <span className="mono">{probe.latencyMs ? `${probe.latencyMs}ms` : "—"}</span>
                </span>
                {!compact ? (
                  <>
                    <span className="cardDesc">
                      genesis <span className="mono">{compactHash(probe.genesisHash)}</span> · tx index <span className="mono">{compactHash(probe.txIndexHash)}</span> · profile <span className="mono">{compactHash(probe.protocolProfileHash)}</span>
                    </span>
                    {probe.compatibilitySourceBaseUrl ? (
                      <span className="cardDesc">
                        Expected from <span className="mono">{probe.compatibilitySourceBaseUrl}</span>: chain <span className="mono">{probe.expectedChainId || "—"}</span> · genesis <span className="mono">{compactHash(probe.expectedGenesisHash)}</span> · tx index <span className="mono">{compactHash(probe.expectedTxIndexHash)}</span> · profile <span className="mono">{compactHash(probe.expectedProtocolProfileHash)}</span>
                      </span>
                    ) : null}
                    {probe.errors.length ? (
                      <span className="cardDesc">
                        Diagnostics: <span className="mono">{probe.errors.join(", ")}</span>
                      </span>
                    ) : null}
                  </>
                ) : null}
              </span>
              <span className="buttonColumn" style={{ display: "grid", gap: 8, justifyItems: "end" }}>
                <span className={`statusPill ${phaseClass(probe.phase)}`}>{nodePhaseLabel(probe.phase)}</span>
                {probe.isCurrent ? <span className="statusPill ok">Current</span> : null}
                {canSwitchToNode(probe) ? (
                  <button className="btn btnPrimary" onClick={() => void chooseNode(probe)}>
                    Switch to this node
                  </button>
                ) : !probe.isCurrent ? (
                  <span className="statusPill warn">Switch blocked</span>
                ) : null}
              </span>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
