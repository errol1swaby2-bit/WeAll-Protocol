import React, { useEffect, useState } from "react";
import { getSession } from "../auth/session";
import { verifyBrowserSessionOnNode } from "../lib/browserNodeSession";
import { config } from "../lib/config";

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
  const [sessionCheck, setSessionCheck] = useState<string>("");

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
        throw new Error("Only healthy, compatible, published HTTPS nodes can be selected from the public connection manager.");
      }
      const session = getSession();
      if (config.publicTestnet && session?.sessionKey) {
        const recognition = await verifyBrowserSessionOnNode(
          probe.baseUrl, session.account, session.sessionKey, { attempts: 3 },
        );
        if (recognition !== "verified") {
          throw new Error("This node has not recognized the current browser session. It may still be syncing; retry when the session record is available, or recover/login independently. Your existing connection was preserved.");
        }
      }
      switchToNode(probe.baseUrl);
      setSwitchedTo(probe.baseUrl);
      await refresh();
    } catch (e: any) {
      setErr(String(e?.message || e || "Could not switch node."));
    }
  }

  async function recheckCurrentSession(): Promise<void> {
    const currentProbe = probes.find((probe) => probe.isCurrent);
    const currentSession = getSession();
    if (!currentProbe || currentProbe.phase !== "healthy" || !currentSession?.sessionKey) {
      setSessionCheck("There is no reachable current node and saved bearer to verify. Open session recovery if needed.");
      return;
    }
    setBusy(true);
    try {
      const recognition = await verifyBrowserSessionOnNode(
        currentProbe.baseUrl, currentSession.account, currentSession.sessionKey, { attempts: 3 },
      );
      setSessionCheck(recognition === "verified"
        ? "The selected node recognizes this browser session."
        : "Session recognition is still unavailable. The browser will not send protected session headers until it is recognized.");
    } finally {
      setBusy(false);
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
        {sessionCheck ? <div className="calloutInfo">{sessionCheck}</div> : null}
        {config.publicTestnet && getSession()?.sessionKey ? (
          <button className="btn" onClick={() => void recheckCurrentSession()} disabled={busy}>
            Recheck session on current node
          </button>
        ) : null}
        {switchedTo ? <div className="calloutInfo"><strong>Connection target changed.</strong> This browser now points at <span className="mono">{switchedTo}</span>. Your account keys and on-chain identity were not changed.</div> : null}
        {currentIsWeak && healthyAlternates.length ? (
          <div className="calloutWarn">
            <strong>Current node may be stale or degraded.</strong> A healthier compatible node is available below.
          </div>
        ) : null}
        <div className="calloutInfo">
          <strong>Switching rule:</strong> only healthy compatible nodes may be selected. Public testnet selections must also be HTTPS endpoints listed by the deployed seed manifest. An active session must be recognized by the destination before the browser switches; pending synchronization is not proof of login. Chain mismatches remain blocked.
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
                {config.publicTestnet ? <span className="cardDesc">{probe.listedInSeedManifest ? "Published testnet API candidate" : "Not listed in the published testnet seed manifest; automatic switching disabled"}</span> : null}
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
