// Optional public testnet browser entrypoint; never consensus or identity authority.
import { getSession } from "../auth/session";
import { clearApprovedBrowserSession, verifyBrowserSessionOnNode } from "./browserNodeSession";
import { config } from "./config";
import { canSwitchToNode, discoverNodeProbes, switchToNode, type NodeProbe } from "./nodeConnectionManager";

export type PublicTestnetConnectResult =
  | { state: "disabled" }
  | { state: "connected"; baseUrl: string; changed: boolean }
  | { state: "unavailable"; reason?: "no_compatible_node" | "session_not_recognized" };

/**
 * Select an HTTPS, chain-compatible access node before mounting the app.
 *
 * Existing session bearer material is sent only to a node already vetted
 * against the pinned chain and, for automatic alternative selection, explicitly
 * listed by this deployment's static seed manifest. A node's reported chain
 * hash alone does not make an arbitrary backend discovery hint trusted.
 *
 * Account keys and session metadata remain in this browser. If no candidate
 * recognizes a previously active browser session, do not silently move the
 * account into a new backend context or treat protected routes as authenticated.
 */
export async function connectPublicTestnetBrowser(): Promise<PublicTestnetConnectResult> {
  if (!config.publicTestnet) return { state: "disabled" };

  const probes = await discoverNodeProbes({ timeoutMs: 2500 });
  const current = probes.find((probe) => probe.isCurrent);
  const session = getSession();

  if (session?.sessionKey) {
    const ordered: NodeProbe[] = [];
    if (current?.phase === "healthy" && current.ok) ordered.push(current);
    ordered.push(...probes.filter((probe) => canSwitchToNode(probe)));

    for (const probe of ordered) {
      const result = await verifyBrowserSessionOnNode(
        probe.baseUrl,
        session.account,
        session.sessionKey,
        { attempts: 2 },
      );
      if (result !== "verified") continue;

      if (probe.isCurrent) {
        return { state: "connected", baseUrl: probe.baseUrl, changed: false };
      }
      switchToNode(probe.baseUrl);
      return { state: "connected", baseUrl: probe.baseUrl, changed: true };
    }

    clearApprovedBrowserSession();
    return { state: "unavailable", reason: "session_not_recognized" };
  }

  if (current?.phase === "healthy" && current.ok) {
    return { state: "connected", baseUrl: current.baseUrl, changed: false };
  }

  const candidate = probes.find((probe) => canSwitchToNode(probe));
  if (!candidate) return { state: "unavailable", reason: "no_compatible_node" };

  switchToNode(candidate.baseUrl);
  return { state: "connected", baseUrl: candidate.baseUrl, changed: true };
}
