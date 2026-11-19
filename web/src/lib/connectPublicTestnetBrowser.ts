// Optional public testnet browser entrypoint; never consensus or identity authority.
import { getSession } from "../auth/session";
import { clearApprovedBrowserSession, hasManualNodeConsent } from "./browserNodeSession";
import { config } from "./config";
import { canSwitchToNode, discoverNodeProbes, type NodeProbe } from "./nodeConnectionManager";
import { selectBrowserNode } from "./browserNodeTransition";

export type PublicTestnetConnectResult =
  | { state: "disabled" }
  | { state: "connected"; baseUrl: string; changed: boolean }
  | { state: "unavailable"; reason?: "no_compatible_node" | "session_not_recognized" };

/**
 * Auto-select only pinned, chain-compatible, published HTTPS access nodes.
 * A previously approved current node may be retained, never automatically
 * discovered as a new unlisted alternative. The shared transition boundary
 * verifies active sessions before any API target change.
 */
export async function connectPublicTestnetBrowser(): Promise<PublicTestnetConnectResult> {
  if (!config.publicTestnet) return { state: "disabled" };

  const probes = await discoverNodeProbes({ timeoutMs: 2500 });
  const current = probes.find((probe) => probe.isCurrent);
  const session = getSession();
  const ordered: NodeProbe[] = [];
  if (current?.phase === "healthy" && current.ok &&
    (current.listedInSeedManifest || hasManualNodeConsent(current.baseUrl))) {
    ordered.push(current);
  }
  ordered.push(...probes.filter((probe) => canSwitchToNode(probe)));

  for (const probe of ordered) {
    try {
      const result = await selectBrowserNode(probe, {
        intent: "automatic",
        allowCurrent: true,
        attempts: 2,
      });
      if (result) {
        return { state: "connected", baseUrl: result.baseUrl, changed: result.changed };
      }
    } catch {
      // Never treat failed compatibility, session recognition, or node switching
      // as proof that this candidate can be used. Try the next published node.
    }
  }

  if (session?.sessionKey) {
    clearApprovedBrowserSession();
    return { state: "unavailable", reason: "session_not_recognized" };
  }
  return { state: "unavailable", reason: "no_compatible_node" };
}
