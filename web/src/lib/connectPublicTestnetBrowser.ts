// Optional public testnet browser entrypoint. Never participates in protocol authority.
import { config } from "./config";
import { canSwitchToNode, discoverNodeProbes, switchToNode } from "./nodeConnectionManager";

export type PublicTestnetConnectResult =
  | { state: "disabled" }
  | { state: "connected"; baseUrl: string; changed: boolean }
  | { state: "unavailable" };

/**
 * On hosted public testnet builds, select a reachable compatible API node before
 * the app issues requests. Respect an already-healthy user-selected node, and
 * never accept a syncing or mismatched node as a fallback.
 *
 * This does not alter consensus peers, PoH, local account keys or node roles.
 */
export async function connectPublicTestnetBrowser(): Promise<PublicTestnetConnectResult> {
  if (!config.publicTestnet) return { state: "disabled" };

  const probes = await discoverNodeProbes({ timeoutMs: 2500 });
  const current = probes.find((probe) => probe.isCurrent);
  if (current?.phase === "healthy" && current.ok) {
    return { state: "connected", baseUrl: current.baseUrl, changed: false };
  }

  const candidate = probes.find((probe) => canSwitchToNode(probe));
  if (!candidate) return { state: "unavailable" };

  switchToNode(candidate.baseUrl);
  return { state: "connected", baseUrl: candidate.baseUrl, changed: true };
}
