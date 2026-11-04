/**
 * One fail-closed browser access-node transition policy.
 *
 * Automatic selection uses only published seeds, except a previously approved
 * current HTTPS node in this tab. Explicit user selection may opt into a
 * healthy, chain-compatible unlisted HTTPS node with informed consent.
 * This module is browser access control, never consensus or PoH authority.
 */
import { getSession } from "../auth/session";
import {
  hasManualNodeConsent,
  rememberManualNodeConsent,
  verifyBrowserSessionOnNode,
} from "./browserNodeSession";
import { config } from "./config";
import { isPublicApiOrigin } from "./publicApiOrigin";
import { switchToNode, type NodeProbe } from "./nodeConnectionManager";

export type BrowserNodeIntent = "automatic" | "manual";
export type BrowserNodeDecision =
  | { allowed: true; consentRequired: boolean }
  | { allowed: false; reason: "disabled" | "not_ready" | "current_node" | "invalid_origin" | "untrusted_node" };

export type BrowserNodeTransition = {
  baseUrl: string;
  changed: boolean;
  runtimeBase: string;
};

export function inspectBrowserNodeTarget(
  probe: NodeProbe | null | undefined,
  intent: BrowserNodeIntent,
  opts?: { allowCurrent?: boolean },
): BrowserNodeDecision {
  if (intent === "automatic" && !config.publicTestnet) {
    return { allowed: false, reason: "disabled" };
  }
  if (!probe || probe.phase !== "healthy" || probe.ok !== true) {
    return { allowed: false, reason: "not_ready" };
  }
  if (probe.isCurrent && !opts?.allowCurrent) {
    return { allowed: false, reason: "current_node" };
  }
  if (!config.publicTestnet) {
    return { allowed: true, consentRequired: false };
  }
  if (!isPublicApiOrigin(probe.baseUrl)) {
    return { allowed: false, reason: "invalid_origin" };
  }
  if (probe.listedInSeedManifest === true) {
    return { allowed: true, consentRequired: false };
  }
  const previouslyApproved = hasManualNodeConsent(probe.baseUrl);
  if (intent === "automatic") {
    // Consent never promotes an unlisted alternative into automatic discovery.
    return probe.isCurrent && previouslyApproved
      ? { allowed: true, consentRequired: false }
      : { allowed: false, reason: "untrusted_node" };
  }
  return { allowed: true, consentRequired: !previouslyApproved };
}

/**
 * Never disclose a bearer before node compatibility and origin trust are
 * established. Record fresh consent only AFTER remote session recognition.
 * A declined user prompt causes no state change.
 */
export async function selectBrowserNode(
  probe: NodeProbe,
  opts: {
    intent: BrowserNodeIntent;
    allowCurrent?: boolean;
    confirmUnlisted?: (baseUrl: string) => boolean | Promise<boolean>;
    attempts?: number;
  },
): Promise<BrowserNodeTransition | null> {
  const decision = inspectBrowserNodeTarget(probe, opts.intent, {
    allowCurrent: opts.allowCurrent,
  });
  if (!decision.allowed) {
    if (decision.reason === "untrusted_node") {
      throw new Error("Unlisted nodes cannot be selected automatically.");
    }
    if (decision.reason === "invalid_origin") {
      throw new Error("Public testnet requires a plain HTTPS API origin.");
    }
    throw new Error("Only healthy chain-compatible nodes can be selected.");
  }

  if (decision.consentRequired) {
    if (opts.intent !== "manual" || !opts.confirmUnlisted) {
      throw new Error("Explicit consent is required before selecting an unlisted node.");
    }
    if (!(await opts.confirmUnlisted(probe.baseUrl))) return null;
  }

  const session = getSession();
  if (config.publicTestnet && session?.sessionKey) {
    const recognition = await verifyBrowserSessionOnNode(
      probe.baseUrl,
      session.account,
      session.sessionKey,
      { attempts: opts.attempts ?? (opts.intent === "automatic" ? 2 : 3) },
    );
    if (recognition !== "verified") {
      throw new Error(
        "The destination has not recognized this browser session; the previous connection was preserved.",
      );
    }
  }

  if (decision.consentRequired) rememberManualNodeConsent(probe.baseUrl);
  if (probe.isCurrent) {
    return { baseUrl: probe.baseUrl, changed: false, runtimeBase: probe.baseUrl };
  }
  const runtimeBase = switchToNode(probe.baseUrl);
  return { baseUrl: probe.baseUrl, changed: true, runtimeBase };
}
