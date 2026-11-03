// Browser access-node session proof, independent of consensus and Cloudflare.
// Never accepts a node's identity without the caller first verifying its pinned
// chain/genesis/tx-index/profile commitments.
export type SessionRecognition = "verified" | "rejected" | "unavailable";
export const BROWSER_NODE_SESSION_CHECKED_EVENT = "weall-browser-node-session-checked";

function announceSessionCheck(): void {
  try {
    window.dispatchEvent(new Event(BROWSER_NODE_SESSION_CHECKED_EVENT));
  } catch {
    // Non-browser tests may not have a DOM event dispatcher.
  }
}

type ApprovedSession = {
  baseUrl: string;
  account: string;
  sessionKey: string;
};

let approved: ApprovedSession | null = null;

function normalizeBase(base: string): string {
  return String(base || "").trim().replace(/\/+$/, "");
}

// User-granted exception for a specifically chosen HTTPS node. Per-tab only:
// unlike the static bootstrap manifest this permission is never inferred from
// backend gossip, never propagated to other browser profiles, and never grants
// protocol authority. Session recognition is still checked separately.
const MANUAL_NODE_CONSENT_KEY = "weall_manual_https_node_consent_v1";

export function hasManualNodeConsent(baseUrl: string): boolean {
  const base = normalizeBase(baseUrl);
  if (!base.startsWith("https://")) return false;
  try {
    return sessionStorage.getItem(MANUAL_NODE_CONSENT_KEY) === base;
  } catch {
    return false;
  }
}

export function rememberManualNodeConsent(baseUrl: string): void {
  const base = normalizeBase(baseUrl);
  if (!base.startsWith("https://")) throw new Error("manual_node_consent_requires_https");
  sessionStorage.setItem(MANUAL_NODE_CONSENT_KEY, base);
}

export function clearApprovedBrowserSession(): void {
  approved = null;
  announceSessionCheck();
}

export function isBrowserSessionApproved(baseUrl: string, account: string, sessionKey: string): boolean {
  return !!(
    approved &&
    approved.baseUrl === normalizeBase(baseUrl) &&
    approved.account === account &&
    approved.sessionKey === sessionKey &&
    sessionKey
  );
}

/**
 * Verify the backend's canonical session record, not just TCP/API health.
 * This must only be called for a previously chain-compatible HTTPS node.
 * A rejected or unreachable session cannot silently become an authenticated
 * browser connection. No keys are written to disk or sent to Cloudflare.
 */
export async function verifyBrowserSessionOnNode(
  baseUrl: string,
  account: string,
  sessionKey: string,
  opts?: { timeoutMs?: number; attempts?: number },
): Promise<SessionRecognition> {
  const base = normalizeBase(baseUrl);
  const acct = String(account || "").trim();
  const bearer = String(sessionKey || "").trim();
  if (!base.startsWith("https://") || !acct || !bearer) return "unavailable";

  const attempts = Math.max(1, Math.min(3, Math.trunc(opts?.attempts ?? 2)));
  const timeoutMs = Math.max(500, Math.min(5000, opts?.timeoutMs ?? 1800));
  let outcome: SessionRecognition = "unavailable";

  for (let i = 0; i < attempts; i += 1) {
    const controller = new AbortController();
    const timer = window.setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await fetch(base + "/v1/session/me", {
        method: "GET",
        headers: {
          Accept: "application/json",
          "X-WeAll-Account": acct,
          "X-WeAll-Session-Key": bearer,
        },
        signal: controller.signal,
        cache: "no-store",
        credentials: "omit",
        redirect: "error",
      });

      if (!res.ok) {
        outcome = res.status === 401 || res.status === 403 ? "rejected" : "unavailable";
      } else {
        const payload: unknown = await res.json();
        const record = payload && typeof payload === "object" ? (payload as Record<string, any>) : {};
        if (
          record.ok === true &&
          record.authenticated === true &&
          record.account === acct &&
          record.session &&
          typeof record.session === "object" &&
          record.session.active === true &&
          record.session.expired !== true
        ) {
          approved = { baseUrl: base, account: acct, sessionKey: bearer };
          announceSessionCheck();
          return "verified";
        }
        outcome = "rejected";
      }
    } catch {
      outcome = "unavailable";
    } finally {
      window.clearTimeout(timer);
    }
    if (i + 1 < attempts) {
      await new Promise<void>((resolve) => window.setTimeout(resolve, 250));
    }
  }

  if (isBrowserSessionApproved(base, acct, bearer)) approved = null;
  announceSessionCheck();
  return outcome;
}
