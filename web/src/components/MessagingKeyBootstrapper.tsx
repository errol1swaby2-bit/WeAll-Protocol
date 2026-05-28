import { useEffect, useRef } from "react";

import { getApiBaseUrl, weall } from "../api/weall";
import { getKeypair, getSession, submitSignedTx } from "../auth/session";
import { normalizeAccount } from "../auth/keys";
import {
  accountMessagingKeyId,
  accountMessagingPublicJwk,
  ensureMessagingEncryptionIdentity,
  readMessagingEncryptionIdentity,
  sameMessagingPublicJwk,
} from "../lib/messageCrypto";
import { requestGlobalRefresh } from "../lib/revalidation";

const ATTEMPT_PREFIX = "weall.messaging.e2ee.autopublish.v1::";
const RECENT_ATTEMPT_MS = 30_000;

function attemptKey(apiBase: string, account: string): string {
  return `${ATTEMPT_PREFIX}${apiBase || "/"}::${normalizeAccount(account)}`;
}

function recentAttempt(key: string): boolean {
  try {
    const ts = Number(localStorage.getItem(key) || "0");
    return Number.isFinite(ts) && Date.now() - ts < RECENT_ATTEMPT_MS;
  } catch {
    return false;
  }
}

function markAttempt(key: string): void {
  try {
    localStorage.setItem(key, String(Date.now()));
  } catch {
    // ignore browser storage failures
  }
}

function eligibleForMessagingKey(state: any): boolean {
  if (!state || typeof state !== "object") return false;
  if (state.banned || state.locked) return false;
  const tier = Number(state.poh_tier || 0);
  return Number.isFinite(tier) && tier >= 1;
}

/**
 * Publishes the current device's messaging public key once the signed-in account
 * is usable.  This is intentionally quiet: encrypted messaging should be ready
 * before the user reaches compose, and the component never silently rotates a
 * key that is already published on-chain.
 */
export default function MessagingKeyBootstrapper(): null {
  const inFlightRef = useRef<string>("");

  useEffect(() => {
    let cancelled = false;

    async function run(): Promise<void> {
      const session = getSession();
      const account = normalizeAccount(session?.account || "");
      const apiBase = getApiBaseUrl();
      if (!account || !getKeypair(account)?.secretKeyB64) return;

      const key = attemptKey(apiBase, account);
      if (inFlightRef.current === key || recentAttempt(key)) return;
      inFlightRef.current = key;
      markAttempt(key);

      try {
        const res: any = await weall.account(account, apiBase);
        if (cancelled) return;
        const state = res?.state;
        if (!eligibleForMessagingKey(state)) return;

        const publishedPublic = accountMessagingPublicJwk(state);
        const publishedKeyId = accountMessagingKeyId(state);
        const localIdentity = readMessagingEncryptionIdentity(account);

        if (publishedPublic && publishedKeyId) {
          // Never silently rotate or replace a key.  If the browser lacks the
          // matching private key, the messages page must show an explicit
          // recovery/rotation choice.
          if (localIdentity && localIdentity.keyId === publishedKeyId && sameMessagingPublicJwk(localIdentity.publicJwk, publishedPublic)) {
            return;
          }
          return;
        }

        const identity = await ensureMessagingEncryptionIdentity(account);
        if (cancelled) return;
        await submitSignedTx({
          account,
          tx_type: "ACCOUNT_SECURITY_POLICY_SET",
          payload: {
            policy: {
              ...(state?.security_policy && typeof state.security_policy === "object" ? state.security_policy : {}),
              messaging_encryption_public_jwk: identity.publicJwk,
              messaging_encryption_key_id: identity.keyId,
              messaging_encryption_scheme: "WEALL_E2EE_V1",
            },
            messaging_encryption_public_jwk: identity.publicJwk,
            messaging_encryption_key_id: identity.keyId,
          },
          base: apiBase,
        });
        if (!cancelled) {
          requestGlobalRefresh({
            reason: "messaging-key-autopublished",
            scopes: ["account", "message", "pending_work"],
          });
        }
      } catch {
        // Keep this path quiet. Compose and thread surfaces provide explicit,
        // user-facing recovery if the key is still unavailable.
      } finally {
        if (inFlightRef.current === key) inFlightRef.current = "";
      }
    }

    void run();
    const onFocus = () => void run();
    const onVisibility = () => {
      if (!document.hidden) void run();
    };
    window.addEventListener("focus", onFocus);
    document.addEventListener("visibilitychange", onVisibility);
    return () => {
      cancelled = true;
      window.removeEventListener("focus", onFocus);
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, []);

  return null;
}
