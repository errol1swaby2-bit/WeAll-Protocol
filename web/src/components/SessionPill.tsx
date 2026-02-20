// projects/web/src/components/SessionPill.tsx
import React, { useEffect, useState } from "react";
import {
  endSession,
  getSession,
  getKeypair,
  clearKeypair,
  clearNonceReservation,
  loginOnThisDevice,
  revokeSessionKeyOnChain,
} from "../auth/session";
import { normalizeAccount } from "../auth/keys";

export default function SessionPill() {
  const [acct, setAcct] = useState<string | null>(null);
  const [ttl, setTtl] = useState<number>(0);
  const [hasKey, setHasKey] = useState<boolean>(false);
  const [hasSessionKey, setHasSessionKey] = useState<boolean>(false);
  const [actionStatus, setActionStatus] = useState<string>("");

  function refresh() {
    const s = getSession();
    if (!s) {
      setAcct(null);
      setHasKey(false);
      setHasSessionKey(false);
      setTtl(0);
      return;
    }

    const account = normalizeAccount(s.account);
    setAcct(account);

    const kp = getKeypair(account);
    setHasKey(!!kp?.secretKeyB64);

    setHasSessionKey(Boolean((s as any)?.sessionKey));

    const remaining = Math.max(0, Math.floor((s.expiresAtMs - Date.now()) / 1000));
    setTtl(remaining);
  }

  async function loginNow() {
    const s = getSession();
    if (!s) return;
    const account = normalizeAccount(s.account);

    try {
      setActionStatus("Issuing on-chain session key...");
      await loginOnThisDevice({ account });
      setActionStatus("Session key issued.");
      refresh();
    } catch (e: any) {
      setActionStatus("Login failed: " + (e?.message || String(e)));
    }
  }

  async function lockNow() {
    const s = getSession();
    if (!s) return;
    const account = normalizeAccount(s.account);

    const ok = window.confirm(
      "Lock session now?\n\nThis ends your login session on this device.\n(Your local keys are not deleted.)"
    );
    if (!ok) return;

    const sk = (s as any)?.sessionKey;
    if (sk) {
      try {
        await revokeSessionKeyOnChain({ account, sessionKey: String(sk) });
      } catch {
        // best-effort only
      }
    }

    endSession();
    clearNonceReservation(account);
    refresh();
  }

  async function forgetKeys() {
    const s = getSession();
    if (!s) return;
    const account = normalizeAccount(s.account);
    const ok = window.confirm(`Forget local keys for ${account}?\n\nThis cannot be undone.`);
    if (!ok) return;
    clearKeypair(account);
    clearNonceReservation(account);
    refresh();
  }

  useEffect(() => {
    refresh();
    const id = setInterval(refresh, 1000);
    return () => clearInterval(id);
  }, []);

  if (!acct) {
    return <div style={{ fontSize: 13, opacity: 0.7 }}>Not logged in</div>;
  }

  return (
    <div
      style={{
        background: "#f4f4f4",
        padding: "6px 10px",
        borderRadius: 20,
        fontSize: 13,
        display: "flex",
        gap: 10,
        alignItems: "center",
        flexWrap: "wrap",
      }}
    >
      <span style={{ fontWeight: 600 }}>{acct}</span>
      <span style={{ opacity: 0.7 }}>TTL: {ttl}s</span>
      <span style={{ opacity: 0.7 }}>{hasKey ? "🔐 local key" : "⚠ no local key"}</span>
      <span style={{ opacity: 0.7 }}>{hasSessionKey ? "🪪 session key" : "⚠ no session key"}</span>

      {actionStatus ? <span style={{ opacity: 0.75 }}>{actionStatus}</span> : null}

      <div style={{ display: "flex", gap: 6, marginLeft: 6 }}>
        {!hasSessionKey && hasKey ? (
          <button
            onClick={loginNow}
            style={{
              padding: "4px 8px",
              borderRadius: 10,
              border: "1px solid #999",
              background: "white",
              cursor: "pointer",
            }}
            title="Issue an on-chain session key for this device"
          >
            Login on this device
          </button>
        ) : null}

        <button
          onClick={lockNow}
          style={{
            padding: "4px 8px",
            borderRadius: 10,
            border: "1px solid #999",
            background: "white",
            cursor: "pointer",
          }}
          title="End session"
        >
          Lock now
        </button>

        {hasKey ? (
          <button
            onClick={forgetKeys}
            style={{
              padding: "4px 8px",
              borderRadius: 10,
              border: "1px solid #999",
              background: "white",
              cursor: "pointer",
            }}
            title="Forget local keys for this account"
          >
            Forget keys
          </button>
        ) : null}
      </div>
    </div>
  );
}
