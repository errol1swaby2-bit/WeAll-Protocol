import React, { useEffect, useMemo, useRef, useState } from "react";
import { getApiBaseUrl, weall } from "../api/weall";
import { normalizeAccount } from "../lib/account";
import { loadKeypair, saveKeypair, deleteKeypair, signDetachedB64 } from "../lib/keys";

type Step = "start" | "sent" | "done";

export default function PohPage(): JSX.Element {
  const apiBase = useMemo(() => getApiBaseUrl(), []);
  const [accountRaw, setAccountRaw] = useState("@alice");
  const account = useMemo(() => normalizeAccount(accountRaw), [accountRaw]);

  const [email, setEmail] = useState("");
  const [code, setCode] = useState("");

  const [step, setStep] = useState<Step>("start");

  const [startErr, setStartErr] = useState("");
  const [confirmErr, setConfirmErr] = useState("");

  const [onChain, setOnChain] = useState<any>(null);
  const [polling, setPolling] = useState(false);

  const pollRef = useRef<number | null>(null);

  const [kp, setKp] = useState<{ pubkeyB64: string; secretKeyB64: string } | null>(null);

  const pubkeyB64 = kp?.pubkeyB64 || "";
  const hasSecret = Boolean(kp?.secretKeyB64);

  const onChainText = useMemo(() => {
    if (!onChain || onChain.ok !== true) return "unknown";
    const tier = (onChain.tier ?? onChain.poh_tier ?? "unknown") as any;
    if (tier === 0 || tier === "0") return "Tier 0";
    if (tier === 1 || tier === "1") return "Tier 1";
    if (tier === 2 || tier === "2") return "Tier 2";
    if (tier === 3 || tier === "3") return "Tier 3";
    return String(tier);
  }, [onChain]);

  async function refreshOnChain(): Promise<void> {
    try {
      const st = await weall.pohState(account, apiBase);
      setOnChain(st);
    } catch (e) {
      setOnChain({ ok: false, error: String(e) });
    }
  }

  function stopPolling() {
    setPolling(false);
    if (pollRef.current != null) {
      window.clearInterval(pollRef.current);
      pollRef.current = null;
    }
  }

  function startPolling() {
    if (pollRef.current != null) return;
    setPolling(true);
    pollRef.current = window.setInterval(() => {
      refreshOnChain();
    }, 1500);
  }

  async function loadKeys() {
    const k = loadKeypair(account);
    if (k) setKp(k);
  }

  async function generateAndSaveKeys() {
    setStartErr("");
    setConfirmErr("");
    try {
      const kp = await saveKeypair(account);
      setKp(kp);
    } catch (e: any) {
      setStartErr(`Unable to generate keys: ${e?.message ?? String(e)}`);
    }
  }

  async function deleteKeys() {
    setStartErr("");
    setConfirmErr("");
    try {
      deleteKeypair(account);
      setKp(null);
    } catch (e: any) {
      setStartErr(`Unable to delete keys: ${e?.message ?? String(e)}`);
    }
  }

  async function resetFlow() {
    setStartErr("");
    setConfirmErr("");
    setEmail("");
    setCode("");
    setStep("start");
    stopPolling();
    await refreshOnChain();
  }

  useEffect(() => {
    loadKeys();
    refreshOnChain();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    // When account changes, reload keypair from local storage
    loadKeys();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [account]);

  useEffect(() => {
    if (step === "done") startPolling();
    else stopPolling();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [step]);

  async function startEmail(): Promise<void> {
    setStartErr("");
    setConfirmErr("");

    const em = email.trim();
    if (!em) {
      setStartErr("Email is required.");
      return;
    }

    try {
      const nextNonceRes = await weall.accountNonce(account, apiBase);
      const nextNonce = Number(nextNonceRes?.nonce ?? 0);

      const msg = `POH_EMAIL_START:${account}:${em}:${nextNonce}`;
      const sig = hasSecret ? signDetachedB64(kp!.secretKeyB64, msg) : "";

      const res = await weall.pohEmailStart({
        account,
        email: em,
        pubkey: pubkeyB64,
        sig,
        nonce: hasSecret ? nextNonce : 0,
        turnstile_token: null,
      });

      if (!res || (res as any).ok !== true) {
        setStartErr(JSON.stringify(res, null, 2));
        return;
      }

      setStep("sent");
    } catch (e: any) {
      const data = e?.data ? JSON.stringify(e.data) : "";
      setStartErr(`Unable to start.\n${e?.message ?? String(e)}\n${data}`);
    }
  }

  async function confirmEmail(): Promise<void> {
    setStartErr("");
    setConfirmErr("");

    const c = code.trim();
    if (!c) {
      setConfirmErr("Code is required.");
      return;
    }

    try {
      const nextNonceRes = await weall.accountNonce(account, apiBase);
      const nextNonce = Number(nextNonceRes?.nonce ?? 0);

      const msg = `POH_EMAIL_CONFIRM:${account}:${email.trim()}:${c}:${nextNonce}`;
      let sig = "";
      let nonce = 0;
      if (hasSecret) {
        sig = signDetachedB64(kp!.secretKeyB64, msg);
        nonce = nextNonce;
      } else {
        sig = "";
        nonce = 0;
      }

      const res = await weall.pohEmailConfirm({
        account,
        email: email.trim(),
        code: c,
        pubkey: pubkeyB64,
        sig,
        nonce,
        turnstile_token: null,
      });

      if (!res || (res as any).ok !== true) {
        setConfirmErr(JSON.stringify(res, null, 2));
        return;
      }

      setStep("done");
      startPolling();
      await refreshOnChain();
    } catch (e: any) {
      const data = e?.data ? JSON.stringify(e.data) : "";
      setConfirmErr(`Unable to confirm.\n${e?.message ?? String(e)}\n${data}`);
    }
  }

  return (
    <div style={{ fontFamily: "system-ui, -apple-system, Segoe UI, Roboto, sans-serif", padding: 18 }}>
      <h1 style={{ marginTop: 0 }}>WeAll PoH — Email Verification</h1>
      <div style={{ opacity: 0.75, marginBottom: 12 }}>
        API: <span style={{ fontFamily: "monospace" }}>{apiBase}</span>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr auto", gap: 12, alignItems: "end" }}>
        <div>
          <div style={{ fontSize: 12, opacity: 0.8, marginBottom: 4 }}>Account</div>
          <input
            value={accountRaw}
            onChange={(e) => setAccountRaw(e.target.value)}
            style={{ width: "100%", padding: 10, borderRadius: 8, border: "1px solid #ccc", fontFamily: "monospace" }}
          />
          <div style={{ marginTop: 6, fontSize: 12, opacity: 0.75 }}>
            Normalized: <span style={{ fontFamily: "monospace" }}>{account}</span>
          </div>
        </div>

        <div>
          <div style={{ fontSize: 12, opacity: 0.8, marginBottom: 4 }}>Email</div>
          <input
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="you@example.com"
            style={{ width: "100%", padding: 10, borderRadius: 8, border: "1px solid #ccc" }}
          />
          <div style={{ marginTop: 6, fontSize: 12, opacity: 0.75 }}>
            On-chain: <b>{onChainText}</b>
          </div>
        </div>

        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", justifyContent: "flex-end" }}>
          <button onClick={refreshOnChain} style={{ padding: "10px 12px", borderRadius: 8 }}>
            Refresh
          </button>
        </div>
      </div>

      <div style={{ border: "1px solid #ddd", borderRadius: 12, padding: 14, marginTop: 14 }}>
        <div style={{ display: "flex", gap: 10, alignItems: "baseline", flexWrap: "wrap" }}>
          <div style={{ fontWeight: 800 }}>Local keys</div>
          <div style={{ opacity: 0.75, fontFamily: "monospace", fontSize: 12 }}>
            pubkey: {pubkeyB64 ? `${pubkeyB64.slice(0, 18)}…` : "(none)"}
          </div>
          <div style={{ opacity: 0.75, fontSize: 12 }}>{hasSecret ? "has secret (can sign)" : "no secret (recovery mode)"}</div>
        </div>

        <div style={{ display: "flex", gap: 8, marginTop: 10, flexWrap: "wrap" }}>
          <button onClick={generateAndSaveKeys} style={{ padding: "10px 12px", borderRadius: 8 }}>
            Generate keys
          </button>
          <button onClick={deleteKeys} style={{ padding: "10px 12px", borderRadius: 8 }}>
            Delete keys
          </button>
        </div>
      </div>

      <div style={{ border: "1px solid #ddd", borderRadius: 12, padding: 14, marginTop: 14 }}>
        {step === "start" ? (
          <>
            <div style={{ fontWeight: 800, marginBottom: 8 }}>Start</div>
            <button onClick={startEmail} style={{ padding: "10px 12px", borderRadius: 8 }}>
              Send verification email
            </button>

            {startErr ? (
              <pre style={{ marginTop: 10, color: "crimson", whiteSpace: "pre-wrap" }}>{startErr}</pre>
            ) : null}
          </>
        ) : null}

        {step === "sent" ? (
          <>
            <div style={{ fontWeight: 800, marginBottom: 8 }}>Confirm</div>
            <div style={{ marginBottom: 8, fontSize: 13, opacity: 0.85 }}>
              Enter the code you received by email. Blocks are produced automatically by the node.
            </div>
            <input
              value={code}
              onChange={(e) => setCode(e.target.value)}
              placeholder="123456"
              style={{ width: 200, padding: 10, borderRadius: 8, border: "1px solid #ccc", fontFamily: "monospace" }}
            />
            <div style={{ marginTop: 10, display: "flex", gap: 8, flexWrap: "wrap" }}>
              <button onClick={confirmEmail} style={{ padding: "10px 12px", borderRadius: 8 }}>
                Confirm
              </button>
              <button onClick={resetFlow} style={{ padding: "10px 12px", borderRadius: 8 }}>
                Start over
              </button>
            </div>

            {confirmErr ? (
              <pre style={{ marginTop: 10, color: "crimson", whiteSpace: "pre-wrap" }}>{confirmErr}</pre>
            ) : null}
          </>
        ) : null}

        {step === "done" ? (
          <>
            <div style={{ fontWeight: 700 }}>Confirmed. Waiting for tier update…</div>
            <div style={{ marginTop: 6, opacity: 0.8 }}>
              Current: <b>{onChainText}</b>
            </div>
            <div style={{ display: "flex", gap: 8, marginTop: 10, flexWrap: "wrap" }}>
              <button onClick={refreshOnChain} style={{ padding: "10px 12px", borderRadius: 8 }}>
                Refresh
              </button>
              <button onClick={resetFlow} style={{ padding: "10px 12px", borderRadius: 8 }}>
                Start over
              </button>
            </div>
          </>
        ) : null}
      </div>

      <div style={{ marginTop: 14, fontSize: 12, opacity: 0.75 }}>
        Note: This UI is intentionally “thin” — it’s a bootstrap path for keys + PoH email verification while the rest of the app is being hardened.
      </div>
    </div>
  );
}
