import React, { useEffect, useMemo, useState } from "react";

import {
  getApiBaseUrl,
  getEmailOracleBaseUrl,
  setApiBaseUrl,
  weall,
} from "../api/weall";
import TurnstileWidget from "../components/TurnstileWidget";
import {
  getAuthHeaders,
  getKeypair,
  getSession,
  loginOnThisDevice,
  submitSignedTx,
} from "../auth/session";
import {
  generateKeypair,
  normalizeAccount,
  saveKeypair,
  signDetachedB64,
  validateAccountId,
} from "../auth/keys";
import { useAccount } from "../context/AccountContext";
import { nav } from "../lib/router";

type RelayToken = {
  payload?: {
    version?: number;
    type?: string;
    challenge_id?: string;
    account_id?: string;
    operator_account_id?: string | null;
    email_commitment?: string;
    issued_at_ms?: number;
    expires_at_ms?: number;
    relay_account_id?: string;
    relay_pubkey?: string;
  };
  signature?: string;
};

type OnboardingStage =
  | "collect"
  | "code-sent"
  | "verified-backup"
  | "provisioning"
  | "done";

function prettyErr(e: any): string {
  return (
    e?.body?.error?.message ||
    e?.body?.message ||
    e?.data?.error?.message ||
    e?.message ||
    String(e || "error")
  );
}

function statusPill(label: string, active: boolean, danger = false): JSX.Element {
  return (
    <span className={`statusPill ${active ? "ok" : ""} ${danger ? "danger" : ""}`}>
      {label}
    </span>
  );
}

function emailLooksValid(value: string): boolean {
  const v = String(value || "").trim().toLowerCase();
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
}

function canonicalEmailReceiptMessage(receipt: Record<string, unknown>): Uint8Array {
  const obj = {
    version: Number(receipt.version || 1),
    kind: String(receipt.kind || "poh_email_tier1"),
    worker_account_id: String(receipt.worker_account_id || ""),
    worker_pubkey: String(receipt.worker_pubkey || ""),
    subject_account_id: String(receipt.subject_account_id || ""),
    email_commitment: String(receipt.email_commitment || ""),
    request_id: String(receipt.request_id || ""),
    nonce: String(receipt.nonce || ""),
    issued_at_ms: Number(receipt.issued_at_ms || 0),
    expires_at_ms: Number(receipt.expires_at_ms || 0),
  };
  return new TextEncoder().encode(JSON.stringify(obj));
}

function buildOperatorReceipt(
  account: string,
  kp: { pubkeyB64: string; secretKeyB64: string },
  relayToken: RelayToken,
) {
  const payload = relayToken?.payload || {};
  const receipt: Record<string, unknown> = {
    version: 1,
    kind: "poh_email_tier1",
    worker_account_id: account,
    worker_pubkey: kp.pubkeyB64,
    subject_account_id: account,
    email_commitment: String(payload.email_commitment || ""),
    request_id: String(payload.challenge_id || ""),
    nonce: String(relayToken?.signature || ""),
    issued_at_ms: Number(payload.issued_at_ms || 0),
    expires_at_ms: Number(payload.expires_at_ms || 0),
    relay_token: relayToken,
  };
  receipt.signature = signDetachedB64(
    kp.secretKeyB64,
    canonicalEmailReceiptMessage(receipt),
  );
  return receipt;
}

function sectionStyle(): React.CSSProperties {
  return {
    border: "1px solid var(--border)",
    background: "linear-gradient(180deg, rgba(8,22,35,0.94), rgba(6,14,24,0.94))",
    borderRadius: 24,
    padding: 24,
    boxShadow: "var(--shadow)",
  };
}

function gridStyle(columns = "1fr 1fr"): React.CSSProperties {
  return {
    display: "grid",
    gap: 20,
    gridTemplateColumns: columns,
  };
}

function codeCardStyle(): React.CSSProperties {
  return {
    padding: 14,
    borderRadius: 16,
    border: "1px solid var(--border)",
    background: "rgba(255,255,255,0.03)",
  };
}

async function copyText(value: string): Promise<void> {
  await navigator.clipboard.writeText(value);
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => window.setTimeout(resolve, ms));
}

async function waitForRegistered(account: string, base: string, timeoutMs = 30000): Promise<void> {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    try {
      const reg: any = await weall.accountRegistered(account, base);
      if (reg?.registered === true) return;
    } catch {
      // ignore and retry
    }
    await sleep(750);
  }
  throw new Error("Timed out waiting for account registration to commit.");
}

async function waitForSessionPresence(account: string, base: string, timeoutMs = 30000): Promise<void> {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    try {
      const acct: any = await weall.account(account, base);
      const state = acct?.state || {};
      const sessions = state?.session_keys;
      if (sessions && typeof sessions === "object" && Object.keys(sessions).length > 0) {
        return;
      }
    } catch {
      // ignore and retry
    }
    await sleep(750);
  }
  throw new Error("Timed out waiting for session issuance to commit.");
}

async function waitForTierAtLeast(account: string, base: string, tier: number, timeoutMs = 30000): Promise<void> {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    try {
      const acct: any = await weall.account(account, base);
      const current = Number(acct?.state?.poh_tier || 0);
      if (current >= tier) return;
    } catch {
      // ignore and retry
    }
    await sleep(750);
  }
  throw new Error(`Timed out waiting for PoH tier ${tier} to commit.`);
}

export default function LoginPage(): JSX.Element {
  const { refresh } = useAccount();

  const turnstileSiteKey = String((import.meta as any)?.env?.VITE_TURNSTILE_SITE_KEY || "").trim();

  const [apiBase, setApiBase] = useState<string>(getApiBaseUrl() || "http://127.0.0.1:8000");
  const [oracleBase] = useState<string>(getEmailOracleBaseUrl() || "http://127.0.0.1:8787");

  const [accountInput, setAccountInput] = useState<string>("@demo");
  const [emailInput, setEmailInput] = useState<string>("");
  const [health, setHealth] = useState<any>(null);
  const [accountView, setAccountView] = useState<any>(null);
  const [registered, setRegistered] = useState<boolean>(false);

  const [turnstileToken, setTurnstileToken] = useState<string>("");
  const [challengeId, setChallengeId] = useState<string>("");
  const [emailCode, setEmailCode] = useState<string>("");

  const [stage, setStage] = useState<OnboardingStage>("collect");
  const [busy, setBusy] = useState<string>("");
  const [result, setResult] = useState<string>("");
  const [error, setError] = useState<string>("");
  const [provisionLog, setProvisionLog] = useState<string[]>([]);

  const [relayToken, setRelayToken] = useState<RelayToken | null>(null);
  const [createdPubkeyB64, setCreatedPubkeyB64] = useState<string>("");
  const [createdSecretKeyB64, setCreatedSecretKeyB64] = useState<string>("");
  const [showPrivateKey, setShowPrivateKey] = useState<boolean>(false);
  const [backupConfirmed, setBackupConfirmed] = useState<boolean>(false);

  const activeAccount = useMemo(() => normalizeAccount(accountInput), [accountInput]);
  const session = getSession();
  const sessionPresent = !!session?.account;
  const liveKeypair = useMemo(
    () => (activeAccount ? getKeypair(activeAccount) : null),
    [activeAccount, createdPubkeyB64, createdSecretKeyB64, result],
  );

  const keypair = useMemo(() => {
    if (createdPubkeyB64 && createdSecretKeyB64) {
      return {
        pubkeyB64: createdPubkeyB64,
        secretKeyB64: createdSecretKeyB64,
      };
    }
    return liveKeypair;
  }, [createdPubkeyB64, createdSecretKeyB64, liveKeypair]);

  const hasSigner = !!keypair?.pubkeyB64 && !!keypair?.secretKeyB64;
  const isApiReachable = health?.ok === true;
  const pohTier = Math.max(0, Number(accountView?.state?.poh_tier || accountView?.poh_tier || 0));
  const emailReady = emailLooksValid(emailInput);
  const usernameValid = validateAccountId(accountInput).ok;

  const canSendCode =
    usernameValid &&
    emailReady &&
    isApiReachable &&
    busy === "" &&
    (turnstileSiteKey ? !!turnstileToken.trim() : true);

  const canVerifyCode =
    stage === "code-sent" &&
    !!challengeId.trim() &&
    !!emailCode.trim() &&
    isApiReachable &&
    busy === "";

  const canContinueAfterBackup =
    stage === "verified-backup" &&
    backupConfirmed &&
    !!relayToken &&
    !!keypair?.pubkeyB64 &&
    !!keypair?.secretKeyB64 &&
    busy === "";

  async function loadState(accountOverride?: string): Promise<void> {
    const acct = normalizeAccount(accountOverride || activeAccount);

    try {
      const h = await weall.status(apiBase).catch(async () => await weall.health(apiBase));
      setHealth(h);
    } catch (e: any) {
      setHealth({ ok: false, error: prettyErr(e) });
    }

    if (!acct) {
      setRegistered(false);
      setAccountView(null);
      return;
    }

    try {
      const [reg, view] = await Promise.all([
        weall.accountRegistered(acct, apiBase).catch(() => ({ registered: false })),
        weall.account(acct, apiBase).catch(() => null),
      ]);
      setRegistered(reg?.registered === true);
      setAccountView(view);
    } catch {
      setRegistered(false);
      setAccountView(null);
    }
  }

  useEffect(() => {
    void loadState();
  }, [activeAccount, apiBase]);

  async function refreshAll(message?: string): Promise<void> {
    await refresh();
    await loadState();
    if (message) setResult(message);
  }

  function saveApiBase(): void {
    try {
      const trimmed = String(apiBase || "").trim();
      if (!trimmed) throw new Error("API base is required.");
      setApiBaseUrl(trimmed);
      setApiBase(trimmed);
      setError("");
      setResult("Client API base saved.");
      void loadState();
    } catch (e: any) {
      setError(prettyErr(e));
    }
  }

  async function checkAccountState(): Promise<void> {
    try {
      setBusy("check");
      setError("");
      await loadState();
      setResult("Account state refreshed.");
    } catch (e: any) {
      setError(prettyErr(e));
    } finally {
      setBusy("");
    }
  }

  async function beginEmailVerification(): Promise<void> {
    try {
      setBusy("email-begin");
      setError("");
      setResult("");
      setProvisionLog([]);

      const v = validateAccountId(accountInput);
      if (!v.ok) throw new Error(`Invalid username: ${v.reason}`);
      if (!emailLooksValid(emailInput)) throw new Error("Enter a valid email address.");

      const res: any = await weall.emailOracleStart(
        {
          account_id: v.normalized,
          operator_account_id: v.normalized,
          email: String(emailInput || "").trim().toLowerCase(),
          turnstile_token: turnstileToken.trim() || undefined,
        },
        oracleBase,
      );

      const id = String(res?.challenge_id || "");
      if (!id) throw new Error("Challenge id missing from relay response.");

      setChallengeId(id);
      setStage("code-sent");
      setResult(`Verification code sent to ${String(emailInput).trim().toLowerCase()}.`);
    } catch (e: any) {
      setError(prettyErr(e));
    } finally {
      setBusy("");
    }
  }

  async function verifyEmailAndPrepareBackup(): Promise<void> {
    try {
      setBusy("email-confirm");
      setError("");
      setResult("");

      const v = validateAccountId(accountInput);
      if (!v.ok) throw new Error(`Invalid username: ${v.reason}`);
      if (!challengeId.trim() || !emailCode.trim()) {
        throw new Error("Challenge id and email code are required.");
      }

      const verifyRes: any = await weall.emailOracleVerify(
        {
          challenge_id: challengeId.trim(),
          code: emailCode.trim(),
        },
        oracleBase,
      );

      const nextRelayToken = verifyRes?.relay_token;
      if (!nextRelayToken?.payload || !nextRelayToken?.signature) {
        throw new Error("Invalid relay token returned by email relay.");
      }

      const kp = generateKeypair();
      saveKeypair(v.normalized, kp);

      setRelayToken(nextRelayToken);
      setCreatedPubkeyB64(kp.pubkeyB64);
      setCreatedSecretKeyB64(kp.secretKeyB64);
      setShowPrivateKey(true);
      setBackupConfirmed(false);
      setStage("verified-backup");
      setResult("Email verified. Save your private key before continuing.");
      await refreshAll();
    } catch (e: any) {
      setError(prettyErr(e));
    } finally {
      setBusy("");
    }
  }

  async function completeOnboarding(): Promise<void> {
    try {
      setBusy("provision");
      setError("");
      setResult("");
      setStage("provisioning");
      setProvisionLog([]);

      const v = validateAccountId(accountInput);
      if (!v.ok) throw new Error(`Invalid username: ${v.reason}`);
      if (!relayToken) throw new Error("Missing verified relay token.");
      if (!keypair?.pubkeyB64 || !keypair?.secretKeyB64) throw new Error("Missing local signer.");

      const lines: string[] = [];
      const pushLine = (line: string) => {
        lines.push(line);
        setProvisionLog([...lines]);
      };

      pushLine("Local Ed25519 signer ready.");
      pushLine("Checking whether the account already exists on-chain...");

      let isAlreadyRegistered = false;
      try {
        const reg: any = await weall.accountRegistered(v.normalized, apiBase);
        isAlreadyRegistered = reg?.registered === true;
      } catch {
        isAlreadyRegistered = false;
      }

      if (!isAlreadyRegistered) {
        pushLine("Registering account on-chain...");
        await submitSignedTx({
          account: v.normalized,
          tx_type: "ACCOUNT_REGISTER",
          payload: { pubkey: keypair.pubkeyB64 },
          parent: null,
          base: apiBase,
        });
        pushLine("Registration accepted. Waiting for account state to commit...");
        await waitForRegistered(v.normalized, apiBase);
        pushLine("Account registration committed.");
      } else {
        pushLine("Account already registered. Skipping registration.");
      }

      pushLine("Issuing browser session...");
      await loginOnThisDevice({
        account: v.normalized,
        ttlSeconds: 24 * 60 * 60,
        base: apiBase,
      });
      pushLine("Session issuance accepted. Waiting for session state to commit...");
      await waitForSessionPresence(v.normalized, apiBase);
      pushLine("Browser session committed.");

      pushLine("Building Tier 1 email receipt...");
      const receipt = buildOperatorReceipt(v.normalized, keypair, relayToken);

      const skeleton: any = await weall.pohEmailReceiptTxSubmit(
        {
          account_id: v.normalized,
          receipt,
        },
        apiBase,
        getAuthHeaders(v.normalized),
      );

      const tx = skeleton?.tx;
      if (!tx?.tx_type) {
        throw new Error("Invalid receipt-submit skeleton.");
      }

      pushLine("Submitting Tier 1 email receipt to the chain...");
      await submitSignedTx({
        account: v.normalized,
        tx_type: String(tx.tx_type),
        payload: tx.payload || {},
        parent: tx.parent ?? null,
        base: apiBase,
      });
      pushLine("Tier 1 receipt accepted. Waiting for PoH tier to commit...");
      await waitForTierAtLeast(v.normalized, apiBase, 1);
      pushLine("PoH Tier 1 committed.");

      await refreshAll("Onboarding complete.");
      setStage("done");
      pushLine("Opening the app...");
      window.setTimeout(() => nav("/home"), 500);
    } catch (e: any) {
      setStage("verified-backup");
      setError(prettyErr(e));
    } finally {
      setBusy("");
    }
  }

  const title =
    stage === "done"
      ? "Identity ready"
      : stage === "verified-backup"
      ? "Save your keys before WeAll opens up"
      : "Set up identity before the app opens up";

  return (
    <div className="container pageNarrow" style={{ paddingTop: 28, paddingBottom: 48 }}>
      <div className="pageStack" style={{ gap: 24 }}>
        <section style={sectionStyle()}>
          <div className="eyebrow">Login / device setup</div>
          <h1 style={{ margin: "10px 0 14px", fontSize: 56, lineHeight: 1.05 }}>{title}</h1>
          <p style={{ margin: 0, maxWidth: 920, color: "var(--muted-strong)", fontSize: 24, lineHeight: 1.6 }}>
            Smooth onboarding for future users: choose a handle, verify email, save the generated
            Ed25519 keys, and let the client finish account creation automatically.
          </p>

          <div
            style={{
              marginTop: 24,
              display: "grid",
              gap: 12,
              gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))",
            }}
          >
            {statusPill("API reachable", isApiReachable)}
            {statusPill(activeAccount || "@no-account", !!activeAccount)}
            {statusPill("Signer ready", hasSigner)}
            {statusPill("Registered", registered)}
            {statusPill("Session present", sessionPresent)}
            {statusPill(`PoH tier ${pohTier}`, pohTier > 0)}
          </div>
        </section>

        <section style={sectionStyle()}>
          <div className="eyebrow">Network target</div>
          <h2 className="cardTitle" style={{ marginTop: 10 }}>Client API base</h2>
          <div className="pageStack" style={{ gap: 14 }}>
            <input
              value={apiBase}
              onChange={(e) => setApiBase(e.target.value)}
              placeholder="http://127.0.0.1:8000"
            />
            <div style={{ display: "flex", flexWrap: "wrap", gap: 10 }}>
              <button onClick={saveApiBase}>Save API base</button>
              <button
                onClick={() => {
                  setApiBase("http://127.0.0.1:8000");
                  setApiBaseUrl("http://127.0.0.1:8000");
                  setResult("Using local backend.");
                  setError("");
                  void loadState();
                }}
              >
                Use local backend
              </button>
              <button disabled={busy === "check"} onClick={checkAccountState}>
                Check account state
              </button>
            </div>
            <div style={{ color: "var(--muted)", fontSize: 14 }}>
              Email relay base: <code>{oracleBase || "(not configured)"}</code>
            </div>
          </div>
        </section>

        <section style={sectionStyle()}>
          <div className="eyebrow">New user onboarding</div>
          <div style={gridStyle("1fr 1fr")}>
            <div className="pageStack" style={{ gap: 14 }}>
              <label className="pageStack" style={{ gap: 8 }}>
                <span>Username</span>
                <input
                  value={accountInput}
                  onChange={(e) => setAccountInput(e.target.value)}
                  placeholder="@yourname"
                  disabled={stage === "provisioning" || stage === "done"}
                />
              </label>

              <label className="pageStack" style={{ gap: 8 }}>
                <span>Email address</span>
                <input
                  value={emailInput}
                  onChange={(e) => setEmailInput(e.target.value)}
                  placeholder="name@example.com"
                  disabled={stage === "provisioning" || stage === "done"}
                />
              </label>

              {turnstileSiteKey ? (
                <div className="pageStack" style={{ gap: 8 }}>
                  <span>Turnstile challenge</span>
                  <TurnstileWidget
                    onToken={(token) => setTurnstileToken(token)}
                    onExpired={() => setTurnstileToken("")}
                    onError={() => setTurnstileToken("")}
                  />
                </div>
              ) : (
                <div
                  style={{
                    padding: 14,
                    borderRadius: 16,
                    border: "1px solid var(--border)",
                    background: "rgba(255,255,255,0.03)",
                    color: "var(--muted)",
                  }}
                >
                  Turnstile site key not configured in the frontend env. Local dev can still work if
                  the relay allows bypass.
                </div>
              )}

              <button disabled={!canSendCode} onClick={beginEmailVerification}>
                {busy === "email-begin" ? "Sending code..." : "Send verification code"}
              </button>
            </div>

            <div className="pageStack" style={{ gap: 14 }}>
              <label className="pageStack" style={{ gap: 8 }}>
                <span>Challenge id</span>
                <input
                  value={challengeId}
                  onChange={(e) => setChallengeId(e.target.value)}
                  placeholder="Returned by /start"
                  disabled={stage === "provisioning" || stage === "done"}
                />
              </label>

              <label className="pageStack" style={{ gap: 8 }}>
                <span>Email code</span>
                <input
                  value={emailCode}
                  onChange={(e) => setEmailCode(e.target.value)}
                  placeholder="000000"
                  disabled={stage === "provisioning" || stage === "done"}
                />
              </label>

              <button disabled={!canVerifyCode} onClick={verifyEmailAndPrepareBackup}>
                {busy === "email-confirm" ? "Verifying..." : "Verify email and continue"}
              </button>

              <div style={{ color: "var(--muted)", fontSize: 14 }}>
                After verification, the browser will generate a fresh Ed25519 keypair locally and
                show it on-screen so the user can save it before account creation proceeds.
              </div>
            </div>
          </div>
        </section>

        {stage === "verified-backup" && keypair ? (
          <section style={sectionStyle()}>
            <div className="eyebrow">Key backup required</div>
            <h2 className="cardTitle" style={{ marginTop: 10 }}>Write these keys down now</h2>
            <p style={{ color: "var(--muted-strong)", lineHeight: 1.65 }}>
              The public key is safe to register on-chain. The private key must stay private. Save
              both before continuing. This is the only copy the user controls.
            </p>

            <div style={gridStyle("repeat(auto-fit, minmax(320px, 1fr))")}>
              <div style={codeCardStyle()}>
                <div className="eyebrow" style={{ marginBottom: 8 }}>Account</div>
                <div style={{ fontSize: 26, fontWeight: 700 }}>{activeAccount}</div>
              </div>

              <div style={codeCardStyle()}>
                <div className="eyebrow" style={{ marginBottom: 8 }}>Public key (Base64)</div>
                <code style={{ display: "block", wordBreak: "break-all", fontSize: 13 }}>
                  {keypair.pubkeyB64}
                </code>
                <div style={{ marginTop: 12 }}>
                  <button
                    onClick={async () => {
                      try {
                        await copyText(keypair.pubkeyB64);
                        setResult("Public key copied to clipboard.");
                        setError("");
                      } catch (e: any) {
                        setError(prettyErr(e));
                      }
                    }}
                  >
                    Copy public key
                  </button>
                </div>
              </div>

              <div style={{ ...codeCardStyle(), gridColumn: "1 / -1" }}>
                <div className="eyebrow" style={{ marginBottom: 8 }}>Private key (Base64)</div>
                <code style={{ display: "block", wordBreak: "break-all", fontSize: 13 }}>
                  {showPrivateKey ? keypair.secretKeyB64 : "Hidden — click below to reveal"}
                </code>
                <div style={{ display: "flex", flexWrap: "wrap", gap: 10, marginTop: 12 }}>
                  <button onClick={() => setShowPrivateKey((v) => !v)}>
                    {showPrivateKey ? "Hide private key" : "Show private key"}
                  </button>
                  <button
                    onClick={async () => {
                      try {
                        await copyText(keypair.secretKeyB64);
                        setResult("Private key copied to clipboard.");
                        setError("");
                      } catch (e: any) {
                        setError(prettyErr(e));
                      }
                    }}
                  >
                    Copy private key
                  </button>
                </div>
              </div>
            </div>

            <label
              style={{
                display: "flex",
                gap: 12,
                alignItems: "flex-start",
                marginTop: 18,
                color: "var(--muted-strong)",
              }}
            >
              <input
                type="checkbox"
                checked={backupConfirmed}
                onChange={(e) => setBackupConfirmed(e.target.checked)}
              />
              <span>I saved the private key and understand the backend does not keep a copy.</span>
            </label>

            <div style={{ marginTop: 18 }}>
              <button disabled={!canContinueAfterBackup} onClick={completeOnboarding}>
                Finish account setup automatically
              </button>
            </div>
          </section>
        ) : null}

        {(stage === "provisioning" || stage === "done") && (
          <section style={sectionStyle()}>
            <div className="eyebrow">Provisioning</div>
            <h2 className="cardTitle" style={{ marginTop: 10 }}>
              {stage === "done" ? "Setup complete" : "Creating the account automatically"}
            </h2>
            <div className="pageStack" style={{ gap: 10, marginTop: 12 }}>
              {provisionLog.map((line, index) => (
                <div
                  key={`${index}-${line}`}
                  style={{
                    padding: 12,
                    borderRadius: 14,
                    border: "1px solid var(--border)",
                    background: "rgba(255,255,255,0.03)",
                  }}
                >
                  {line}
                </div>
              ))}
            </div>
          </section>
        )}

        {(result || error) && (
          <section style={sectionStyle()}>
            <div className="eyebrow">Last action</div>
            {result ? (
              <div
                style={{
                  marginTop: 12,
                  padding: 14,
                  borderRadius: 16,
                  border: "1px solid rgba(134,239,172,0.2)",
                  background: "rgba(134,239,172,0.08)",
                  color: "var(--text)",
                  whiteSpace: "pre-wrap",
                  wordBreak: "break-word",
                }}
              >
                {result}
              </div>
            ) : null}
            {error ? (
              <div
                style={{
                  marginTop: 12,
                  padding: 14,
                  borderRadius: 16,
                  border: "1px solid rgba(251,113,133,0.22)",
                  background: "rgba(251,113,133,0.08)",
                  color: "var(--text)",
                  whiteSpace: "pre-wrap",
                  wordBreak: "break-word",
                }}
              >
                {error}
              </div>
            ) : null}
          </section>
        )}

        <section style={{ display: "flex", justifyContent: "flex-end", gap: 10 }}>
          <button onClick={() => nav("/poh")} disabled={!sessionPresent}>
            Open PoH
          </button>
          <button onClick={() => nav("/home")} disabled={!sessionPresent}>
            Open app
          </button>
        </section>
      </div>
    </div>
  );
}
