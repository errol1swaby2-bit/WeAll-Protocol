import { FormEvent, useEffect, useMemo, useState } from "react"
import TurnstileWidget from "../components/TurnstileWidget"
import {
  ApiError,
  beginPohEmailVerification,
  fetchStatus,
  getApiBase,
  getEmailOracleBaseUrl,
  setApiBase,
  weall,
} from "../api/weall"
import { getKeypair, restoreAccountAndLoginOnThisDevice, submitSignedTx } from "../auth/session"
import { signDetachedB64 } from "../auth/keys"
import { nav } from "../lib/router"

function normalizeAccount(raw: string): string {
  const trimmed = raw.trim().toLowerCase()
  if (!trimmed) return ""
  return trimmed.startsWith("@") ? trimmed : `@${trimmed}`
}

function humanizeApiError(error: unknown, fallback: string): string {
  if (error instanceof ApiError) {
    return error.message || fallback
  }
  if (error instanceof Error) {
    return error.message || fallback
  }
  return fallback
}

type LoginMode = "create" | "existing"

type RelayToken = {
  payload?: {
    challenge_id?: string
    email_commitment?: string
    issued_at_ms?: number
    expires_at_ms?: number
  }
  signature?: string
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
  }
  return new TextEncoder().encode(JSON.stringify(obj))
}

function buildOperatorReceipt(
  account: string,
  kp: { pubkeyB64: string; secretKeyB64: string },
  relayToken: RelayToken,
) {
  const payload = relayToken?.payload || {}
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
  }
  receipt.signature = signDetachedB64(kp.secretKeyB64, canonicalEmailReceiptMessage(receipt))
  return receipt
}

export default function LoginPage() {
  const [apiBaseInput, setApiBaseInput] = useState(getApiBase())
  const [backendReachable, setBackendReachable] = useState<boolean | null>(null)
  const [mode, setMode] = useState<LoginMode>("create")

  const [accountInput, setAccountInput] = useState("")
  const [email, setEmail] = useState("")
  const [code, setCode] = useState("")
  const [turnstileToken, setTurnstileToken] = useState("")
  const [turnstileError, setTurnstileError] = useState("")
  const [turnstileNonce, setTurnstileNonce] = useState(0)

  const [existingAccountInput, setExistingAccountInput] = useState("")
  const [privateKey, setPrivateKey] = useState("")

  const [requestId, setRequestId] = useState("")
  const [step, setStep] = useState<"begin" | "confirm">("begin")

  const [busy, setBusy] = useState(false)
  const [error, setError] = useState("")
  const [notice, setNotice] = useState("")

  const account = useMemo(() => normalizeAccount(accountInput), [accountInput])
  const existingAccount = useMemo(() => normalizeAccount(existingAccountInput), [existingAccountInput])
  const keypair = account ? getKeypair(account) : null
  const emailOracleBase = useMemo(() => getEmailOracleBaseUrl(), [])

  useEffect(() => {
    let cancelled = false
    fetchStatus()
      .then(() => {
        if (!cancelled) setBackendReachable(true)
      })
      .catch(() => {
        if (!cancelled) setBackendReachable(false)
      })
    return () => {
      cancelled = true
    }
  }, [])

  async function handleSaveApiBase() {
    setApiBase(apiBaseInput)
    setError("")
    setNotice("")
    try {
      await fetchStatus()
      setBackendReachable(true)
      setNotice("Backend target saved and reachable.")
    } catch (err) {
      setBackendReachable(false)
      setError(humanizeApiError(err, "Could not reach backend target."))
    }
  }

  async function handleBegin(e: FormEvent) {
    e.preventDefault()
    setError("")
    setNotice("")

    if (!account) {
      setError("Enter a handle.")
      return
    }

    if (!email.trim()) {
      setError("Enter an email address.")
      return
    }

    if (!turnstileToken.trim()) {
      setError("Complete the Turnstile check before requesting your email code.")
      return
    }

    setBusy(true)
    try {
      const res = await beginPohEmailVerification({
        account,
        email: email.trim(),
        turnstile_token: turnstileToken.trim(),
      })

      const nextRequestId =
        typeof res.request_id === "string"
          ? res.request_id.trim()
          : typeof res.challenge_id === "string"
            ? res.challenge_id.trim()
            : ""

      setRequestId(nextRequestId)
      setStep("confirm")
      setNotice("Verification code requested. Check your email and enter the code below.")
      setTurnstileError("")
    } catch (err) {
      setError(
        humanizeApiError(
          err,
          "Could not start email verification. Check the backend response and try again.",
        ),
      )
      setTurnstileToken("")
      setTurnstileNonce((v) => v + 1)
    } finally {
      setBusy(false)
    }
  }

  async function handleConfirm(e: FormEvent) {
    e.preventDefault()
    setError("")
    setNotice("")

    if (!account) {
      setError("Enter a handle.")
      return
    }
    if (!email.trim()) {
      setError("Enter an email address.")
      return
    }
    if (!code.trim()) {
      setError("Enter the verification code.")
      return
    }
    if (!keypair?.pubkeyB64 || !keypair?.secretKeyB64) {
      setError("A local signing key is required to finish email verification.")
      return
    }
    if (!requestId.trim()) {
      setError("Missing verification request id. Request a new code and try again.")
      return
    }

    setBusy(true)
    try {
      const verifyRes: any = await weall.emailOracleVerify(
        {
          challenge_id: requestId.trim(),
          code: code.trim(),
        },
        emailOracleBase,
      )

      const relayToken = verifyRes?.relay_token as RelayToken | undefined
      if (!relayToken?.payload || !relayToken?.signature) {
        throw new Error("Email oracle did not return a relay token.")
      }

      const receipt = buildOperatorReceipt(account, keypair, relayToken)
      const skeleton: any = await weall.pohEmailReceiptTxSubmit({ account_id: account, receipt })
      const txSkeleton = skeleton?.tx
      if (!txSkeleton?.tx_type || !txSkeleton?.payload) {
        throw new Error("Backend did not return a valid receipt-submit transaction skeleton.")
      }

      await submitSignedTx({
        account,
        tx_type: String(txSkeleton.tx_type),
        payload: txSkeleton.payload,
        parent: txSkeleton.parent ?? null,
      })

      setNotice("Email confirmed and Tier 1 submission sent. Continue into the app.")
      nav("/feed")
    } catch (err) {
      setError(
        humanizeApiError(
          err,
          "Could not finish email verification. Check the code, oracle, and backend receipt-submit route.",
        ),
      )
    } finally {
      setBusy(false)
    }
  }

  async function handleExistingLogin(e: FormEvent) {
    e.preventDefault()
    setError("")
    setNotice("")

    if (!existingAccount) {
      setError("Enter the existing account handle.")
      return
    }
    if (!privateKey.trim()) {
      setError("Paste the private key for that account.")
      return
    }

    setBusy(true)
    try {
      await restoreAccountAndLoginOnThisDevice({
        account: existingAccount,
        secretKeyB64: privateKey.trim(),
      })
      setNotice("Fresh device session created. Redirecting to your feed.")
      nav("/feed")
    } catch (err) {
      setError(
        humanizeApiError(
          err,
          "Could not create a fresh session for this account. Confirm the handle, private key, and backend status.",
        ),
      )
    } finally {
      setBusy(false)
    }
  }

  return (
    <main className="page-shell">
      <section className="panel">
        <p className="eyebrow">Access</p>
        <h1>Join or log in</h1>
        <p className="muted">
          Use email verification only for new-account onboarding. Existing accounts log in with the account handle and private key, and each successful login creates a fresh device session.
        </p>

        <div className="stack-md">
          <label className="field">
            <span>Client API base</span>
            <input
              value={apiBaseInput}
              onChange={(e) => setApiBaseInput(e.target.value)}
              placeholder="http://localhost:8000"
            />
          </label>

          <div className="row gap-sm wrap">
            <button type="button" onClick={handleSaveApiBase}>
              Save API base
            </button>
          </div>

          <p className="muted">
            Current backend status:{" "}
            {backendReachable === null ? "checking" : backendReachable ? "reachable" : "unreachable"}
          </p>
        </div>
      </section>

      <section className="panel stack-md">
        <div className="row gap-sm wrap">
          <button
            type="button"
            className={mode === "create" ? "" : "secondary"}
            onClick={() => {
              setMode("create")
              setError("")
              setNotice("")
            }}
          >
            Create new account
          </button>
          <button
            type="button"
            className={mode === "existing" ? "" : "secondary"}
            onClick={() => {
              setMode("existing")
              setError("")
              setNotice("")
            }}
          >
            Log in with private key
          </button>
        </div>

        {mode === "create" ? (
          <>
            <p className="eyebrow">Email onboarding</p>
            <form onSubmit={step === "begin" ? handleBegin : handleConfirm} className="stack-md">
              <label className="field">
                <span>Handle</span>
                <input
                  value={accountInput}
                  onChange={(e) => setAccountInput(e.target.value)}
                  placeholder="@yourname"
                  autoComplete="off"
                />
              </label>

              <label className="field">
                <span>Email address</span>
                <input
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="you@example.com"
                  autoComplete="email"
                  type="email"
                />
              </label>

              {step === "begin" ? (
                <div className="field">
                  <span>Human check</span>
                  <TurnstileWidget
                    key={turnstileNonce}
                    onToken={(token) => {
                      setTurnstileToken(token)
                      setTurnstileError("")
                    }}
                    onError={() => {
                      setTurnstileToken("")
                      setTurnstileError("Turnstile could not be verified. Reload the widget and try again.")
                    }}
                    onExpired={() => {
                      setTurnstileToken("")
                      setTurnstileError(
                        "Turnstile expired. Complete the challenge again before requesting an email code.",
                      )
                    }}
                  />
                  <p className="muted">
                    This shared Cloudflare Turnstile check protects the protocol email worker from abuse.
                  </p>
                  {turnstileError ? <p className="error-text">{turnstileError}</p> : null}
                </div>
              ) : null}

              {step === "confirm" ? (
                <label className="field">
                  <span>Verification code</span>
                  <input
                    value={code}
                    onChange={(e) => setCode(e.target.value)}
                    placeholder="123456"
                    autoComplete="one-time-code"
                    inputMode="numeric"
                  />
                </label>
              ) : null}

              <div className="row gap-sm wrap">
                {step === "begin" ? (
                  <button type="submit" disabled={busy || backendReachable === false}>
                    {busy ? "Sending code…" : "Send verification code"}
                  </button>
                ) : (
                  <>
                    <button type="submit" disabled={busy || backendReachable === false}>
                      {busy ? "Confirming…" : "Confirm code"}
                    </button>
                    <button
                      type="button"
                      className="secondary"
                      onClick={() => {
                        setStep("begin")
                        setCode("")
                        setError("")
                        setNotice("")
                        setTurnstileToken("")
                        setTurnstileNonce((v) => v + 1)
                      }}
                    >
                      Start over
                    </button>
                  </>
                )}
              </div>
            </form>

            {requestId ? <p className="muted">Request ID: {requestId}</p> : null}
          </>
        ) : (
          <>
            <p className="eyebrow">Existing account</p>
            <form onSubmit={handleExistingLogin} className="stack-md">
              <label className="field">
                <span>Handle</span>
                <input
                  value={existingAccountInput}
                  onChange={(e) => setExistingAccountInput(e.target.value)}
                  placeholder="@yourname"
                  autoComplete="username"
                />
              </label>

              <label className="field">
                <span>Private key</span>
                <textarea
                  value={privateKey}
                  onChange={(e) => setPrivateKey(e.target.value)}
                  placeholder="Paste the 64-byte base64 private key for this account"
                  rows={5}
                  spellCheck={false}
                />
              </label>

              <p className="muted">
                The private key stays local to this browser. Each successful login issues a brand-new
                device session instead of reusing an old one.
              </p>

              <div className="row gap-sm wrap">
                <button type="submit" disabled={busy || backendReachable === false}>
                  {busy ? "Logging in…" : "Log in"}
                </button>
              </div>
            </form>
          </>
        )}

        {notice ? <p className="notice-text">{notice}</p> : null}
        {error ? <p className="error-text">{error}</p> : null}
      </section>
    </main>
  )
}
