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
import {
  ensureKeypair,
  getKeypair,
  getSession,
  restoreAccountAndLoginOnThisDevice,
  submitSignedTx,
} from "../auth/session"
import { signDetachedB64 } from "../auth/keys"
import { consumeReturnTo, nav } from "../lib/router"
import { useAppConfig } from "../lib/config"
import { useSignerSubmissionBusy } from "../hooks/useSignerSubmissionBusy"

function normalizeAccount(raw: string): string {
  const trimmed = raw.trim().toLowerCase()
  if (!trimmed) return ""
  return trimmed.startsWith("@") ? trimmed : `@${trimmed}`
}

function humanizeApiError(error: unknown, fallback: string): string {
  if (error instanceof ApiError) return error.message || fallback
  if (error instanceof Error) return error.message || fallback
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

type CheckpointTone = "good" | "pending" | "warn"

type Checkpoint = {
  title: string
  detail: string
  tone: CheckpointTone
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


type DevBootstrapStep = {
  label?: string
  href?: string
}

type DevBootstrapManifest = {
  account?: string
  apiBase?: string
  pubkeyB64?: string
  sessionTtlSeconds?: number
  note?: string
  seededGroup?: { group_id?: string; member_visible?: boolean; visibility?: string }
  seededProposal?: { proposal_id?: string; stage?: string }
  seededDispute?: { dispute_id?: string; stage?: string; juror?: string; juror_status?: string; target_id?: string }
  recommendedPath?: DevBootstrapStep[]
  fallbackInstructions?: string[]
  resetInstructions?: string[]
}

function manifestSteps(value: DevBootstrapManifest | null): DevBootstrapStep[] {
  const items = Array.isArray(value?.recommendedPath) ? value?.recommendedPath : []
  return items.filter((item): item is DevBootstrapStep => !!item && typeof item === "object")
}

function maskSecret(value: string): string {
  const s = String(value || "").trim()
  if (s.length <= 16) return s
  return `${s.slice(0, 10)}…${s.slice(-8)}`
}

async function fetchDevBootstrapManifest(url: string): Promise<DevBootstrapManifest | null> {
  try {
    const res = await fetch(url, { cache: "no-store" })
    if (!res.ok) return null
    const body = (await res.json()) as DevBootstrapManifest
    return body && typeof body === "object" ? body : null
  } catch {
    return null
  }
}

type DevBootstrapSecretResponse = {
  account?: string
  pubkeyB64?: string
  secretKeyB64?: string
  secret_key_b64?: string
  sessionTtlSeconds?: number
}

function apiJoin(base: string, path: string): string {
  const normalized = String(base || "").trim()
  if (!normalized || normalized === "/") return path
  return `${normalized.replace(/\/+$/, "")}${path}`
}

async function fetchDevBootstrapSecret(account: string, apiBase: string): Promise<DevBootstrapSecretResponse | null> {
  const normalized = normalizeAccount(account)
  if (!normalized) return null
  const res = await fetch(apiJoin(apiBase, `/v1/dev/bootstrap-secret?account=${encodeURIComponent(normalized)}`), { cache: "no-store" })
  if (!res.ok) return null
  const body = (await res.json()) as DevBootstrapSecretResponse
  return body && typeof body === "object" ? body : null
}

function manifestLines(value: unknown): string[] {
  if (!Array.isArray(value)) return []
  return value
    .map((item) => String(item || "").trim())
    .filter((item) => !!item)
}

function DevBootstrapDetails({ manifest }: { manifest: DevBootstrapManifest }) {
  return (
    <>
      <div className="stack-xs" data-testid="dev-bootstrap-summary">
        <strong>Handle</strong>
        <code data-testid="dev-bootstrap-account">{normalizeAccount(String(manifest.account || ""))}</code>
        <strong>Local dev signer</strong>
        <code data-testid="dev-bootstrap-secret">Fetched on demand from the local dev backend</code>
        {manifest.seededGroup?.group_id ? (
          <>
            <strong>Seeded group</strong>
            <code data-testid="dev-bootstrap-seeded-group">{String(manifest.seededGroup.group_id || "")}</code>
          </>
        ) : null}
        {manifest.seededProposal?.proposal_id ? (
          <>
            <strong>Seeded proposal</strong>
            <code data-testid="dev-bootstrap-seeded-proposal">{String(manifest.seededProposal.proposal_id || "")}</code>
          </>
        ) : null}
        {manifest.seededDispute?.dispute_id ? (
          <>
            <strong>Seeded dispute</strong>
            <code data-testid="dev-bootstrap-seeded-dispute">{String(manifest.seededDispute.dispute_id || "")}</code>
          </>
        ) : null}
      </div>
      {manifestSteps(manifest).length ? (
        <div className="stack-xs" data-testid="dev-bootstrap-path">
          <strong>Suggested conference path</strong>
          <ol className="muted" style={{ margin: 0, paddingLeft: "1.25rem" }}>
            {manifestSteps(manifest).map((step, index) => (
              <li key={`${String(step.href || step.label || index)}`}>
                {step.href ? (
                  <a data-testid={`dev-bootstrap-step-${index + 1}`} href={`/#${String(step.href)}`}>
                    {String(step.label || `Step ${index + 1}`)}
                  </a>
                ) : (
                  String(step.label || `Step ${index + 1}`)
                )}
                {step.href ? ` — ${String(step.href)}` : ""}
              </li>
            ))}
          </ol>
        </div>
      ) : null}
      <div className="stack-xs" data-testid="dev-bootstrap-quick-links">
        <strong>Quick links</strong>
        <div className="stack-xs">
          {manifest.seededGroup?.group_id ? (
            <a href={`/#/groups/${encodeURIComponent(String(manifest.seededGroup.group_id || ""))}`} data-testid="dev-bootstrap-open-group">
              Open seeded group
            </a>
          ) : null}
          {manifest.seededDispute?.dispute_id ? (
            <a href={`/#/disputes`} data-testid="dev-bootstrap-open-disputes">
              Open disputes surface
            </a>
          ) : null}
          {manifest.seededProposal?.proposal_id ? (
            <a href={`/#/proposal/${encodeURIComponent(String(manifest.seededProposal.proposal_id || ""))}`} data-testid="dev-bootstrap-open-proposal">
              Open seeded proposal
            </a>
          ) : null}
        </div>
      </div>
      {manifestLines(manifest.fallbackInstructions).length ? (
        <div className="stack-xs" data-testid="dev-bootstrap-fallback">
          <strong>Fallback if something misbehaves</strong>
          <ol className="muted" style={{ margin: 0, paddingLeft: "1.25rem" }}>
            {manifestLines(manifest.fallbackInstructions).map((step, index) => (
              <li key={`fallback-${index}`}>{step}</li>
            ))}
          </ol>
        </div>
      ) : null}
      {manifestLines(manifest.resetInstructions).length ? (
        <div className="stack-xs" data-testid="dev-bootstrap-reset">
          <strong>Deterministic reset</strong>
          <ol className="muted" style={{ margin: 0, paddingLeft: "1.25rem" }}>
            {manifestLines(manifest.resetInstructions).map((step, index) => (
              <li key={`reset-${index}`}>{step}</li>
            ))}
          </ol>
        </div>
      ) : null}
    </>
  )
}

function CheckpointList({ items }: { items: Checkpoint[] }) {
  return (
    <div className="checkpointList">
      {items.map((item) => (
        <div key={item.title} className={`checkpointItem checkpoint-${item.tone}`}>
          <div className="checkpointBullet" aria-hidden="true" />
          <div className="checkpointBody">
            <strong>{item.title}</strong>
            <span>{item.detail}</span>
          </div>
        </div>
      ))}
    </div>
  )
}

export default function LoginPage() {
  const config = useAppConfig()
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
  const [devManifest, setDevManifest] = useState<DevBootstrapManifest | null>(null)
  const [devBootstrapBusy, setDevBootstrapBusy] = useState(false)

  const session = getSession()
  const sessionAccount = session?.account || ""
  const sessionKeypair = useMemo(() => (sessionAccount ? getKeypair(sessionAccount) : null), [sessionAccount])

  const account = useMemo(() => normalizeAccount(accountInput), [accountInput])
  const existingAccount = useMemo(() => normalizeAccount(existingAccountInput), [existingAccountInput])
  const newAccountKeypair = useMemo(() => (account ? getKeypair(account) : null), [account])
  const emailOracleBase = useMemo(() => getEmailOracleBaseUrl(), [])
  const createSignerSubmission = useSignerSubmissionBusy(account)
  const existingSignerSubmission = useSignerSubmissionBusy(existingAccount)
  const signerBusy = mode === "create" ? createSignerSubmission.busy : existingSignerSubmission.busy

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

  useEffect(() => {
    let cancelled = false
    if (!config.enableDevBootstrap) {
      setDevManifest(null)
      return () => {
        cancelled = true
      }
    }

    fetchDevBootstrapManifest(config.devBootstrapManifestUrl).then((manifest) => {
      if (cancelled || !manifest) return
      setDevManifest(manifest)
      const manifestAccount = normalizeAccount(String(manifest.account || ""))
      const manifestApiBase = String(manifest.apiBase || "").trim()
      if (manifestAccount && !existingAccountInput.trim()) setExistingAccountInput(manifestAccount)
      if (manifestApiBase && !apiBaseInput.trim()) setApiBaseInput(manifestApiBase)
    })

    return () => {
      cancelled = true
    }
  }, [config, existingAccountInput, apiBaseInput])

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
      ensureKeypair(account)
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
      setNotice("Verification code requested. Check your email and continue with the confirmation step below.")
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
    if (!requestId.trim()) {
      setError("Missing verification request id. Request a new code and try again.")
      return
    }

    setBusy(true)
    try {
      const keypair = ensureKeypair(account)
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

      await restoreAccountAndLoginOnThisDevice({
        account,
        secretKeyB64: keypair.secretKeyB64,
      })

      setNotice("Email confirmed, Tier 1 submission sent, and this device session is now active.")
      nav(consumeReturnTo("/home"))
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
      setNotice("Fresh device session created. Redirecting to your intended route.")
      nav(consumeReturnTo("/home"))
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


  async function handleUseDevBootstrap() {
    setError("")
    setNotice("")
    if (!devManifest?.account) {
      setError("Dev bootstrap manifest is missing the account handle.")
      return
    }

    setDevBootstrapBusy(true)
    try {
      const secret = await fetchDevBootstrapSecret(String(devManifest.account || ""), String(devManifest.apiBase || apiBaseInput || getApiBase()))
      const secretKeyB64 = String(secret?.secretKeyB64 || secret?.secret_key_b64 || "").trim()
      if (!secretKeyB64) throw new Error("Dev bootstrap secret is not available from the local backend.")
      await restoreAccountAndLoginOnThisDevice({
        account: normalizeAccount(devManifest.account),
        secretKeyB64,
      })
      setNotice("Loaded the canonical demo tester credentials and created a fresh device session.")
      nav(consumeReturnTo("/home"))
    } catch (err) {
      setError(
        humanizeApiError(
          err,
          "Could not load the demo tester session automatically. You can still use the prefilled restore form below.",
        ),
      )
    } finally {
      setDevBootstrapBusy(false)
    }
  }

  async function handleCopyDevSecret() {
    if (!devManifest?.account) return
    try {
      const secret = await fetchDevBootstrapSecret(String(devManifest.account || ""), String(devManifest.apiBase || apiBaseInput || getApiBase()))
      const secretKeyB64 = String(secret?.secretKeyB64 || secret?.secret_key_b64 || "").trim()
      if (!secretKeyB64) throw new Error("missing_secret")
      await navigator.clipboard.writeText(secretKeyB64)
      setNotice("Demo private key copied from the local dev backend.")
    } catch {
      setNotice("Could not copy automatically. Use the one-click demo session loader instead.")
    }
  }

  const backendStateLabel =
    backendReachable === null ? "Checking backend reachability" : backendReachable ? "Backend reachable" : "Backend unreachable"

  const currentSessionCheckpoints: Checkpoint[] = sessionAccount
    ? [
        {
          title: "Local session",
          detail: `Active for ${sessionAccount}. ${session?.sessionKey ? "This browser has an issued device session key." : "No backend-issued session key is stored."}`,
          tone: session?.sessionKey ? "good" : "warn",
        },
        {
          title: "Local signer",
          detail: sessionKeypair?.secretKeyB64
            ? "A signer is available on this device for the active account."
            : "No local signer is available for the active account.",
          tone: sessionKeypair?.secretKeyB64 ? "good" : "warn",
        },
      ]
    : [
        {
          title: "No active session",
          detail: "Create or restore an account below to establish a device-local session.",
          tone: "pending",
        },
      ]

  const createFlowCheckpoints: Checkpoint[] = [
    {
      title: "1. Create local identity",
      detail: account
        ? `${account} will get a browser-local signer before email confirmation finishes.`
        : "Enter a handle to generate a browser-local signer for the new account.",
      tone: account ? "good" : "pending",
    },
    {
      title: "2. Verify email with the worker",
      detail: step === "begin"
        ? "Request a verification code after passing Turnstile."
        : "A verification request exists. Enter the code from your email to continue.",
      tone: requestId ? "good" : "pending",
    },
    {
      title: "3. Submit Tier 1 receipt on-chain",
      detail: "The frontend sends a signed receipt-submit transaction. Submission is not the same as broader PoH completion.",
      tone: step === "confirm" ? "pending" : "warn",
    },
    {
      title: "4. Establish this device session",
      detail: "After the receipt transaction is submitted, the client creates a fresh device session for the same account.",
      tone: requestId ? "pending" : "warn",
    },
  ]

  const restoreFlowCheckpoints: Checkpoint[] = [
    {
      title: "1. Restore the local signer",
      detail: "Paste the existing account’s private key. It stays local to this browser.",
      tone: existingAccount && privateKey.trim() ? "good" : "pending",
    },
    {
      title: "2. Issue a fresh device session",
      detail: "Successful login creates a new backend-recognized session for this device rather than reusing a stale one.",
      tone: existingAccount ? "pending" : "warn",
    },
    {
      title: "3. Continue from Home",
      detail: "After session creation, use Home and PoH to inspect chain-recognized readiness and next steps.",
      tone: "pending",
    },
  ]

  return (
    <main className="page-shell authPageShell">
      <section className="panel authHeroPanel">
        <div className="authHeroGrid">
          <div className="authHeroCopy">
            <p className="eyebrow">Start</p>
            <h1>Connect this device, then continue onboarding with clear state boundaries.</h1>
            <p className="muted">
              This page is where local identity, device session, and the first on-chain onboarding steps come together.
              It should be obvious what is local to this browser, what is verified by the relay worker, and what still
              depends on on-chain processing.
            </p>
          </div>

          <div className="authStatusRail">
            <div className="authStatusCard">
              <span className="authStatusLabel">Connection target</span>
              <strong>{backendStateLabel}</strong>
              <span>{apiBaseInput || "No API base configured."}</span>
            </div>
            <div className="authStatusCard">
              <span className="authStatusLabel">Email relay</span>
              <strong>{emailOracleBase}</strong>
              <span>Used for the email verification step before the receipt transaction is submitted.</span>
            </div>
            <div className="authStatusCard">
              <span className="authStatusLabel">Active device state</span>
              <strong>{sessionAccount || "No active session"}</strong>
              <span>
                {session?.sessionKey ? "A backend-issued device session key is stored locally." : "No backend-issued device session is currently active."}
              </span>
            </div>
          </div>
        </div>
      </section>

      <section className="surfaceBoundaryBar authBoundaryBar">
        <div className="surfaceBoundaryHeader">
          <div>
            <h2 className="surfaceBoundaryTitle">Access contract</h2>
            <p className="surfaceBoundaryText">
              This route is a deliberate access surface. It should make environment selection, local signer setup, browser session issuance, and first-step onboarding legible without blending them into the main product hubs.
            </p>
          </div>
          <div className="surfaceBoundaryList">
            <span className="surfaceBoundaryTag">Environment targeting</span>
            <span className="surfaceBoundaryTag">Local signer custody</span>
            <span className="surfaceBoundaryTag">Browser session issuance</span>
            <span className="surfaceBoundaryTag">On-chain follow-through</span>
          </div>
        </div>
      </section>

      <section className="authGrid">
        <article className="panel authConnectionPanel">
          <div className="authPanelHeader">
            <div>
              <p className="eyebrow">Environment</p>
              <h2>Backend and current browser state</h2>
            </div>
            <button type="button" className="secondary" onClick={handleSaveApiBase}>
              Save target
            </button>
          </div>

          <label className="field">
            <span>Client API base</span>
            <input
              value={apiBaseInput}
              onChange={(e) => setApiBaseInput(e.target.value)}
              placeholder="http://127.0.0.1:8000"
            />
          </label>

          <p className="muted authHelperCopy">
            Changing the API base changes the protocol environment this client is talking to. Treat it like an environment switch, not a cosmetic preference.
          </p>

          <CheckpointList items={currentSessionCheckpoints} />
        </article>

        <article className="panel authFlowPanel">
          <div className="authPanelHeader authModeHeader">
            <div>
              <p className="eyebrow">Access</p>
              <h2>{mode === "create" ? "Create a new account" : "Restore an existing account"}</h2>
            </div>
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
                New account
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
                Existing account
              </button>
            </div>
          </div>

          {mode === "create" ? (
            <div className="authFlowBody">
              {config.enableDevBootstrap && devManifest?.account ? (
                <div className="panel stack-sm">
                  <p className="eyebrow">Dev bootstrap</p>
                  <h3>Canonical demo tester is ready</h3>
                  <p className="muted">
                    This local environment already generated a demo tester account. You can load it with one click, or fetch the
                    local-only private key on demand without serving it from a public frontend file.
                  </p>
                  <div className="row gap-sm wrap">
                    <button type="button" data-testid="load-demo-tester-session" onClick={handleUseDevBootstrap} disabled={busy || devBootstrapBusy}>
                      {devBootstrapBusy ? "Loading demo session…" : "Load demo tester session"}
                    </button>
                    <button type="button" className="secondary" onClick={handleCopyDevSecret}>
                      Copy private key
                    </button>
                    <button
                      type="button"
                      className="secondary"
                      onClick={() => {
                        setMode("existing")
                        setExistingAccountInput(normalizeAccount(String(devManifest.account || "")))
                        setPrivateKey("")
                        setNotice("Demo handle copied into the restore form. Use Copy private key to fetch the local dev signer on demand if you need manual restore.")
                      }}
                    >
                      Open restore form
                    </button>
                  </div>
                  <DevBootstrapDetails manifest={devManifest} />
                </div>
              ) : null}
              <CheckpointList items={createFlowCheckpoints} />

              {createSignerSubmission.busy ? (
                <div className="calloutInfo">
                  Another signed action for {account || "this account"} is still settling. Wait for it to finish before requesting or confirming email verification on this device.
                </div>
              ) : null}

              <form onSubmit={step === "begin" ? handleBegin : handleConfirm} className="stack-md authFormCard">
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
                      This protects the shared email worker from abuse before it issues a verification challenge.
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

                <div className="authMetaGrid">
                  <div className="authMetaCard">
                    <span>Local signer</span>
                    <strong>{newAccountKeypair?.pubkeyB64 ? "Prepared" : account ? "Will be generated" : "Waiting for handle"}</strong>
                  </div>
                  <div className="authMetaCard">
                    <span>Verification request</span>
                    <strong>{requestId || "Not created yet"}</strong>
                  </div>
                </div>

                <div className="row gap-sm wrap">
                  {step === "begin" ? (
                    <button type="submit" disabled={busy || backendReachable === false || signerBusy}>
                      {busy ? "Sending code…" : "Request verification code"}
                    </button>
                  ) : (
                    <>
                      <button type="submit" disabled={busy || backendReachable === false || signerBusy}>
                        {busy ? "Confirming…" : "Confirm code and submit Tier 1"}
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
            </div>
          ) : (
            <div className="authFlowBody">
              {config.enableDevBootstrap && devManifest?.account ? (
                <div className="panel stack-sm">
                  <p className="eyebrow">Dev bootstrap</p>
                  <h3>Use the generated tester credentials</h3>
                  <p className="muted">
                    The restore form below is already prefilled from the generated demo bootstrap manifest. You can submit it as-is
                    or load the session with one click.
                  </p>
                  <div className="row gap-sm wrap">
                    <button type="button" data-testid="load-demo-tester-session" onClick={handleUseDevBootstrap} disabled={busy || devBootstrapBusy}>
                      {devBootstrapBusy ? "Loading demo session…" : "Load demo tester session"}
                    </button>
                    <button type="button" className="secondary" onClick={handleCopyDevSecret}>
                      Copy private key
                    </button>
                  </div>
                  <DevBootstrapDetails manifest={devManifest} />
                </div>
              ) : null}
              <CheckpointList items={restoreFlowCheckpoints} />

              {existingSignerSubmission.busy ? (
                <div className="calloutInfo">
                  Another signed action for {existingAccount || "this account"} is still settling. Wait for it to finish before restoring or reissuing a session here.
                </div>
              ) : null}

              <form onSubmit={handleExistingLogin} className="stack-md authFormCard">
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

                <p className="muted authHelperCopy">
                  The private key remains local to this browser. A successful restore issues a fresh device session instead of trusting a stale local session record.
                </p>

                <div className="row gap-sm wrap">
                  <button type="submit" disabled={busy || backendReachable === false || signerBusy}>
                    {busy ? "Restoring…" : "Restore account and create session"}
                  </button>
                </div>
              </form>
            </div>
          )}

          {notice ? <p className="notice-text">{notice}</p> : null}
          {error ? <p className="error-text">{error}</p> : null}
        </article>
      </section>
    </main>
  )
}
