import { useEffect, useMemo, useState } from "react"
import type { FormEvent, ReactNode } from "react"

import { ApiError, fetchStatus, getApiBase, setApiBase } from "../api/weall"
import { ensureKeypair, getKeypair, getSession, issueSessionFromSecretKey, loginOnThisDevice, restoreAccountAndLoginOnThisDevice } from "../auth/session"
import { buildRecoveryKeyFile, downloadRecoveryKeyFile, parseRecoveryKeyFileText, readRecoveryKeyFile, recoveryFileText, verifyRecoveryKeyFileForAccount } from "../auth/recoveryFile"
import { confirmEasySignIn, getEasySignInForAccount, listEasySignInRecords, passkeysAvailable, registerEasySignIn } from "../auth/passkeys"
import { consumeReturnTo, nav } from "../lib/router"
import { useAppConfig } from "../lib/config"

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

type LoginMode = "create" | "restore"

type DevBootstrapStep = {
  label?: string
  href?: string
}

type DevBootstrapManifest = {
  account?: string
  apiBase?: string
  api_base?: string
  pubkeyB64?: string
  sessionTtlSeconds?: number
  note?: string
  recommendedPath?: DevBootstrapStep[]
  fallbackInstructions?: string[]
  resetInstructions?: string[]
}

type CreatedKeyState = {
  account: string
  pubkeyB64: string
  secretKeyB64: string
}

function apiJoin(base: string, path: string): string {
  const normalized = String(base || "/").trim() || "/"
  if (normalized === "/") return path
  return `${normalized.replace(/\/+$/, "")}${path}`
}

function usableApiBase(...values: Array<string | null | undefined>): string {
  for (const value of values) {
    const normalized = String(value || "").trim()
    if (normalized && normalized !== "/") return normalized
  }
  return "/"
}

function manifestApiBase(manifest: DevBootstrapManifest | null, fallback: string): string {
  return usableApiBase(manifest?.apiBase, manifest?.api_base, fallback, getApiBase())
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

async function fetchDevBootstrapSecret(account: string, apiBase: string): Promise<DevBootstrapSecretResponse | null> {
  const normalized = normalizeAccount(account)
  if (!normalized) return null
  const res = await fetch(apiJoin(apiBase, `/v1/dev/bootstrap-secret?account=${encodeURIComponent(normalized)}`), { cache: "no-store" })
  if (!res.ok) return null
  const body = (await res.json()) as DevBootstrapSecretResponse
  return body && typeof body === "object" ? body : null
}

function manifestSteps(value: DevBootstrapManifest | null): DevBootstrapStep[] {
  const items = Array.isArray(value?.recommendedPath) ? value?.recommendedPath : []
  return items.filter((item): item is DevBootstrapStep => !!item && typeof item === "object")
}

function DevBootstrapCard({
  manifest,
  busy,
  onLoad,
  onCopy,
}: {
  manifest: DevBootstrapManifest
  busy: boolean
  onLoad: () => void
  onCopy: () => void
}) {
  return (
    <div className="panel stack-sm" data-testid="dev-bootstrap-card">
      <p className="eyebrow">Developer demo login</p>
      <h3>Load the local demo account</h3>
      <p className="muted">
        This appears only in developer/demo builds. Normal users should create an account or sign in with a recovery key.
      </p>
      <div className="row gap-sm wrap">
        <button type="button" data-testid="load-demo-tester-session" onClick={onLoad} disabled={busy}>
          {busy ? "Loading demo account…" : "Load demo account"}
        </button>
        <button type="button" className="secondary" onClick={onCopy}>
          Copy demo recovery key
        </button>
      </div>
      <div className="stack-xs" data-testid="dev-bootstrap-summary">
        <strong>Demo handle</strong>
        <code data-testid="dev-bootstrap-account">{normalizeAccount(String(manifest.account || ""))}</code>
      </div>
      {manifestSteps(manifest).length ? (
        <div className="stack-xs" data-testid="dev-bootstrap-path">
          <strong>Suggested demo path</strong>
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
              </li>
            ))}
          </ol>
        </div>
      ) : null}
    </div>
  )
}

function StepPill({ done, children }: { done: boolean; children: ReactNode }) {
  return <span className={`statusPill ${done ? "ok" : ""}`}>{children}</span>
}

export default function LoginPage() {
  const config = useAppConfig()
  const [apiBaseInput, setApiBaseInput] = useState(getApiBase())
  const [backendReachable, setBackendReachable] = useState<boolean | null>(null)
  const [mode, setMode] = useState<LoginMode>("create")

  const [accountInput, setAccountInput] = useState("")
  const [createdKey, setCreatedKey] = useState<CreatedKeyState | null>(null)
  const [recoverySaved, setRecoverySaved] = useState(false)
  const [recoveryDownloaded, setRecoveryDownloaded] = useState(false)
  const [recoveryVerified, setRecoveryVerified] = useState(false)
  const [recoveryVerificationText, setRecoveryVerificationText] = useState("")
  const [easySignInAdded, setEasySignInAdded] = useState(false)

  const [restoreAccountInput, setRestoreAccountInput] = useState("")
  const [recoveryKeyInput, setRecoveryKeyInput] = useState("")

  const [busy, setBusy] = useState(false)
  const [error, setError] = useState("")
  const [notice, setNotice] = useState("")
  const [devManifest, setDevManifest] = useState<DevBootstrapManifest | null>(null)
  const [devBootstrapBusy, setDevBootstrapBusy] = useState(false)
  const [easySignInBusy, setEasySignInBusy] = useState(false)

  const session = getSession()
  const account = useMemo(() => normalizeAccount(accountInput), [accountInput])
  const restoreAccount = useMemo(() => normalizeAccount(restoreAccountInput), [restoreAccountInput])
  const savedEasySignIns = useMemo(() => listEasySignInRecords(), [notice, easySignInAdded])
  const passkeyReady = passkeysAvailable()

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
      const nextApiBase = manifestApiBase(manifest, config.defaultApiBase)
      if (manifestAccount && !restoreAccountInput.trim()) setRestoreAccountInput(manifestAccount)
      if (nextApiBase && nextApiBase !== "/" && !apiBaseInput.trim()) setApiBaseInput(nextApiBase)
    })
    return () => {
      cancelled = true
    }
  }, [config, restoreAccountInput, apiBaseInput])

  async function handleSaveApiBase() {
    setApiBase(apiBaseInput)
    setError("")
    setNotice("")
    try {
      await fetchStatus()
      setBackendReachable(true)
      setNotice("Connection settings saved.")
    } catch (err) {
      setBackendReachable(false)
      setError(humanizeApiError(err, "Could not reach this WeAll node."))
    }
  }

  async function handleCreateAccount(e: FormEvent) {
    e.preventDefault()
    setError("")
    setNotice("")
    if (!account) {
      setError("Enter a handle to create your account key.")
      return
    }
    if (backendReachable === false) {
      setError("The selected WeAll node is unreachable. Check Advanced connection settings first.")
      return
    }

    setBusy(true)
    try {
      const keypair = ensureKeypair(account)
      issueSessionFromSecretKey({ account, secretKeyB64: keypair.secretKeyB64 })
      setCreatedKey({ account, pubkeyB64: keypair.pubkeyB64, secretKeyB64: keypair.secretKeyB64 })
      setRecoverySaved(false)
      setRecoveryDownloaded(false)
      setRecoveryVerified(false)
      setRecoveryVerificationText("")
      setEasySignInAdded(!!getEasySignInForAccount(account))
      setNotice("Your account key was created locally. Download your recovery file, then verify it before registering or continuing.")
    } catch (err) {
      setError(humanizeApiError(err, "Could not create your account key."))
    } finally {
      setBusy(false)
    }
  }

  async function handleDownloadRecoveryKey() {
    if (!createdKey) return
    try {
      downloadRecoveryKeyFile({
        account: createdKey.account,
        publicKeyB64: createdKey.pubkeyB64,
        secretKeyB64: createdKey.secretKeyB64,
      })
      setRecoveryDownloaded(true)
      setRecoverySaved(false)
      setRecoveryVerified(false)
      setNotice("Recovery file downloaded. Upload or paste it below once to prove you can restore this account before continuing.")
    } catch (err) {
      setError(humanizeApiError(err, "Could not download the recovery file."))
    }
  }

  async function handleCopyRecoveryKey() {
    if (!createdKey) return
    try {
      const file = buildRecoveryKeyFile({
        account: createdKey.account,
        publicKeyB64: createdKey.pubkeyB64,
        secretKeyB64: createdKey.secretKeyB64,
      })
      await navigator.clipboard.writeText(recoveryFileText(file))
      setRecoveryDownloaded(true)
      setRecoverySaved(false)
      setRecoveryVerified(false)
      setNotice("Recovery key copied. Paste the recovery JSON below once to prove you can restore this account before continuing.")
    } catch (err) {
      setError(humanizeApiError(err, "Could not copy the recovery key."))
    }
  }

  async function handleAddEasySignIn() {
    const target = createdKey?.account || session?.account || ""
    if (!target) {
      setError("Create or restore an account before adding easy sign-in.")
      return
    }
    setEasySignInBusy(true)
    setError("")
    setNotice("")
    try {
      await registerEasySignIn({ account: target })
      setEasySignInAdded(true)
      setNotice("Easy sign-in was added for this browser/device. Your recovery key is still required as the backup.")
    } catch (err) {
      setError(humanizeApiError(err, "Could not add easy sign-in on this device."))
    } finally {
      setEasySignInBusy(false)
    }
  }

  function handleContinueAfterRecovery() {
    if (!createdKey) return
    if (!recoveryVerified) {
      setError("Verify your saved recovery file or pasted recovery JSON before continuing.")
      return
    }
    nav(consumeReturnTo("/verification"))
  }

  function verifyCreatedRecoveryFile(parsed: ReturnType<typeof parseRecoveryKeyFileText>) {
    if (!createdKey) {
      setError("Create an account key before verifying a recovery file.")
      return
    }
    const result = verifyRecoveryKeyFileForAccount(parsed, {
      account: createdKey.account,
      publicKeyB64: createdKey.pubkeyB64,
      secretKeyB64: createdKey.secretKeyB64,
    })
    if (!result.ok) {
      setRecoverySaved(false)
      setRecoveryVerified(false)
      setError(`Recovery verification failed: ${result.reason}`)
      return
    }
    setRecoverySaved(true)
    setRecoveryVerified(true)
    setNotice("Recovery verified. You can restore this account if this browser is lost or reset.")
  }

  async function handleVerifyCreatedRecoveryFileSelected(file: File | null) {
    setError("")
    setNotice("")
    if (!file) return
    try {
      const parsed = await readRecoveryKeyFile(file)
      verifyCreatedRecoveryFile(parsed)
    } catch (err) {
      setRecoverySaved(false)
      setRecoveryVerified(false)
      setError(humanizeApiError(err, "Could not verify that recovery file."))
    }
  }

  function handleVerifyCreatedRecoveryText(value: string) {
    const text = String(value || "")
    setRecoveryVerificationText(text)
    setRecoverySaved(false)
    setRecoveryVerified(false)
    const trimmed = text.trim()
    if (!trimmed) return
    if (!trimmed.startsWith("{")) {
      setError("Paste the full recovery JSON from your saved file to verify it.")
      return
    }
    try {
      const parsed = parseRecoveryKeyFileText(trimmed)
      setError("")
      verifyCreatedRecoveryFile(parsed)
    } catch (err) {
      setError(humanizeApiError(err, "Could not verify the pasted recovery JSON."))
    }
  }

  async function handleRecoveryFileSelected(file: File | null) {
    setError("")
    setNotice("")
    if (!file) return
    try {
      const parsed = await readRecoveryKeyFile(file)
      setRestoreAccountInput(parsed.account)
      setRecoveryKeyInput(parsed.secretKeyB64)
      setNotice("Recovery file loaded. Review the handle, then sign in.")
    } catch (err) {
      setError(humanizeApiError(err, "Could not read that recovery file."))
    }
  }

  function handlePasteRecoveryText(value: string) {
    const text = String(value || "")
    setRecoveryKeyInput(text)
    const trimmed = text.trim()
    if (!trimmed.startsWith("{")) return
    try {
      const parsed = parseRecoveryKeyFileText(trimmed)
      setRestoreAccountInput(parsed.account)
      setRecoveryKeyInput(parsed.secretKeyB64)
      setNotice("Recovery JSON detected and loaded.")
    } catch {
      // Leave text as-is so the user can finish editing/pasting.
    }
  }

  async function handleRestoreLogin(e: FormEvent) {
    e.preventDefault()
    setError("")
    setNotice("")
    if (!restoreAccount) {
      setError("Enter your account handle.")
      return
    }
    if (!recoveryKeyInput.trim()) {
      setError("Upload your recovery file or paste your recovery key.")
      return
    }

    setBusy(true)
    try {
      await restoreAccountAndLoginOnThisDevice({
        account: restoreAccount,
        secretKeyB64: recoveryKeyInput.trim(),
      })
      setNotice("Signed in on this device.")
      nav(consumeReturnTo("/home"))
    } catch (err) {
      setError(humanizeApiError(err, "Could not sign in with that recovery key."))
    } finally {
      setBusy(false)
    }
  }

  async function handleUseEasySignIn() {
    setEasySignInBusy(true)
    setError("")
    setNotice("")
    try {
      const selected = await confirmEasySignIn()
      const keypair = getKeypair(selected.account)
      if (!keypair?.secretKeyB64) {
        setMode("restore")
        setRestoreAccountInput(selected.account)
        setNotice("Easy sign-in recognized this account. Use your recovery file once on this browser to restore the account key.")
        return
      }
      await loginOnThisDevice({ account: selected.account })
      setNotice("Signed in with easy sign-in.")
      nav(consumeReturnTo("/home"))
    } catch (err) {
      setError(humanizeApiError(err, "Easy sign-in could not be completed."))
    } finally {
      setEasySignInBusy(false)
    }
  }

  async function handleUseDevBootstrap() {
    setError("")
    setNotice("")
    if (!devManifest?.account) {
      setError("Demo account is unavailable.")
      return
    }
    setDevBootstrapBusy(true)
    try {
      const apiBase = manifestApiBase(devManifest, apiBaseInput)
      const secret = await fetchDevBootstrapSecret(String(devManifest.account || ""), apiBase)
      const secretKeyB64 = String(secret?.secretKeyB64 || secret?.secret_key_b64 || "").trim()
      if (!secretKeyB64) throw new Error("Demo recovery key is unavailable from the local backend.")
      const ttlSeconds = Number(secret?.sessionTtlSeconds || devManifest.sessionTtlSeconds || 24 * 60 * 60)
      setApiBase(apiBase)
      setApiBaseInput(apiBase)
      await restoreAccountAndLoginOnThisDevice({
        account: normalizeAccount(devManifest.account),
        secretKeyB64,
        ttlSeconds,
        base: apiBase,
      })
      setNotice("Demo account loaded.")
      nav(consumeReturnTo("/home"))
    } catch (err) {
      setError(humanizeApiError(err, "Could not load the demo account."))
    } finally {
      setDevBootstrapBusy(false)
    }
  }

  async function handleCopyDevSecret() {
    if (!devManifest?.account) return
    try {
      const secret = await fetchDevBootstrapSecret(String(devManifest.account || ""), manifestApiBase(devManifest, apiBaseInput))
      const secretKeyB64 = String(secret?.secretKeyB64 || secret?.secret_key_b64 || "").trim()
      if (!secretKeyB64) throw new Error("missing_secret")
      await navigator.clipboard.writeText(secretKeyB64)
      setNotice("Demo recovery key copied from the local dev backend.")
    } catch {
      setNotice("Could not copy automatically. Use the one-click demo login instead.")
    }
  }

  const backendStateLabel = backendReachable === null ? "Checking node" : backendReachable ? "Node reachable" : "Node unreachable"

  return (
    <main className="page-shell authPageShell">
      <section className="panel authHeroPanel">
        <div className="authHeroGrid">
          <div className="authHeroCopy">
            <p className="eyebrow">Welcome</p>
            <h1>Sign in to WeAll</h1>
            <p className="muted">
              Create an account key, verify your recovery file, then use easy sign-in on this device for faster access later.
            </p>
            <div className="statusRowWrap">
              <StepPill done={!!createdKey || !!session?.account}>Account key</StepPill>
              <StepPill done={recoveryDownloaded}>Recovery downloaded</StepPill>
              <StepPill done={recoveryVerified}>Recovery verified</StepPill>
              <StepPill done={easySignInAdded || !!savedEasySignIns.length}>Easy sign-in optional</StepPill>
            </div>
          </div>

          <div className="authStatusRail">
            <div className="authStatusCard">
              <span className="authStatusLabel">This device</span>
              <strong>{session?.account || "Not signed in"}</strong>
              <span>{session?.sessionKey ? "Active device login" : "No active device login"}</span>
            </div>
            <div className="authStatusCard">
              <span className="authStatusLabel">Connection</span>
              <strong>{backendStateLabel}</strong>
              <span>{apiBaseInput || "No node configured"}</span>
            </div>
          </div>
        </div>
      </section>

      <section className="authGrid">
        <article className="panel authFlowPanel">
          <div className="authPanelHeader authModeHeader">
            <div>
              <p className="eyebrow">Account access</p>
              <h2>{mode === "create" ? "Create a new account" : "Sign in with recovery key"}</h2>
            </div>
            <div className="row gap-sm wrap">
              <button type="button" className={mode === "create" ? "" : "secondary"} onClick={() => setMode("create")}>
                Create account
              </button>
              <button type="button" className={mode === "restore" ? "" : "secondary"} onClick={() => setMode("restore")}>
                Sign in
              </button>
            </div>
          </div>

          {config.enableDevBootstrap && devManifest?.account ? (
            <DevBootstrapCard manifest={devManifest} busy={devBootstrapBusy} onLoad={handleUseDevBootstrap} onCopy={handleCopyDevSecret} />
          ) : null}

          {savedEasySignIns.length ? (
            <div className="calloutInfo" data-testid="easy-signin-returning">
              Easy sign-in is available for {savedEasySignIns.map((item) => item.account).join(", ")}.
              <div className="row gap-sm wrap" style={{ marginTop: "0.75rem" }}>
                <button type="button" className="secondary" onClick={() => void handleUseEasySignIn()} disabled={easySignInBusy || !passkeyReady}>
                  {easySignInBusy ? "Checking device…" : "Use easy sign-in"}
                </button>
              </div>
            </div>
          ) : null}

          {mode === "create" ? (
            <div className="authFlowBody">
              {!createdKey ? (
                <form onSubmit={handleCreateAccount} className="stack-md authFormCard" data-testid="create-account-key-form">
                  <label className="field">
                    <span>Choose a handle</span>
                    <input value={accountInput} onChange={(e) => setAccountInput(e.target.value)} placeholder="@yourname" autoComplete="username" />
                  </label>
                  <div className="calloutInfo">
                    WeAll will create an account key on this device. You must download and verify the recovery file before registration or verification continues.
                  </div>
                  <button type="submit" disabled={busy || backendReachable === false}>
                    {busy ? "Creating…" : "Create account key"}
                  </button>
                </form>
              ) : (
                <div className="stack-md authFormCard" data-testid="recovery-save-step">
                  <div>
                    <p className="eyebrow">Recovery key</p>
                    <h3>Save this before continuing</h3>
                    <p className="muted">
                      This recovery key is how you sign in on another device. WeAll cannot reset it for you. You must verify the saved file before continuing.
                    </p>
                  </div>
                  <div className="authMetaGrid">
                    <div className="authMetaCard">
                      <span>Handle</span>
                      <strong>{createdKey.account}</strong>
                    </div>
                    <div className="authMetaCard">
                      <span>Account key</span>
                      <strong>Created</strong>
                    </div>
                  </div>
                  <div className="row gap-sm wrap">
                    <button type="button" onClick={() => void handleDownloadRecoveryKey()}>
                      Download recovery file\n                  <span className="text-xs opacity-80">Do not rely on a checkbox like “I saved my recovery key somewhere private”; WeAll verifies your recovery file or recovery key before account setup can continue.</span>
                    </button>
                    <button type="button" className="secondary" onClick={() => void handleCopyRecoveryKey()}>
                      Copy recovery key
                    </button>
                  </div>
                  <div className="stack-sm" data-testid="recovery-verify-step">
                    <label className="field">
                      <span>Verify saved recovery file</span>
                      <input
                        type="file"
                        accept="application/json,.json"
                        data-testid="verify-created-recovery-file"
                        onChange={(e) => void handleVerifyCreatedRecoveryFileSelected(e.currentTarget.files?.[0] || null)}
                      />
                    </label>
                    <label className="field">
                      <span>Or paste recovery JSON to verify</span>
                      <textarea
                        value={recoveryVerificationText}
                        onChange={(e) => handleVerifyCreatedRecoveryText(e.target.value)}
                        placeholder="Paste the recovery JSON you saved"
                        rows={4}
                        spellCheck={false}
                        data-testid="verify-created-recovery-json"
                      />
                    </label>
                    <div className={recoveryVerified ? "calloutSuccess" : "calloutInfo"} data-testid="recovery-verification-status">
                      {recoveryVerified
                        ? "Recovery verified. You can restore this account if this browser is lost or reset."
                        : "Download or copy the recovery file, then upload or paste it here to prove you saved a working backup."}
                    </div>
                  </div>
                  <div className="calloutInfo">
                    Optional: add easy sign-in so this device can use fingerprint, face unlock, or device PIN when supported. It never replaces the verified recovery file.
                  </div>
                  <div className="row gap-sm wrap">
                    <button type="button" className="secondary" onClick={() => void handleAddEasySignIn()} disabled={easySignInBusy || !passkeyReady || !recoveryVerified}>
                      {easySignInBusy ? "Adding…" : easySignInAdded ? "Easy sign-in added" : "Add easy sign-in"}
                    </button>
                    <button type="button" onClick={handleContinueAfterRecovery} disabled={!recoveryVerified}>
                      Continue to account verification
                    </button>
                  </div>
                  {!passkeyReady ? <p className="muted">Easy sign-in is not available in this browser. Your recovery key still works.</p> : null}
                </div>
              )}
            </div>
          ) : (
            <div className="authFlowBody">
              <form onSubmit={handleRestoreLogin} className="stack-md authFormCard" data-testid="restore-account-form">
                <div>
                  <p className="eyebrow">Returning user</p>
                  <h3>Use your recovery key</h3>
                  <p className="muted">Upload your saved recovery file, or paste the recovery key manually.</p>
                </div>
                <label className="field">
                  <span>Recovery file</span>
                  <input type="file" accept="application/json,.json" onChange={(e) => void handleRecoveryFileSelected(e.currentTarget.files?.[0] || null)} />
                </label>
                <label className="field">
                  <span>Handle</span>
                  <input value={restoreAccountInput} onChange={(e) => setRestoreAccountInput(e.target.value)} placeholder="@yourname" autoComplete="username" />
                </label>
                <label className="field">
                  <span>Recovery key</span>
                  <textarea
                    value={recoveryKeyInput}
                    onChange={(e) => handlePasteRecoveryText(e.target.value)}
                    placeholder="Paste your recovery key or recovery JSON"
                    rows={5}
                    spellCheck={false}
                    autoComplete="current-password"
                  />
                </label>
                <button type="submit" disabled={busy || backendReachable === false}>
                  {busy ? "Signing in…" : "Sign in"}
                </button>
              </form>
            </div>
          )}

          {notice ? <p className="notice-text">{notice}</p> : null}
          {error ? <p className="error-text">{error}</p> : null}
        </article>

        <article className="panel authConnectionPanel">
          <div className="authPanelHeader">
            <div>
              <p className="eyebrow">Help</p>
              <h2>What to save</h2>
            </div>
          </div>
          <div className="stack-sm">
            <div className="summaryCallout">
              <strong>Recovery key:</strong> your long-term backup. Store it somewhere private.
            </div>
            <div className="summaryCallout">
              <strong>Easy sign-in:</strong> optional device convenience through passkey-style browser support. It does not replace your recovery key.
            </div>
            <div className="summaryCallout">
              <strong>Log out:</strong> revokes this device session. Use your recovery key to sign back in if this browser forgets the account key.
            </div>
          </div>
          <details className="advancedDisclosure" style={{ marginTop: "1rem" }}>
            <summary>Advanced connection settings</summary>
            <div className="stack-sm" style={{ marginTop: "1rem" }}>
              <label className="field">
                <span>WeAll node API base</span>
                <input value={apiBaseInput} onChange={(e) => setApiBaseInput(e.target.value)} placeholder="http://127.0.0.1:8000" />
              </label>
              <button type="button" className="secondary" onClick={handleSaveApiBase}>
                Save connection
              </button>
            </div>
          </details>
          <details className="advancedDisclosure" style={{ marginTop: "1rem" }}>
            <summary>Lost your recovery key?</summary>
            <p className="muted">
              If you still have another active device or account recovery guardians, use Account Recovery. If not, WeAll cannot reset your key for you.
            </p>
            <button type="button" className="secondary" onClick={() => nav("/settings")}>Open account settings</button>
          </details>
        </article>
      </section>
    </main>
  )
}
