import React, { useEffect, useMemo, useState } from "react";

import { getApiBaseUrl, weall } from "../api/weall";
import ErrorBanner from "../components/ErrorBanner";
import { getAuthHeaders, getKeypair, getSession, setSession, submitSignedTx } from "../auth/session";
import { normalizeAccount } from "../auth/keys";
import { useAccount } from "../context/AccountContext";
import { useTxQueue } from "../hooks/useTxQueue";
import { useSignerSubmissionBusy } from "../hooks/useSignerSubmissionBusy";
import { getTier2VideoUploadEnabled } from "../lib/capabilities";
import { resolveOnboardingSnapshot, summarizeNextRequirements } from "../lib/onboarding";
import { nav } from "../lib/router";
import { refreshMutationSlices } from "../lib/revalidation";
import {
  TRUSTED_RESPONSIBILITIES,
  VERIFICATION_LABELS,
  blockedByVerificationMessage,
  friendlyActionError,
  verificationLabel,
  verificationSummary,
} from "../lib/userLanguage";

type ErrState = { msg: string; details: any } | null;

type UploadState = {
  cid?: string;
  gateway_url?: string;
  video_commitment?: string;
  mime?: string;
  name?: string;
  size?: number;
};

type StageTone = "done" | "active" | "locked";

type StatusCardProps = {
  eyebrow: string;
  title: string;
  status: "done" | "available" | "locked";
  description: string;
  children?: React.ReactNode;
};

function prettyErr(e: any): { msg: string; details: any } {
  const details = e?.body || e?.data || e;
  const raw = details?.message || details?.error?.message || e?.message || "This action could not be completed.";
  return { msg: friendlyActionError(raw), details };
}

function statusTone(status: string): StageTone {
  const s = String(status || "").toLowerCase();
  if (["complete", "completed", "finalized", "passed", "approved", "active"].includes(s)) return "done";
  if (["open", "pending", "review", "assigned", "scheduled", "accepted", "in_progress"].includes(s)) return "active";
  return "locked";
}

function JsonDetails({ title, value }: { title: string; value: any }): JSX.Element | null {
  if (!value) return null;
  return (
    <details className="advancedDisclosure">
      <summary>{title}</summary>
      <pre style={{ whiteSpace: "pre-wrap", marginTop: 10 }}>{JSON.stringify(value, null, 2)}</pre>
    </details>
  );
}

function StatusCard({ eyebrow, title, status, description, children }: StatusCardProps): JSX.Element {
  const pill = status === "done" ? "Complete" : status === "available" ? "Available" : "Locked";
  return (
    <article className={`card tierCard tierCard-${status === "available" ? "active" : status}`}>
      <div className="cardBody formStack">
        <div className="sectionHead">
          <div>
            <div className="eyebrow">{eyebrow}</div>
            <h2 className="cardTitle">{title}</h2>
          </div>
          <span className={`statusPill ${status === "done" ? "ok" : ""}`}>{pill}</span>
        </div>
        <p className="cardDesc">{description}</p>
        {children}
      </div>
    </article>
  );
}

function CaseCard({ item }: { item: any }): JSX.Element {
  const created = item?.created_at_ms ? new Date(item.created_at_ms).toLocaleString() : "—";
  const tone = statusTone(String(item?.status || ""));
  return (
    <div className="infoCard compact">
      <div className="infoCardHeader">
        <strong>{String(item?.case_id || "Review case")}</strong>
        <span className={`statusPill ${tone === "done" ? "ok" : ""}`}>{String(item?.status || "unknown")}</span>
      </div>
      <div className="infoCardText">Opened {created}</div>
    </div>
  );
}

async function reconcileRegisteredState(account: string, base: string): Promise<{ phase: "confirmed" | "submitted" | "failed" | "unknown"; detail?: string } | null> {
  try {
    const registration = await weall.accountRegistered(account, base);
    if (registration?.registered === true) {
      return { phase: "confirmed", detail: "The account is now visible as registered." };
    }
  } catch {
    // fall through to account view
  }

  try {
    const accountView = await weall.account(account, base);
    const state = accountView?.account?.state ?? accountView?.state ?? null;
    if (state && typeof state === "object") {
      const accountNonce = Number((state as any)?.nonce || 0);
      const pubkey = String((state as any)?.pubkey || "").trim();
      if (accountNonce > 0 || !!pubkey) return { phase: "confirmed", detail: "The account record is now visible." };
    }
  } catch {
    // ignore
  }

  return null;
}

async function reconcileSessionKeyVisible(account: string, expectedSessionKey: string, base: string): Promise<{ phase: "confirmed" | "submitted" | "failed" | "unknown"; detail?: string } | null> {
  if (!expectedSessionKey.trim()) return null;
  try {
    const accountView = await weall.account(account, base);
    const state = accountView?.account?.state ?? accountView?.state ?? null;
    const byId = (state?.session_keys?.by_id ?? state?.session_keys) as Record<string, any> | undefined;
    if (byId && typeof byId === "object") {
      const records = Object.values(byId);
      const matched = records.some((item: any) => String(item?.session_key || item?.key || item?.id || "").trim() === expectedSessionKey.trim());
      if (matched) return { phase: "confirmed", detail: "The session key is now visible in account state." };
    }
  } catch {
    // ignore
  }
  return null;
}

async function reconcileVerificationLevel(account: string, minimumLevel: number, base: string): Promise<{ phase: "confirmed" | "submitted" | "failed" | "unknown"; detail?: string } | null> {
  try {
    const accountView = await weall.account(account, base);
    const state = accountView?.account?.state ?? accountView?.state ?? null;
    const rawTier = Math.max(0, Number((state as any)?.poh_tier || 0));
    const level = Number.isFinite(rawTier) ? Math.min(2, Math.floor(rawTier)) : 0;
    if (level >= minimumLevel) {
      return {
        phase: "confirmed",
        detail: minimumLevel >= 2 ? "Live verification is now reflected in your account status." : "Account verification is now reflected in your account status.",
      };
    }
  } catch {
    // ignore
  }
  return null;
}

async function reconcileAsyncCompatibilityCase(account: string, base: string, headers?: HeadersInit): Promise<{ phase: "confirmed" | "submitted" | "failed" | "unknown"; detail?: string } | null> {
  try {
    const cases = await weall.pohTier2MyCases(account, base, headers);
    const items = Array.isArray(cases?.cases) ? cases.cases : [];
    if (items.length > 0) return { phase: "confirmed", detail: "The compatibility review case is visible." };
  } catch {
    // ignore
  }
  return reconcileVerificationLevel(account, 2, base);
}

async function reconcileLiveCaseVisible(account: string, base: string, headers?: HeadersInit): Promise<{ phase: "confirmed" | "submitted" | "failed" | "unknown"; detail?: string } | null> {
  try {
    const assigned = await weall.pohLiveAssigned(account, base, headers);
    const cases = Array.isArray(assigned?.cases) ? assigned.cases : [];
    if (cases.length > 0) return { phase: "confirmed", detail: "Your live verification case is visible." };
  } catch {
    // ignore
  }
  return reconcileVerificationLevel(account, 2, base);
}

export default function AccountVerificationPage(): JSX.Element {
  const base = useMemo(() => getApiBaseUrl(), []);
  const session = getSession();
  const acct = session ? normalizeAccount(session.account) : null;
  const kp = acct ? getKeypair(acct) : null;
  const { refresh: refreshAccountContext } = useAccount();
  const tx = useTxQueue();
  const signerSubmission = useSignerSubmissionBusy(acct);

  const [acctView, setAcctView] = useState<any | null>(null);
  const [registration, setRegistration] = useState<any | null>(null);
  const [acctState, setAcctState] = useState<any | null>(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<ErrState>(null);
  const [result, setResult] = useState<any | null>(null);

  const [sessionBusy, setSessionBusy] = useState(false);
  const [registerBusy, setRegisterBusy] = useState(false);
  const [compatUploadBusy, setCompatUploadBusy] = useState(false);
  const [compatRequestBusy, setCompatRequestBusy] = useState(false);
  const [liveRequestBusy, setLiveRequestBusy] = useState(false);
  const [casesBusy, setCasesBusy] = useState(false);

  const [compatUpload, setCompatUpload] = useState<UploadState | null>(null);
  const [compatCases, setCompatCases] = useState<any[]>([]);
  const [liveCases, setLiveCases] = useState<any[]>([]);
  const [liveSessions, setLiveSessions] = useState<any[]>([]);

  const compatibilityUploadEnabled = getTier2VideoUploadEnabled();
  const hasLocalKeypair = !!kp?.secretKeyB64;
  const sessionKeyPresent = !!session?.sessionKey;

  async function refresh(): Promise<void> {
    setLoading(true);
    setErr(null);
    try {
      if (!acct) {
        setAcctView(null);
        setAcctState(null);
        setRegistration(null);
        return;
      }
      const [accountView, registrationView] = await Promise.all([
        weall.account(acct, base),
        weall.accountRegistered(acct, base).catch(() => ({ registered: false })),
      ]);
      setAcctView(accountView);
      setAcctState(accountView?.state ?? null);
      setRegistration(registrationView);
    } catch (e: any) {
      setErr(prettyErr(e));
    } finally {
      setLoading(false);
    }
  }

  async function loadVerificationData(): Promise<void> {
    if (!acct) {
      setCompatCases([]);
      setLiveCases([]);
      setLiveSessions([]);
      return;
    }
    setCasesBusy(true);
    try {
      const headers = getAuthHeaders(acct);
      const [compat, live, sessions] = await Promise.all([
        weall.pohTier2MyCases(acct, base, headers).catch(() => ({ cases: [] })),
        weall.pohLiveAssigned(acct, base, headers).catch(() => ({ cases: [] })),
        weall.pohLiveSessions(base, headers).catch(() => ({ sessions: [] })),
      ]);
      setCompatCases(Array.isArray(compat?.cases) ? compat.cases : []);
      setLiveCases(Array.isArray(live?.cases) ? live.cases : []);
      setLiveSessions(Array.isArray(sessions?.sessions) ? sessions.sessions : []);
    } catch (e: any) {
      setErr(prettyErr(e));
    } finally {
      setCasesBusy(false);
    }
  }

  async function refreshVerificationSurface(): Promise<void> {
    await refreshMutationSlices(refresh, refreshAccountContext, loadVerificationData);
  }

  useEffect(() => {
    void refresh();
    void loadVerificationData();
  }, [acct]);

  const snapshot = resolveOnboardingSnapshot({
    account: acct,
    session,
    keypair: kp,
    accountView: acctView,
    registrationView: registration,
  });

  const requirements = summarizeNextRequirements(snapshot);
  const accountLevel = snapshot.tier;
  const currentLabel = verificationLabel(accountLevel);
  const currentSummary = verificationSummary(accountLevel);
  const registered = snapshot.registered;
  const banned = snapshot.banned;
  const locked = snapshot.locked;

  const basicStatus: "done" | "available" | "locked" = acct && hasLocalKeypair ? "done" : "available";
  const verifiedStatus: "done" | "available" | "locked" = accountLevel >= 1 ? "done" : registered ? "available" : "locked";
  const trustedStatus: "done" | "available" | "locked" = accountLevel >= 2 ? "done" : accountLevel >= 1 ? "available" : "locked";

  const nextStep = useMemo(() => {
    if (!acct) return "Sign in or create an account on this device.";
    if (!hasLocalKeypair) return "Restore the saved account key for this account.";
    if (!sessionKeyPresent) return "Save a session key so authenticated account calls work on this device.";
    if (!registered) return "Register your account so the network can recognize it.";
    if (accountLevel < 1) return "Start account verification when the native async review flow is available on this deployment.";
    if (accountLevel < 2) return "Complete live verification to unlock high-trust social and community actions.";
    return "You can now apply for trusted responsibilities where you meet the requirements.";
  }, [acct, accountLevel, hasLocalKeypair, registered, sessionKeyPresent]);

  async function registerAccount(): Promise<void> {
    if (!acct) {
      setErr({ msg: "Sign in before registering this account.", details: null });
      return;
    }
    if (!kp?.pubkeyB64) {
      setErr({ msg: "This device is missing the saved account key for this account.", details: null });
      return;
    }
    setRegisterBusy(true);
    setErr(null);
    setResult(null);
    try {
      const r = await tx.runTx({
        title: "Register account",
        pendingMessage: "Saving account registration…",
        successMessage: "Account registration submitted.",
        errorMessage: (e) => prettyErr(e).msg,
        getTxId: (res: any) => res?.tx_id || res?.result?.tx_id,
        finality: { timeoutMs: 16_000, reconcile: async () => reconcileRegisteredState(acct, base) },
        task: async () =>
          submitSignedTx({
            account: acct,
            tx_type: "ACCOUNT_REGISTER",
            payload: { pubkey: kp.pubkeyB64 },
            parent: null,
            base,
          }),
      });
      setResult(r);
      await refresh();
      await refreshAccountContext();
    } catch (e: any) {
      setErr(prettyErr(e));
      setResult(e?.body || e?.data || null);
    } finally {
      setRegisterBusy(false);
    }
  }

  async function issueSessionKey(): Promise<void> {
    if (!acct) {
      setErr({ msg: "Sign in before saving a session key.", details: null });
      return;
    }

    const requestedSessionKey = (window.prompt("Paste the session key you want linked to this device.", session?.sessionKey || "") || "").trim();
    if (!requestedSessionKey) {
      setErr({ msg: "Paste a session key before continuing.", details: null });
      return;
    }

    setSessionBusy(true);
    setErr(null);
    setResult(null);

    try {
      const r = await tx.runTx({
        title: "Save session key",
        pendingMessage: "Saving session key…",
        successMessage: "Session key submitted.",
        errorMessage: (e) => prettyErr(e).msg,
        getTxId: (res: any) => res?.result?.tx_id,
        finality: { timeoutMs: 16_000, reconcile: async () => reconcileSessionKeyVisible(acct, requestedSessionKey, base) },
        task: async () =>
          submitSignedTx({
            account: acct,
            tx_type: "ACCOUNT_SESSION_KEY_ISSUE",
            payload: { session_key: requestedSessionKey },
            parent: null,
            base,
          }),
      });

      if (requestedSessionKey && session) setSession({ ...session, sessionKey: requestedSessionKey });
      setResult(r);
      await refresh();
      await refreshAccountContext();
    } catch (e: any) {
      setErr(prettyErr(e));
      setResult(e?.body || e?.data || null);
    } finally {
      setSessionBusy(false);
    }
  }

  function explainNativeAsyncVerification(): void {
    setErr(null);
    setResult({
      ok: true,
      path: "account_verification",
      message: "The primary path is native async human review finalized by WeAll account state. This frontend does not require an external identity provider.",
      next_steps: registered
        ? ["Open the native async review flow when this deployment exposes it.", "Refresh account status after reviewers finalize the result."]
        : ["Register the account first.", "Return here to start or inspect verification."],
    });
  }

  async function uploadCompatibilityVideo(file: File): Promise<void> {
    setCompatUploadBusy(true);
    setErr(null);
    try {
      const r: any = await tx.runTx({
        title: "Upload compatibility evidence",
        pendingMessage: "Uploading evidence…",
        successMessage: "Evidence uploaded.",
        errorMessage: (e) => prettyErr(e).msg,
        task: async () => weall.pohTier2VideoUpload(file, base, getAuthHeaders(acct || undefined)),
      });
      setCompatUpload(r);
      setResult(r);
    } catch (e: any) {
      setErr(prettyErr(e));
    } finally {
      setCompatUploadBusy(false);
    }
  }

  async function submitCompatibilityRequest(): Promise<void> {
    if (!acct) {
      setErr({ msg: "Sign in before opening a compatibility review.", details: null });
      return;
    }
    if (!compatUpload?.cid && !compatUpload?.video_commitment) {
      setErr({ msg: "Upload evidence before opening this compatibility review.", details: null });
      return;
    }

    setCompatRequestBusy(true);
    setErr(null);
    try {
      const headers = getAuthHeaders(acct);
      const r = await tx.runTx({
        title: "Open compatibility review",
        pendingMessage: "Opening compatibility review…",
        successMessage: "Compatibility review submitted.",
        errorMessage: (e) => prettyErr(e).msg,
        getTxId: (res: any) => res?.submit?.result?.tx_id || res?.result?.tx_id,
        finality: { timeoutMs: 20_000, reconcile: async () => reconcileAsyncCompatibilityCase(acct, base, headers) },
        task: async () => {
          const skel: any = await weall.pohTier2TxRequest(
            {
              account_id: acct,
              video_cid: compatUpload?.cid,
              video_commitment: compatUpload?.video_commitment,
              target_tier: 2,
            },
            base,
            headers,
          );
          const skeletonTx = skel?.tx;
          if (!skeletonTx) throw new Error("The backend did not return a valid review request.");
          const payload = { ...(skeletonTx.payload || {}) };
          if (typeof payload.ts_ms === "number" && payload.ts_ms === 0) payload.ts_ms = Date.now();
          const submit = await submitSignedTx({
            account: acct,
            tx_type: String(skeletonTx.tx_type || ""),
            payload,
            parent: skeletonTx.parent ?? null,
            base,
          });
          return { skeleton: skel, submit };
        },
      });

      setResult(r);
      await refresh();
      await loadVerificationData();
      await refreshAccountContext();
    } catch (e: any) {
      setErr(prettyErr(e));
    } finally {
      setCompatRequestBusy(false);
    }
  }

  async function submitLiveRequest(): Promise<void> {
    if (!acct) {
      setErr({ msg: "Sign in before opening live verification.", details: null });
      return;
    }
    setLiveRequestBusy(true);
    setErr(null);
    try {
      const headers = getAuthHeaders(acct);
      const r = await tx.runTx({
        title: "Open live verification",
        pendingMessage: "Opening live verification…",
        successMessage: "Live verification request submitted.",
        errorMessage: (e) => prettyErr(e).msg,
        getTxId: (res: any) => res?.submit?.result?.tx_id || res?.result?.tx_id,
        finality: { timeoutMs: 20_000, reconcile: async () => reconcileLiveCaseVisible(acct, base, headers) },
        task: async () => {
          const skel: any = await weall.pohLiveTxRequest({ account_id: acct }, base, headers);
          const skeletonTx = skel?.tx;
          if (!skeletonTx) throw new Error("The backend did not return a valid live verification request.");
          const submit = await submitSignedTx({
            account: acct,
            tx_type: String(skeletonTx.tx_type || ""),
            payload: skeletonTx.payload || {},
            parent: skeletonTx.parent ?? null,
            base,
          });
          return { skeleton: skel, submit };
        },
      });

      setResult(r);
      await refresh();
      await loadVerificationData();
      await refreshAccountContext();
    } catch (e: any) {
      setErr(prettyErr(e));
    } finally {
      setLiveRequestBusy(false);
    }
  }

  return (
    <div className="pageStack accountVerificationPage">
      <section className="card heroCard">
        <div className="cardBody heroBody compactHero">
          <div className="heroSplit">
            <div>
              <div className="eyebrow">Account Verification</div>
              <h1 className="heroTitle heroTitleSm">Know what your account can do</h1>
              <p className="heroText">
                Verification should feel like normal account trust. You can see your current status, what it unlocks, what to do next,
                and which trusted responsibilities you may earn over time. Technical records stay available, but they are hidden unless you open them.
              </p>
            </div>

            <div className="heroInfoPanel">
              <div className="heroInfoTitle">Your Account Status</div>
              <div className="heroInfoList">
                <span className={`statusPill ${!!acct ? "ok" : ""}`}>{acct ? "Signed in" : "Not signed in"}</span>
                <span className={`statusPill ${hasLocalKeypair ? "ok" : ""}`}>{hasLocalKeypair ? "Device ready" : "Device setup needed"}</span>
                <span className={`statusPill ${sessionKeyPresent ? "ok" : ""}`}>{sessionKeyPresent ? "Session ready" : "Session key needed"}</span>
                <span className={`statusPill ${registered ? "ok" : ""}`}>{registered ? "Account registered" : "Registration needed"}</span>
                <span className={`statusPill ${accountLevel >= 2 ? "ok" : ""}`}>{currentLabel}</span>
              </div>
              <div className="calloutInfo">
                <strong>Next step:</strong> {nextStep}
              </div>
            </div>
          </div>

          <div className="statsGrid statsGridCompact">
            <div className="statCard">
              <span className="statLabel">Current status</span>
              <span className="statValue">{currentLabel}</span>
            </div>
            <div className="statCard">
              <span className="statLabel">What it means</span>
              <span className="statValue statValueLong">{currentSummary}</span>
            </div>
            <div className="statCard">
              <span className="statLabel">Create posts</span>
              <span className="statValue">{snapshot.canPost ? "Available" : "Live verification needed"}</span>
            </div>
          </div>

          {(banned || locked) && (
            <div className="calloutDanger">
              This account is currently restricted. Recovery or reinstatement is required before normal account verification can continue.
            </div>
          )}
        </div>
      </section>

      <ErrorBanner
        message={err?.msg}
        details={err?.details}
        onRetry={() => {
          void refreshVerificationSurface();
        }}
        onDismiss={() => setErr(null)}
      />

      <section className="grid2">
        <article className="card">
          <div className="cardBody formStack">
            <div className="sectionHead">
              <div>
                <div className="eyebrow">Your Account Status</div>
                <h2 className="cardTitle">What is ready now?</h2>
              </div>
              <button className="btn btnGhost" onClick={() => void refreshVerificationSurface()} disabled={loading || casesBusy}>
                {loading || casesBusy ? "Refreshing…" : "Refresh status"}
              </button>
            </div>
            <div className="infoGrid">
              {requirements.map((item) => (
                <div key={item.label} className="infoCard compact">
                  <div className="infoCardHeader">
                    <span className={`statusPill ${item.ok ? "ok" : ""}`}>{item.ok ? "Ready" : "Needed"}</span>
                    <strong>{item.label}</strong>
                  </div>
                  <div className="infoCardText">{item.hint}</div>
                </div>
              ))}
            </div>
          </div>
        </article>

        <article className="card">
          <div className="cardBody formStack">
            <div className="sectionHead">
              <div>
                <div className="eyebrow">Account Setup</div>
                <h2 className="cardTitle">Finish local setup first</h2>
              </div>
              <button className="btn" onClick={() => nav("/login")}>Open sign-in</button>
            </div>
            <p className="cardDesc">
              This device needs a browser session, the matching saved account key, and a visible account record before verification actions can complete.
            </p>
            <div className="buttonRowWide">
              <button
                className="btn btnPrimary"
                onClick={() => void registerAccount()}
                disabled={!acct || !hasLocalKeypair || registered || registerBusy || signerSubmission.busy}
              >
                {registerBusy ? "Registering…" : signerSubmission.busy ? "Waiting…" : registered ? "Account registered" : "Register account"}
              </button>
              <button className="btn" onClick={() => void issueSessionKey()} disabled={!acct || !hasLocalKeypair || sessionBusy || signerSubmission.busy}>
                {sessionBusy ? "Saving…" : signerSubmission.busy ? "Waiting…" : "Save session key"}
              </button>
            </div>
          </div>
        </article>
      </section>

      <section className="grid3">
        <StatusCard
          eyebrow="Account"
          title={VERIFICATION_LABELS.basic}
          status={basicStatus}
          description="You can browse, set up your profile, and start account verification."
        />
        <StatusCard
          eyebrow="Basic human review"
          title={VERIFICATION_LABELS.verified}
          status={verifiedStatus}
          description="Complete a basic human review to join groups, message people, and take part in basic community activity."
        >
          <div className="buttonRowWide">
            <button className="btn" onClick={() => explainNativeAsyncVerification()} disabled={!acct}>
              Show verification next steps
            </button>
          </div>
        </StatusCard>
        <StatusCard
          eyebrow="Live human review"
          title={VERIFICATION_LABELS.trusted}
          status={trustedStatus}
          description="Complete live verification to create posts, vote in community decisions, report harmful content, and apply for trusted responsibilities."
        >
          <button className="btn btnPrimary" onClick={() => void submitLiveRequest()} disabled={!acct || liveRequestBusy || accountLevel >= 2 || accountLevel < 1 || signerSubmission.busy}>
            {liveRequestBusy ? "Opening…" : signerSubmission.busy ? "Waiting…" : accountLevel < 1 ? blockedByVerificationMessage(1) : "Open live verification"}
          </button>
        </StatusCard>
      </section>

      <section className="card">
        <div className="cardBody formStack">
          <div className="sectionHead">
            <div>
              <div className="eyebrow">Trusted Responsibilities</div>
              <h2 className="cardTitle">Responsibilities you can earn over time</h2>
            </div>
            <span className={`statusPill ${accountLevel >= 2 ? "ok" : ""}`}>{accountLevel >= 2 ? "Eligible to apply" : "Live verification required"}</span>
          </div>
          <p className="cardDesc">
            Verification proves account status. Responsibilities prove specific service permission, such as reviewing reports or helping operate network services.
          </p>
          <div className="infoGrid">
            {TRUSTED_RESPONSIBILITIES.map((responsibility) => (
              <div key={responsibility.key} className="infoCard compact">
                <div className="infoCardHeader">
                  <strong>{responsibility.label}</strong>
                  <span className={`statusPill ${accountLevel >= 2 ? "ok" : ""}`}>{accountLevel >= 2 ? "Can apply" : "Locked"}</span>
                </div>
                <div className="infoCardText">{responsibility.description}</div>
                <div className="miniTag">Requires: {responsibility.requires}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="grid2">
        <article className="card">
          <div className="cardBody formStack">
            <div className="sectionHead">
              <div>
                <div className="eyebrow">Verification History</div>
                <h2 className="cardTitle">Requests, reviews, and live sessions</h2>
              </div>
              <span className="statusPill">{liveCases.length + compatCases.length} item(s)</span>
            </div>
            <p className="cardDesc">
              This area shows account-verification work that is visible to this device. It is written as a history of requests and reviews, not as protocol machinery.
            </p>
            {liveCases.length ? <div className="infoGrid">{liveCases.map((it: any, idx: number) => <CaseCard key={String(it?.case_id || idx)} item={it} />)}</div> : null}
            {compatCases.length ? <div className="infoGrid">{compatCases.map((it: any, idx: number) => <CaseCard key={String(it?.case_id || idx)} item={it} />)}</div> : null}
            {!liveCases.length && !compatCases.length ? <div className="emptyState compactEmpty"><div className="emptyTitle">No verification history is visible yet.</div></div> : null}
            {liveSessions.length ? <JsonDetails title="Advanced: live session payloads" value={liveSessions} /> : null}
          </div>
        </article>

        <article className="card">
          <div className="cardBody formStack">
            <div className="sectionHead">
              <div>
                <div className="eyebrow">Advanced Details</div>
                <h2 className="cardTitle">Technical records</h2>
              </div>
            </div>
            <p className="cardDesc">These records are hidden by default because they are for review, debugging, and auditability.</p>
            <JsonDetails title="Advanced: current account state" value={acctState} />
            <JsonDetails title="Advanced: registration payload" value={registration} />
            {result ? <JsonDetails title="Advanced: last API result" value={result} /> : <div className="emptyState compactEmpty"><div className="emptyTitle">No recent action payload.</div></div>}
          </div>
        </article>
      </section>

      <section className="card">
        <div className="cardBody formStack">
          <details className="advancedDisclosure">
            <summary>Advanced compatibility controls</summary>
            <p className="cardDesc">
              This section is for migration-era compatibility only. It must not be presented as the normal account verification path.
            </p>
            {!compatibilityUploadEnabled ? (
              <div className="calloutInfo">Compatibility evidence upload is not enabled on this deployment.</div>
            ) : (
              <div className="formStack">
                <input
                  type="file"
                  accept="video/*"
                  onChange={(e) => {
                    const file = e.target.files?.[0];
                    if (file) void uploadCompatibilityVideo(file);
                  }}
                  disabled={compatUploadBusy || accountLevel >= 2}
                />
                {compatUpload ? <JsonDetails title="Latest compatibility upload payload" value={compatUpload} /> : null}
                <button className="btn btnPrimary" onClick={() => void submitCompatibilityRequest()} disabled={!acct || !compatUpload || compatRequestBusy || accountLevel >= 2 || signerSubmission.busy}>
                  {compatRequestBusy ? "Opening…" : signerSubmission.busy ? "Waiting…" : "Open compatibility review"}
                </button>
              </div>
            )}
          </details>
        </div>
      </section>
    </div>
  );
}
