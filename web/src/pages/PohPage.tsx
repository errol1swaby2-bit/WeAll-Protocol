import React, { useEffect, useMemo, useState } from "react";

import { getApiBaseUrl, getEmailOracleBaseUrl, weall } from "../api/weall";
import ErrorBanner from "../components/ErrorBanner";
import TurnstileWidget from "../components/TurnstileWidget";
import {
  getAuthHeaders,
  getKeypair,
  getSession,
  setSession,
  submitSignedTx,
} from "../auth/session";
import { normalizeAccount, signDetachedB64 } from "../auth/keys";
import { useAccount } from "../context/AccountContext";
import { useTxQueue } from "../hooks/useTxQueue";
import {
  getBootstrapTier3Enabled,
  getDurableOperatorTarget,
  getMediaReplicationTarget,
  getTier2VideoUploadEnabled,
} from "../lib/capabilities";
import { resolveOnboardingSnapshot, summarizeNextRequirements } from "../lib/onboarding";
import { nav } from "../lib/router";

type TierCardProps = {
  tier: number;
  title: string;
  status: "done" | "active" | "locked";
  description: string;
  children?: React.ReactNode;
};

type ErrState = { msg: string; details: any } | null;

type UploadState = {
  cid?: string;
  gateway_url?: string;
  video_commitment?: string;
  mime?: string;
  name?: string;
  size?: number;
};

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

function buildOperatorReceipt(account: string, kp: { pubkeyB64: string; secretKeyB64: string }, relayToken: RelayToken) {
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
  receipt.signature = signDetachedB64(kp.secretKeyB64, canonicalEmailReceiptMessage(receipt));
  return receipt;
}

function prettyErr(e: any): { msg: string; details: any } {
  const details = e?.body || e?.data || e;
  const msg = details?.message || details?.error?.message || e?.message || "error";
  return { msg, details };
}

function statusTone(status: string): "done" | "active" | "locked" {
  const s = String(status || "").toLowerCase();
  if (["complete", "completed", "finalized", "passed", "approved", "active"].includes(s)) return "done";
  if (["open", "pending", "review", "assigned", "scheduled", "accepted", "in_progress"].includes(s)) return "active";
  return "locked";
}

function TierCard({ tier, title, status, description, children }: TierCardProps): JSX.Element {
  return (
    <article className={`card tierCard tierCard-${status}`}>
      <div className="cardBody formStack">
        <div className="sectionHead">
          <div>
            <div className="eyebrow">Tier {tier}</div>
            <h2 className="cardTitle">{title}</h2>
          </div>
          <span className={`statusPill ${status === "done" ? "ok" : ""}`}>
            {status === "done" ? "Complete" : status === "active" ? "Available" : "Locked"}
          </span>
        </div>
        <p className="cardDesc">{description}</p>
        {children}
      </div>
    </article>
  );
}

function JsonDetails({ title, value }: { title: string; value: any }): JSX.Element | null {
  if (!value) return null;
  return (
    <details>
      <summary style={{ cursor: "pointer" }}>{title}</summary>
      <pre style={{ whiteSpace: "pre-wrap", marginTop: 10 }}>{JSON.stringify(value, null, 2)}</pre>
    </details>
  );
}

export default function PohPage(): JSX.Element {
  const base = useMemo(() => getApiBaseUrl(), []);
  const emailOracleBase = useMemo(() => getEmailOracleBaseUrl(), []);
  const useEmailOracle = emailOracleBase.length > 0;
  const session = getSession();
  const acct = session ? normalizeAccount(session.account) : null;
  const kp = acct ? getKeypair(acct) : null;
  const { refresh: refreshAccountContext } = useAccount();
  const tx = useTxQueue();

  const [acctView, setAcctView] = useState<any | null>(null);
  const [registration, setRegistration] = useState<any | null>(null);
  const [acctState, setAcctState] = useState<any | null>(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<ErrState>(null);
  const [result, setResult] = useState<any | null>(null);

  const [bootstrapBusy, setBootstrapBusy] = useState(false);
  const [sessionBusy, setSessionBusy] = useState(false);
  const [registerBusy, setRegisterBusy] = useState(false);
  const [emailBusy, setEmailBusy] = useState(false);
  const [confirmBusy, setConfirmBusy] = useState(false);
  const [tier2UploadBusy, setTier2UploadBusy] = useState(false);
  const [tier2RequestBusy, setTier2RequestBusy] = useState(false);
  const [tier3RequestBusy, setTier3RequestBusy] = useState(false);
  const [casesBusy, setCasesBusy] = useState(false);

  const [email, setEmail] = useState("");
  const [requestId, setRequestId] = useState("");
  const [emailCode, setEmailCode] = useState("");
  const [turnstileToken, setTurnstileToken] = useState("");
  const [tier2Upload, setTier2Upload] = useState<UploadState | null>(null);
  const [tier2Cases, setTier2Cases] = useState<any[]>([]);
  const [tier3Cases, setTier3Cases] = useState<any[]>([]);
  const [tier3Sessions, setTier3Sessions] = useState<any[]>([]);

  const hasLocalKeypair = !!kp?.secretKeyB64;
  const sessionKeyPresent = !!session?.sessionKey;

  const tier2VideoUploadEnabled = getTier2VideoUploadEnabled();
  const bootstrapTier3Enabled = getBootstrapTier3Enabled();
  const replicationTarget = getMediaReplicationTarget();
  const durableOperatorTarget = getDurableOperatorTarget();

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

  async function loadPohData(): Promise<void> {
    if (!acct) {
      setTier2Cases([]);
      setTier3Cases([]);
      setTier3Sessions([]);
      return;
    }
    setCasesBusy(true);
    try {
      const headers = getAuthHeaders(acct);
      const [myTier2, myTier3, sessions] = await Promise.all([
        weall.pohTier2MyCases(acct, base, headers).catch(() => ({ cases: [] })),
        weall.pohTier3Assigned(acct, base, headers).catch(() => ({ cases: [] })),
        weall.pohTier3Sessions(base, headers).catch(() => ({ sessions: [] })),
      ]);
      setTier2Cases(Array.isArray(myTier2?.cases) ? myTier2.cases : []);
      setTier3Cases(Array.isArray(myTier3?.cases) ? myTier3.cases : []);
      setTier3Sessions(Array.isArray(sessions?.sessions) ? sessions.sessions : []);
    } catch (e: any) {
      setErr(prettyErr(e));
    } finally {
      setCasesBusy(false);
    }
  }

  useEffect(() => {
    void refresh();
    void loadPohData();
  }, [acct]);

  const snapshot = resolveOnboardingSnapshot({
    account: acct,
    session,
    keypair: kp,
    accountView: acctView,
    registrationView: registration,
  });

  const requirements = summarizeNextRequirements(snapshot);
  const tier = snapshot.tier;
  const banned = snapshot.banned;
  const locked = snapshot.locked;
  const registered = snapshot.registered;

  const tier1Status: "done" | "active" | "locked" = tier >= 1 ? "done" : "active";
  const tier2Status: "done" | "active" | "locked" = tier >= 2 ? "done" : tier >= 1 ? "active" : "locked";
  const tier3Status: "done" | "active" | "locked" = tier >= 3 ? "done" : tier >= 2 ? "active" : "locked";

  async function registerAccount(): Promise<void> {
    if (!acct) {
      setErr({ msg: "not_logged_in", details: null });
      return;
    }
    if (!kp?.pubkeyB64) {
      setErr({ msg: "local_signer_required", details: null });
      return;
    }
    setRegisterBusy(true);
    setErr(null);
    setResult(null);
    try {
      const r = await tx.runTx({
        title: "Register account",
        pendingMessage: "Submitting ACCOUNT_REGISTER…",
        successMessage: "Account registration submitted.",
        errorMessage: (e) => prettyErr(e).msg,
        getTxId: (res: any) => res?.tx_id || res?.result?.tx_id,
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

  async function bootstrapTier3(): Promise<void> {
    if (!acct) {
      setErr({ msg: "not_logged_in", details: null });
      return;
    }

    setBootstrapBusy(true);
    setErr(null);
    setResult(null);

    try {
      const r = await tx.runTx({
        title: "Bootstrap Tier 3 grant",
        pendingMessage: "Submitting Tier 3 bootstrap grant…",
        successMessage: "Tier 3 bootstrap grant submitted.",
        errorMessage: (e) => prettyErr(e).msg,
        getTxId: (res: any) => res?.result?.tx_id,
        task: async () =>
          submitSignedTx({
            account: acct,
            tx_type: "POH_BOOTSTRAP_TIER3_GRANT",
            payload: {},
            parent: null,
            base,
          }),
      });
      setResult(r);
      await refresh();
      await loadPohData();
      await refreshAccountContext();
    } catch (e: any) {
      setErr(prettyErr(e));
      setResult(e?.body || e?.data || null);
    } finally {
      setBootstrapBusy(false);
    }
  }

  async function issueSessionKey(): Promise<void> {
    if (!acct) {
      setErr({ msg: "not_logged_in", details: null });
      return;
    }

    setSessionBusy(true);
    setErr(null);
    setResult(null);

    try {
      const r = await tx.runTx({
        title: "Issue session key",
        pendingMessage: "Submitting session-key issuance tx…",
        successMessage: "Session-key issuance submitted.",
        errorMessage: (e) => prettyErr(e).msg,
        getTxId: (res: any) => res?.result?.tx_id,
        task: async () =>
          submitSignedTx({
            account: acct,
            tx_type: "ACCOUNT_SESSION_KEY_ISSUE",
            payload: {},
            parent: null,
            base,
          }),
      });

      const sessionKey =
        window.prompt(
          "Paste the session key you want stored for authenticated UI calls.",
          session?.sessionKey || "",
        ) || "";
      if (sessionKey.trim() && session) {
        setSession({ ...session, sessionKey: sessionKey.trim() });
      }

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

  async function beginEmailVerification(): Promise<void> {
    if (!acct) {
      setErr({ msg: "not_logged_in", details: null });
      return;
    }
    if (!registered) {
      setErr({ msg: "registration_required_first", details: null });
      return;
    }
    if (!email.trim()) {
      setErr({ msg: "email_required", details: null });
      return;
    }
    if (useEmailOracle && !turnstileToken.trim()) {
      setErr({ msg: "turnstile_token_required", details: null });
      return;
    }

    setEmailBusy(true);
    setErr(null);
    try {
      const r: any = await tx.runTx({
        title: "Begin email verification",
        pendingMessage: "Sending verification code…",
        successMessage: "Verification code sent.",
        errorMessage: (e) => prettyErr(e).msg,
        task: async () =>
          useEmailOracle
            ? weall.emailOracleStart(
                {
                  account_id: acct,
                  operator_account_id: acct,
                  email: email.trim(),
                  turnstile_token: turnstileToken.trim(),
                },
                emailOracleBase,
              )
            : weall.pohEmailBegin(
                {
                  account: acct,
                  email: email.trim(),
                  turnstile_token: turnstileToken || undefined,
                },
                base,
                getAuthHeaders(acct),
              ),
      });
      setRequestId(String(r?.challenge_id || r?.request_id || ""));
      setResult(r);
    } catch (e: any) {
      setErr(prettyErr(e));
    } finally {
      setEmailBusy(false);
    }
  }

  async function confirmEmailVerification(): Promise<void> {
    if (!acct) {
      setErr({ msg: "not_logged_in", details: null });
      return;
    }
    if (!requestId.trim() || !emailCode.trim()) {
      setErr({ msg: "request_id_and_code_required", details: null });
      return;
    }
    if (!kp?.secretKeyB64 || !kp?.pubkeyB64) {
      setErr({ msg: "local_signer_required", details: null });
      return;
    }
    setConfirmBusy(true);
    setErr(null);
    try {
      const r = await tx.runTx({
        title: "Confirm email verification",
        pendingMessage: "Confirming email code…",
        successMessage: "Email verification confirmed.",
        errorMessage: (e) => prettyErr(e).msg,
        getTxId: (res: any) => res?.submit?.result?.tx_id || res?.result?.tx_id,
        task: async () => {
          if (useEmailOracle) {
            const verifyRes: any = await weall.emailOracleVerify(
              { challenge_id: requestId.trim(), code: emailCode.trim() },
              emailOracleBase,
            );
            const relayToken = verifyRes?.relay_token;
            if (!relayToken?.payload || !relayToken?.signature) throw new Error("invalid_relay_token");
            const receipt = buildOperatorReceipt(acct, kp as any, relayToken as RelayToken);
            const skel: any = await weall.pohEmailReceiptTxSubmit(
              { account_id: acct, receipt },
              base,
              getAuthHeaders(acct),
            );
            const skeletonTx = skel?.tx;
            if (!skeletonTx) throw new Error("invalid_skeleton");
            const submit = await submitSignedTx({
              account: acct,
              tx_type: String(skeletonTx.tx_type || ""),
              payload: skeletonTx.payload || {},
              parent: skeletonTx.parent ?? null,
              base,
            });
            return { verify: verifyRes, receipt, skeleton: skel, submit };
          }
          return await weall.pohEmailConfirm(
            {
              account: acct,
              request_id: requestId.trim(),
              code: emailCode.trim(),
              turnstile_token: turnstileToken || undefined,
            },
            base,
            getAuthHeaders(acct),
          );
        },
      });
      setResult(r);
      await refresh();
      await refreshAccountContext();
    } catch (e: any) {
      setErr(prettyErr(e));
    } finally {
      setConfirmBusy(false);
    }
  }

  async function uploadTier2Video(file: File): Promise<void> {
    setTier2UploadBusy(true);
    setErr(null);
    try {
      const r: any = await tx.runTx({
        title: "Upload Tier 2 video",
        pendingMessage: "Uploading Tier 2 evidence video…",
        successMessage: "Tier 2 evidence uploaded.",
        errorMessage: (e) => prettyErr(e).msg,
        task: async () => weall.pohTier2VideoUpload(file, base, getAuthHeaders(acct || undefined)),
      });
      setTier2Upload(r);
      setResult(r);
    } catch (e: any) {
      setErr(prettyErr(e));
    } finally {
      setTier2UploadBusy(false);
    }
  }

  async function submitTier2Request(): Promise<void> {
    if (!acct) {
      setErr({ msg: "not_logged_in", details: null });
      return;
    }
    if (!tier2Upload?.cid && !tier2Upload?.video_commitment) {
      setErr({ msg: "tier2_video_required", details: null });
      return;
    }

    setTier2RequestBusy(true);
    setErr(null);
    try {
      const r = await tx.runTx({
        title: "Open Tier 2 request",
        pendingMessage: "Submitting Tier 2 request…",
        successMessage: "Tier 2 request submitted.",
        errorMessage: (e) => prettyErr(e).msg,
        getTxId: (res: any) => res?.submit?.result?.tx_id || res?.result?.tx_id,
        task: async () => {
          const skel: any = await weall.pohTier2TxRequest(
            {
              account_id: acct,
              video_cid: tier2Upload?.cid,
              video_commitment: tier2Upload?.video_commitment,
              target_tier: 2,
            },
            base,
            getAuthHeaders(acct),
          );
          const skeletonTx = skel?.tx;
          if (!skeletonTx) throw new Error("invalid_skeleton");
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
      await loadPohData();
      await refreshAccountContext();
    } catch (e: any) {
      setErr(prettyErr(e));
    } finally {
      setTier2RequestBusy(false);
    }
  }

  async function submitTier3Request(): Promise<void> {
    if (!acct) {
      setErr({ msg: "not_logged_in", details: null });
      return;
    }
    setTier3RequestBusy(true);
    setErr(null);
    try {
      const r = await tx.runTx({
        title: "Open Tier 3 request",
        pendingMessage: "Submitting Tier 3 request…",
        successMessage: "Tier 3 request submitted.",
        errorMessage: (e) => prettyErr(e).msg,
        getTxId: (res: any) => res?.submit?.result?.tx_id || res?.result?.tx_id,
        task: async () => {
          const skel: any = await weall.pohTier3TxRequest(
            { account_id: acct },
            base,
            getAuthHeaders(acct),
          );
          const skeletonTx = skel?.tx;
          if (!skeletonTx) throw new Error("invalid_skeleton");
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
      await loadPohData();
      await refreshAccountContext();
    } catch (e: any) {
      setErr(prettyErr(e));
    } finally {
      setTier3RequestBusy(false);
    }
  }

  return (
    <div className="pageStack">
      <section className="card heroCard">
        <div className="cardBody heroBody compactHero">
          <div className="heroSplit">
            <div>
              <div className="eyebrow">Identity and Proof of Humanity</div>
              <h1 className="heroTitle heroTitleSm">Move from device setup into verified participation</h1>
              <p className="heroText">
                This page acts as the canonical onboarding hub for account readiness, Tier 1 email
                verification, Tier 2 video intake, Tier 2 case tracking, Tier 3 request submission,
                and live session visibility.
              </p>
            </div>

            <div className="heroInfoPanel">
              <div className="heroInfoTitle">Current identity status</div>
              <div className="heroInfoList">
                <span className={`statusPill ${!!acct ? "ok" : ""}`}>{acct ? "Account loaded" : "No session"}</span>
                <span className={`statusPill ${hasLocalKeypair ? "ok" : ""}`}>
                  {hasLocalKeypair ? "Local signing ready" : "No local signer"}
                </span>
                <span className={`statusPill ${sessionKeyPresent ? "ok" : ""}`}>
                  {sessionKeyPresent ? "Session key present" : "Session key missing"}
                </span>
                <span className={`statusPill ${registered ? "ok" : ""}`}>
                  {registered ? "Registered" : "Registration needed"}
                </span>
                <span className={`statusPill ${tier >= 1 ? "ok" : ""}`}>PoH tier {tier}</span>
              </div>
            </div>
          </div>

          <div className="statsGrid">
            <div className="statCard">
              <span className="statLabel">Account</span>
              <span className="statValue mono">{acct || "Not signed in"}</span>
            </div>
            <div className="statCard">
              <span className="statLabel">PoH tier</span>
              <span className="statValue">{tier}</span>
            </div>
            <div className="statCard">
              <span className="statLabel">Interaction access</span>
              <span className="statValue">{tier >= 1 ? "Like and comment" : "Verify email first"}</span>
            </div>
            <div className="statCard">
              <span className="statLabel">Posting access</span>
              <span className="statValue">{snapshot.canPost ? "Unlocked" : "Still gated"}</span>
            </div>
          </div>

          {(banned || locked) && (
            <div className="calloutDanger">
              This account is currently {banned ? "banned" : "locked"}. Some actions will remain
              unavailable until the account is restored through protocol rules.
            </div>
          )}
        </div>
      </section>

      <ErrorBanner
        message={err?.msg}
        details={err?.details}
        onRetry={() => {
          void refresh();
          void loadPohData();
        }}
        onDismiss={() => setErr(null)}
      />

      <section className="grid2">
        <article className="card">
          <div className="cardBody formStack">
            <div className="sectionHead">
              <div>
                <div className="eyebrow">Deployment capability</div>
                <h2 className="cardTitle">What this client expects from the stack</h2>
              </div>
            </div>

            <div className="progressList">
              <div className="progressRow">
                <span>Tier 2 video upload UI</span>
                <span className={`statusPill ${tier2VideoUploadEnabled ? "ok" : ""}`}>
                  {tier2VideoUploadEnabled ? "Enabled" : "Disabled"}
                </span>
              </div>
              <div className="progressRow">
                <span>Bootstrap Tier 3 controls</span>
                <span className={`statusPill ${bootstrapTier3Enabled ? "ok" : ""}`}>
                  {bootstrapTier3Enabled ? "Enabled" : "Disabled"}
                </span>
              </div>
              <div className="progressRow">
                <span>Media replication target</span>
                <span className="statusPill">{replicationTarget}</span>
              </div>
              <div className="progressRow">
                <span>Durable operator threshold</span>
                <span className="statusPill">{durableOperatorTarget}</span>
              </div>
            </div>
          </div>
        </article>

        <article className="card">
          <div className="cardBody formStack">
            <div className="sectionHead">
              <div>
                <div className="eyebrow">Readiness</div>
                <h2 className="cardTitle">Backend-aligned onboarding checklist</h2>
              </div>
            </div>

            <div className="infoGrid">
              {requirements.map((item) => (
                <div key={item.label} className="infoCard compact">
                  <div className="infoCardHeader">
                    <span className={`statusPill ${item.ok ? "ok" : ""}`}>
                      {item.ok ? "Ready" : "Needed"}
                    </span>
                    <strong>{item.label}</strong>
                  </div>
                  <div className="infoCardText">{item.hint}</div>
                </div>
              ))}
            </div>
          </div>
        </article>
      </section>

      <section className="grid3">
        <TierCard
          tier={1}
          title="Verified entry"
          status={tier1Status}
          description="Tier 1 verifies control of a human inbox and opens the door to basic network participation."
        >
          <div className="milestoneList">
            <span className="miniTag">Register account</span>
            <span className="miniTag">Email begin + confirm</span>
            <span className="miniTag">Like/comment access</span>
          </div>
        </TierCard>

        <TierCard
          tier={2}
          title="Participant access"
          status={tier2Status}
          description="Tier 2 adds video evidence, juror review, and unlocks broader participation."
        >
          <div className="milestoneList">
            <span className="miniTag">Video upload</span>
            <span className="miniTag">Juror review queue</span>
          </div>
        </TierCard>

        <TierCard
          tier={3}
          title="Steward access"
          status={tier3Status}
          description="Tier 3 moves into live-session validation and unlocks full steward-class participation."
        >
          <div className="milestoneList">
            <span className="miniTag">Live juror session</span>
            <span className="miniTag">Creator / steward capabilities</span>
          </div>
        </TierCard>
      </section>

      <section className="grid2">
        <article className="card">
          <div className="cardBody formStack">
            <div className="sectionHead">
              <div>
                <div className="eyebrow">Device readiness</div>
                <h2 className="cardTitle">Local account setup</h2>
              </div>
              <button className="btn" onClick={() => nav("/login")}>
                Open login
              </button>
            </div>

            <div className="statusSummary">
              <span className={`statusPill ${acct ? "ok" : ""}`}>
                {acct ? "Session found" : "No session"}
              </span>
              <span className={`statusPill ${hasLocalKeypair ? "ok" : ""}`}>
                {hasLocalKeypair ? "Signing key ready" : "Signing key missing"}
              </span>
              <span className={`statusPill ${sessionKeyPresent ? "ok" : ""}`}>
                {sessionKeyPresent ? "API session ready" : "API session missing"}
              </span>
              <span className={`statusPill ${registered ? "ok" : ""}`}>
                {registered ? "Registered" : "Not registered"}
              </span>
            </div>

            <p className="cardDesc">
              The account must exist on-chain before the rest of the flow feels reliable. If you
              are missing a local keypair, device session, or registration state, handle that first.
            </p>

            <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
              <button
                className="btn btnPrimary"
                onClick={() => void registerAccount()}
                disabled={!acct || !hasLocalKeypair || registered || registerBusy}
              >
                {registerBusy ? "Registering…" : registered ? "Account registered" : "Register account"}
              </button>
              <button
                className="btn"
                onClick={() => void issueSessionKey()}
                disabled={!acct || !hasLocalKeypair || sessionBusy}
              >
                {sessionBusy ? "Issuing…" : "Issue session tx"}
              </button>
              {bootstrapTier3Enabled ? (
                <button className="btn" onClick={() => void bootstrapTier3()} disabled={!acct || bootstrapBusy}>
                  {bootstrapBusy ? "Submitting…" : "Bootstrap Tier 3 grant"}
                </button>
              ) : null}
              <button
                className="btn btnGhost"
                onClick={() => {
                  void refresh();
                  void loadPohData();
                }}
                disabled={loading || casesBusy}
              >
                {loading || casesBusy ? "Refreshing…" : "Refresh PoH state"}
              </button>
            </div>
          </div>
        </article>

        <article className="card">
          <div className="cardBody formStack">
            <div className="sectionHead">
              <div>
                <div className="eyebrow">Tier 1</div>
                <h2 className="cardTitle">Email verification</h2>
              </div>
              <span className={`statusPill ${tier >= 1 ? "ok" : ""}`}>
                {tier >= 1 ? "Tier 1 complete" : "Pending"}
              </span>
            </div>

            <label className="formField">
              <span>Email address</span>
              <input
                className="input"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="name@example.com"
              />
            </label>

            <TurnstileWidget onToken={(token: string) => setTurnstileToken(token)} />

            <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
              <button
                className="btn"
                onClick={() => void beginEmailVerification()}
                disabled={!acct || !registered || emailBusy || tier >= 1}
              >
                {emailBusy ? "Sending…" : "Send verification code"}
              </button>
            </div>

            <label className="formField">
              <span>Request ID</span>
              <input
                className="input mono"
                value={requestId}
                onChange={(e) => setRequestId(e.target.value)}
                placeholder="Returned by /start"
              />
            </label>

            <label className="formField">
              <span>Email code</span>
              <input
                className="input mono"
                value={emailCode}
                onChange={(e) => setEmailCode(e.target.value)}
                placeholder="000000"
              />
            </label>

            <button
              className="btn"
              onClick={() => void confirmEmailVerification()}
              disabled={!acct || !registered || confirmBusy || tier >= 1}
            >
              {confirmBusy ? "Confirming…" : "Confirm email code"}
            </button>
          </div>
        </article>
      </section>

      <section className="grid2">
        <article className="card">
          <div className="cardBody formStack">
            <div className="sectionHead">
              <div>
                <div className="eyebrow">Tier 2</div>
                <h2 className="cardTitle">Video evidence intake</h2>
              </div>
              <span className={`statusPill ${tier >= 2 ? "ok" : ""}`}>
                {tier >= 2 ? "Tier 2 complete" : tier2Upload ? "Upload ready" : "Awaiting upload"}
              </span>
            </div>

            {!tier2VideoUploadEnabled ? (
              <div className="calloutInfo">
                Tier 2 video upload UI is disabled for this deployment. The client capability flags
                currently hide the upload surface. Enable it only when the backend route and IPFS
                path are intended to be available.
              </div>
            ) : (
              <>
                <input
                  type="file"
                  accept="video/*"
                  onChange={(e) => {
                    const file = e.target.files?.[0];
                    if (file) void uploadTier2Video(file);
                  }}
                  disabled={tier2UploadBusy || tier >= 2}
                />
                {tier2Upload ? <JsonDetails title="Latest upload payload" value={tier2Upload} /> : null}
                <button
                  className="btn"
                  onClick={() => void submitTier2Request()}
                  disabled={!acct || !tier2Upload || tier2RequestBusy || tier >= 2}
                >
                  {tier2RequestBusy ? "Submitting…" : "Open Tier 2 request"}
                </button>
              </>
            )}
          </div>
        </article>

        <article className="card">
          <div className="cardBody formStack">
            <div className="sectionHead">
              <div>
                <div className="eyebrow">Tier 3</div>
                <h2 className="cardTitle">Live session request</h2>
              </div>
              <span className={`statusPill ${tier >= 3 ? "ok" : ""}`}>
                {tier >= 3 ? "Tier 3 complete" : "Request available"}
              </span>
            </div>

            <p className="cardDesc">
              Tier 3 opens a live juror case. Once operators initialize the session, the join URL
              and participant state will appear in your case timeline below.
            </p>

            <button
              className="btn"
              onClick={() => void submitTier3Request()}
              disabled={!acct || tier3RequestBusy || tier >= 3}
            >
              {tier3RequestBusy ? "Submitting…" : "Open Tier 3 request"}
            </button>
          </div>
        </article>
      </section>

      <section className="grid2">
        <article className="card">
          <div className="cardBody formStack">
            <div className="sectionHead">
              <div>
                <div className="eyebrow">My cases</div>
                <h2 className="cardTitle">Tier 2 request history</h2>
              </div>
              <span className="statusPill">{tier2Cases.length} case(s)</span>
            </div>
            {tier2Cases.length ? (
              <div className="infoGrid">
                {tier2Cases.map((it: any) => (
                  <div key={String(it?.case_id || Math.random())} className="infoCard compact">
                    <div className="infoCardHeader">
                      <strong className="mono">{String(it?.case_id || "case")}</strong>
                      <span className={`statusPill ${statusTone(String(it?.status || "")) === "done" ? "ok" : ""}`}>
                        {String(it?.status || "unknown")}
                      </span>
                    </div>
                    <div className="infoCardText">opened {String(it?.created_at_ms ? new Date(it.created_at_ms).toLocaleString() : "—")}</div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="emptyState compactEmpty">
                <div className="emptyTitle">No Tier 2 cases yet.</div>
              </div>
            )}
          </div>
        </article>

        <article className="card">
          <div className="cardBody formStack">
            <div className="sectionHead">
              <div>
                <div className="eyebrow">My live sessions</div>
                <h2 className="cardTitle">Tier 3 cases and sessions</h2>
              </div>
              <span className="statusPill">{tier3Cases.length} case(s)</span>
            </div>
            {tier3Cases.length ? (
              <div className="infoGrid">
                {tier3Cases.map((it: any) => (
                  <div key={String(it?.case_id || Math.random())} className="infoCard compact">
                    <div className="infoCardHeader">
                      <strong className="mono">{String(it?.case_id || "case")}</strong>
                      <span className={`statusPill ${statusTone(String(it?.status || "")) === "done" ? "ok" : ""}`}>
                        {String(it?.status || "unknown")}
                      </span>
                    </div>
                    <div className="infoCardText">opened {String(it?.created_at_ms ? new Date(it.created_at_ms).toLocaleString() : "—")}</div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="emptyState compactEmpty">
                <div className="emptyTitle">No Tier 3 cases yet.</div>
              </div>
            )}

            {tier3Sessions.length ? <JsonDetails title="Live session payloads" value={tier3Sessions} /> : null}
          </div>
        </article>
      </section>

      {result ? <JsonDetails title="Last API result" value={result} /> : null}
    </div>
  );
}
