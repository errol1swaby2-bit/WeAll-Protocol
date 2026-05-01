import React, { useEffect, useMemo, useState } from "react";

import { getApiBaseUrl, weall } from "../api/weall";
import ErrorBanner from "../components/ErrorBanner";
import {
  getAuthHeaders,
  getKeypair,
  getSession,
  setSession,
  submitSignedTx,
} from "../auth/session";
import { normalizeAccount } from "../auth/keys";
import { useAccount } from "../context/AccountContext";
import { useTxQueue } from "../hooks/useTxQueue";
import { useSignerSubmissionBusy } from "../hooks/useSignerSubmissionBusy";
import { getTier2VideoUploadEnabled } from "../lib/capabilities";
import { resolveOnboardingSnapshot, summarizeNextRequirements } from "../lib/onboarding";
import { nav } from "../lib/router";
import { refreshMutationSlices } from "../lib/revalidation";

type TierCardProps = {
  tier: number | string;
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

type StageTone = "done" | "active" | "locked";

type TimelineStep = {
  id: string;
  eyebrow: string;
  title: string;
  tone: StageTone;
  summary: string;
  detail: string;
};

function prettyErr(e: any): { msg: string; details: any } {
  const details = e?.body || e?.data || e;
  const msg = details?.message || details?.error?.message || e?.message || "error";
  return { msg, details };
}

function statusTone(status: string): StageTone {
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
            <div className="eyebrow">{typeof tier === "number" ? `Tier ${tier}` : tier}</div>
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

function StageSummaryCard({
  eyebrow,
  title,
  tone,
  summary,
  detail,
}: TimelineStep): JSX.Element {
  return (
    <div className={`stageSummaryCard stageTone-${tone}`}>
      <div className="stageSummaryTop">
        <div>
          <div className="eyebrow">{eyebrow}</div>
          <h3 className="stageSummaryTitle">{title}</h3>
        </div>
        <span className={`statusPill ${tone === "done" ? "ok" : ""}`}>
          {tone === "done" ? "Ready" : tone === "active" ? "Current" : "Waiting"}
        </span>
      </div>
      <div className="stageSummaryText">{summary}</div>
      <div className="stageSummaryHint">{detail}</div>
    </div>
  );
}

async function reconcileRegisteredState(account: string, base: string): Promise<{ phase: "confirmed" | "submitted" | "failed" | "unknown"; detail?: string } | null> {
  try {
    const registration = await weall.accountRegistered(account, base);
    if (registration?.registered === true) {
      return {
        phase: "confirmed",
        detail: "The account is already visible as registered on-chain.",
      };
    }
  } catch {
    // ignore and fall back to account view
  }
  try {
    const accountView = await weall.account(account, base);
    const state = accountView?.account?.state ?? accountView?.state ?? null;
    if (state && typeof state === "object") {
      const nonce = Number((state as any)?.nonce || 0);
      const pubkey = String((state as any)?.pubkey || "").trim();
      if (nonce > 0 || !!pubkey) {
        return {
          phase: "confirmed",
          detail: "The authoritative account record is already visible on-chain.",
        };
      }
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
      if (matched) {
        return {
          phase: "confirmed",
          detail: "The issued session key is already visible in authoritative account state.",
        };
      }
    }
  } catch {
    // ignore
  }
  return null;
}

async function reconcileTierVisible(account: string, minimumTier: number, base: string): Promise<{ phase: "confirmed" | "submitted" | "failed" | "unknown"; detail?: string } | null> {
  try {
    const accountView = await weall.account(account, base);
    const state = accountView?.account?.state ?? accountView?.state ?? null;
    const rawTier = Math.max(0, Number((state as any)?.poh_tier || 0));
    const tier = Number.isFinite(rawTier) ? Math.min(2, Math.floor(rawTier)) : 0;
    if (tier >= minimumTier) {
      return {
        phase: "confirmed",
        detail: minimumTier >= 2
          ? "Authoritative account state now reports Live Verified Human."
          : "Authoritative account state now reports Async Verified Human.",
      };
    }
  } catch {
    // ignore
  }
  return null;
}

async function reconcileTier2CaseVisible(account: string, base: string, headers?: HeadersInit): Promise<{ phase: "confirmed" | "submitted" | "failed" | "unknown"; detail?: string } | null> {
  try {
    const cases = await weall.pohTier2MyCases(account, base, headers);
    const items = Array.isArray(cases?.cases) ? cases.cases : [];
    if (items.length > 0) {
      return {
        phase: "confirmed",
        detail: "Your async review compatibility case is already visible on the authoritative PoH surface.",
      };
    }
  } catch {
    // ignore
  }
  return reconcileTierVisible(account, 2, base);
}

async function reconcileTier3CaseVisible(account: string, base: string, headers?: HeadersInit): Promise<{ phase: "confirmed" | "submitted" | "failed" | "unknown"; detail?: string } | null> {
  try {
    const assigned = await weall.pohTier3Assigned(account, base, headers);
    const cases = Array.isArray(assigned?.cases) ? assigned.cases : [];
    if (cases.length > 0) {
      return {
        phase: "confirmed",
        detail: "Your Live Verification case is already visible on the authoritative PoH surface.",
      };
    }
  } catch {
    // ignore
  }
  return reconcileTierVisible(account, 2, base);
}

function CaseCard({ item }: { item: any }): JSX.Element {
  const created = item?.created_at_ms ? new Date(item.created_at_ms).toLocaleString() : "—";
  const tone = statusTone(String(item?.status || ""));
  return (
    <div className="infoCard compact">
      <div className="infoCardHeader">
        <strong className="mono">{String(item?.case_id || "case")}</strong>
        <span className={`statusPill ${tone === "done" ? "ok" : ""}`}>{String(item?.status || "unknown")}</span>
      </div>
      <div className="infoCardText">opened {created}</div>
    </div>
  );
}

export default function PohPage(): JSX.Element {
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
  const [emailBusy, setEmailBusy] = useState(false);
  const [confirmBusy, setConfirmBusy] = useState(false);
  const [tier2UploadBusy, setTier2UploadBusy] = useState(false);
  const [tier2RequestBusy, setTier2RequestBusy] = useState(false);
  const [tier3RequestBusy, setTier3RequestBusy] = useState(false);
  const [casesBusy, setCasesBusy] = useState(false);

  const [email, setEmail] = useState("");
  const [requestId, setRequestId] = useState("");
  const [emailCode, setEmailCode] = useState("");
  const [securityPhrase, setSecurityPhrase] = useState("");
  const [officialSender, setOfficialSender] = useState("verify@poh.weall.org");
  const [emailMasked, setEmailMasked] = useState("");
  const [tier2Upload, setTier2Upload] = useState<UploadState | null>(null);
  const [tier2Cases, setTier2Cases] = useState<any[]>([]);
  const [tier3Cases, setTier3Cases] = useState<any[]>([]);
  const [tier3Sessions, setTier3Sessions] = useState<any[]>([]);

  const hasLocalKeypair = !!kp?.secretKeyB64;
  const sessionKeyPresent = !!session?.sessionKey;

  const tier2VideoUploadEnabled = getTier2VideoUploadEnabled();

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

  async function refreshPohSurface(): Promise<void> {
    await refreshMutationSlices(refresh, refreshAccountContext, loadPohData);
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

  const tier1Status: StageTone = tier >= 1 ? "done" : "active";
  const tier2Status: StageTone = tier >= 2 ? "done" : tier >= 1 ? "active" : "locked";
  const tier3Status: StageTone = tier >= 2 ? "done" : tier >= 1 ? "active" : "locked";

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
        finality: {
          timeoutMs: 16000,
          reconcile: async () => reconcileRegisteredState(acct, base),
        },
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
      setErr({ msg: "not_logged_in", details: null });
      return;
    }

    const requestedSessionKey = (window.prompt(
      "Paste the session key you want stored for authenticated UI calls.",
      session?.sessionKey || "",
    ) || "").trim();
    if (!requestedSessionKey) {
      setErr({ msg: "session_key_required", details: "Paste the session key you want linked to this device before submitting the issuance tx." });
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
        finality: {
          timeoutMs: 16000,
          reconcile: async () => reconcileSessionKeyVisible(acct, requestedSessionKey, base),
        },
        task: async () =>
          submitSignedTx({
            account: acct,
            tx_type: "ACCOUNT_SESSION_KEY_ISSUE",
            payload: { session_key: requestedSessionKey },
            parent: null,
            base,
          }),
      });

      const sessionKey = requestedSessionKey;
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
    const headers = getAuthHeaders(acct);
    setEmailBusy(true);
    setErr(null);
    try {
      const r: any = await tx.runTx({
        title: "Begin legacy async adapter",
        pendingMessage: "Sending legacy verification code…",
        successMessage: "Legacy verification code sent.",
        errorMessage: (e) => prettyErr(e).msg,
        task: async () =>
          weall.pohEmailBegin(
            {
              account: acct,
              email: email.trim(),
            },
            base,
            headers,
          ),
      });
      setRequestId(String(r?.challenge_id || r?.request_id || ""));
      setSecurityPhrase(String(r?.security_phrase || ""));
      setOfficialSender(String(r?.official_sender || "verify@poh.weall.org"));
      setEmailMasked(String(r?.email_masked || ""));
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
        title: "Submit legacy async adapter",
        pendingMessage: "Confirming legacy code…",
        successMessage: "Legacy async adapter confirmed.",
        errorMessage: (e) => prettyErr(e).msg,
        getTxId: (res: any) => res?.submit?.result?.tx_id || res?.result?.tx_id,
        finality: {
          timeoutMs: 20000,
          reconcile: async () => reconcileTierVisible(acct, 1, base),
        },
        task: async () => {
          const verifyRes: any = await weall.emailOracleVerify(
            {
              account: acct,
              email: email.trim(),
              request_id: requestId.trim(),
              code: emailCode.trim(),
            },
            base,
            getAuthHeaders(acct),
          );
          const skeletonTx = verifyRes?.tx;
          if (!skeletonTx) throw new Error("invalid_skeleton");
          const submit = await submitSignedTx({
            account: acct,
            tx_type: String(skeletonTx.tx_type || ""),
            payload: skeletonTx.payload || {},
            parent: skeletonTx.parent ?? null,
            base,
          });
          return { verify: verifyRes, submit };
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
      const headers = getAuthHeaders(acct);
      const r = await tx.runTx({
        title: "Open async escalation request",
        pendingMessage: "Submitting Tier 2 request…",
        successMessage: "Tier 2 request submitted.",
        errorMessage: (e) => prettyErr(e).msg,
        getTxId: (res: any) => res?.submit?.result?.tx_id || res?.result?.tx_id,
        finality: {
          timeoutMs: 20000,
          reconcile: async () => reconcileTier2CaseVisible(acct, base, headers),
        },
        task: async () => {
          const skel: any = await weall.pohTier2TxRequest(
            {
              account_id: acct,
              video_cid: tier2Upload?.cid,
              video_commitment: tier2Upload?.video_commitment,
              target_tier: 2,
            },
            base,
            headers,
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
      const headers = getAuthHeaders(acct);
      const r = await tx.runTx({
        title: "Open Live Verification request",
        pendingMessage: "Submitting Live Verification request…",
        successMessage: "Live Verification request submitted.",
        errorMessage: (e) => prettyErr(e).msg,
        getTxId: (res: any) => res?.submit?.result?.tx_id || res?.result?.tx_id,
        finality: {
          timeoutMs: 20000,
          reconcile: async () => reconcileTier3CaseVisible(acct, base, headers),
        },
        task: async () => {
          const skel: any = await weall.pohTier3TxRequest(
            { account_id: acct },
            base,
            headers,
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

  const pohLevelLabel = tier >= 2 ? "Live Verified Human" : tier >= 1 ? "Async Verified Human" : "Unverified Account";

  const currentStage = useMemo<string>(() => {
    if (!acct) return "Connect or restore a device session first.";
    if (!hasLocalKeypair) return "Create or restore the local signer tied to this account.";
    if (!registered) return "Register the account on-chain before starting PoH actions.";
    if (tier < 1) return "Complete Async Human Verification to unlock basic verified-human participation.";
    if (tier < 2) return "Open the Live Verification live-session request and watch for assigned sessions.";
    return "Live Verification is complete. Service authority now depends on badges and roles.";
  }, [acct, hasLocalKeypair, registered, tier]);



  const nextOwner = useMemo<string>(() => {
    if (!acct) return "You";
    if (!hasLocalKeypair || !sessionKeyPresent) return "You";
    if (!registered) return "You";
    if (tier < 1) return requestId.trim() ? "You → legacy adapter → chain" : "You";
    if (tier < 2) return tier3Cases.length || tier3Sessions.length ? "Assigned jurors / session operators" : "You";
    return "No pending owner";
  }, [acct, hasLocalKeypair, sessionKeyPresent, registered, tier, requestId, tier3Cases.length, tier3Sessions.length]);

  const pendingExpectation = useMemo<string>(() => {
    if (!acct) return "Connect this device to an account before the protocol can track your PoH status.";
    if (!hasLocalKeypair) return "Restore or create the local signer on this device. Nothing has been submitted to the chain yet.";
    if (!registered) return "Register the account on-chain first. PoH review state does not begin until the account exists authoritatively.";
    if (tier < 1) return requestId.trim() ? "A legacy compatibility request exists. The target path is native async juror-attested verification finalized on-chain." : "Start Async Human Verification. Legacy email controls remain compatibility-only until POH_ASYNC_* lands.";
    if (tier < 2) return tier3Cases.length || tier3Sessions.length ? "Live Verification has moved into assigned review or live-session scheduling. Watch the case/session cards rather than guessing completion timing." : "Open the Live Verification request. After submission, the next move comes from session assignment and juror coordination.";
    return "PoH is complete for the two-tier model. Service authority is handled separately through badges and roles.";
  }, [acct, hasLocalKeypair, registered, requestId, sessionKeyPresent, tier, tier3Cases.length, tier3Sessions.length]);

  const successDefinition = useMemo<string>(() => {
    if (tier >= 2) return "Success means Live Verification remains finalized and badge or role requirements are evaluated separately.";
    if (tier >= 1) return "Success means a Live Verification request becomes scheduled, reviewed, and finalized.";
    return "Success means the account completes async human verification and Tier 1 appears in authoritative account state.";
  }, [tier]);

  const stageCards: TimelineStep[] = useMemo(() => [
    {
      id: "device",
      eyebrow: "Stage 1",
      title: "Device and session readiness",
      tone: !acct || !hasLocalKeypair || !sessionKeyPresent ? "active" : "done",
      summary: !acct
        ? "No current browser session is loaded."
        : hasLocalKeypair
          ? sessionKeyPresent
            ? "This device can sign and has an API session key."
            : "This device can sign, but the API session key is still missing."
          : "The account is known, but the local signer is missing on this device.",
      detail: "Local signer and device session are local prerequisites. They are not the same thing as on-chain account state.",
    },
    {
      id: "tier1",
      eyebrow: "Stage 2",
      title: "Tier 1 async human verification",
      tone: tier1Status,
      summary: tier >= 1 ? "Async Verified Human is complete and basic participation is unlocked." : "Open the native async review path when available; legacy adapter controls are compatibility-only.",
      detail: "The v2.1 target is juror-attested async verification finalized on-chain, not inbox control as identity authority.",
    },
    {
      id: "tier2",
      eyebrow: "Stage 3",
      title: "Tier 2 live verification",
      tone: tier3Status,
      summary: tier >= 2 ? "Live Verified Human is complete." : tier >= 1 ? "Open the Live Verification request, then watch for live-session assignment." : "Live Verification stays locked until Async Verified Human is complete.",
      detail: "Live Verification depends on scheduled live review state from the backend and assigned jurors. The UI should show request state, not guess finality.",
    },
    {
      id: "badges",
      eyebrow: "Stage 4",
      title: "Badges and roles",
      tone: tier >= 2 ? "active" : "locked",
      summary: tier >= 2 ? "Service authority is now evaluated through badges, roles, activation, suspension, and receipts." : "Badges and roles stay locked until the required PoH level is complete.",
      detail: "PoH proves human-verification strength. It does not automatically grant juror, validator, node-operator, treasury, or moderator authority.",
    },
  ], [acct, hasLocalKeypair, sessionKeyPresent, tier, tier1Status, tier3Status]);

  return (
    <div className="pageStack">
      <section className="card heroCard">
        <div className="cardBody heroBody compactHero">
          <div className="heroSplit">
            <div>
              <div className="eyebrow">Proof of Humanity lifecycle</div>
              <h1 className="heroTitle heroTitleSm">Move deliberately from local setup into authoritative eligibility</h1>
              <p className="heroText">
                This surface now treats PoH as a staged protocol workflow instead of a bag of forms. It separates local device readiness,
                native async verification, live verification, on-chain registration state, and badge or role progression so the UI does not blur what is merely prepared,
                what has been submitted, and what the network has actually finalized.
              </p>
            </div>

            <div className="heroInfoPanel">
              <div className="heroInfoTitle">Current PoH posture</div>
              <div className="heroInfoList">
                <span className={`statusPill ${!!acct ? "ok" : ""}`}>{acct ? "Session loaded" : "No session"}</span>
                <span className={`statusPill ${hasLocalKeypair ? "ok" : ""}`}>{hasLocalKeypair ? "Local signer ready" : "Local signer missing"}</span>
                <span className={`statusPill ${sessionKeyPresent ? "ok" : ""}`}>{sessionKeyPresent ? "API session ready" : "API session missing"}</span>
                <span className={`statusPill ${registered ? "ok" : ""}`}>{registered ? "On-chain account registered" : "Registration needed"}</span>
                <span className={`statusPill ${tier >= 1 ? "ok" : ""}`}>{pohLevelLabel}</span>
              </div>
              <div className="calloutInfo">
                <strong>Next unlock:</strong> {currentStage}
              </div>
            </div>
          </div>

          <div className="statsGrid statsGridCompact">
            <div className="statCard">
              <span className="statLabel">Local device</span>
              <span className="statValue">{hasLocalKeypair ? "Can sign" : "Cannot sign yet"}</span>
            </div>
            <div className="statCard">
              <span className="statLabel">On-chain standing</span>
              <span className="statValue">{registered ? `Registered · ${pohLevelLabel}` : "Not registered"}</span>
            </div>
            <div className="statCard">
              <span className="statLabel">Posting rights</span>
              <span className="statValue">{snapshot.canPost ? "Unlocked" : "Still gated"}</span>
            </div>
          </div>

          {(banned || locked) && (
            <div className="calloutDanger">
              This account is currently {banned ? "banned" : "locked"}. Protocol recovery or reinstatement must happen before normal PoH progression can continue.
            </div>
          )}
        </div>
      </section>

      <ErrorBanner
        message={err?.msg}
        details={err?.details}
        onRetry={() => {
          void refreshPohSurface();
        }}
        onDismiss={() => setErr(null)}
      />

      <section className="grid2">
        <article className="card">
          <div className="cardBody formStack">
            <div className="sectionHead">
              <div>
                <div className="eyebrow">Readiness model</div>
                <h2 className="cardTitle">What this page separates on purpose</h2>
              </div>
            </div>
            <div className="infoGrid">
              <div className="infoCard compact">
                <div className="infoCardHeader"><strong>Local device state</strong></div>
                <div className="infoCardText">Keypair presence and browser session are local facts, not consensus facts.</div>
              </div>
              <div className="infoCard compact">
                <div className="infoCardHeader"><strong>Backend assistance</strong></div>
                <div className="infoCardText">Case and session discovery depend on backend-assisted views, but PoH authority must be finalized by chain state.</div>
              </div>
              <div className="infoCard compact">
                <div className="infoCardHeader"><strong>On-chain standing</strong></div>
                <div className="infoCardText">Registration and finalized PoH tiers are authoritative chain state.</div>
              </div>
              <div className="infoCard compact">
                <div className="infoCardHeader"><strong>Review workflow</strong></div>
                <div className="infoCardText">Async and live verification are review processes, not instant unlock buttons.</div>
              </div>
            </div>
          </div>
        </article>

        <article className="card">
          <div className="cardBody formStack">
            <div className="sectionHead">
              <div>
                <div className="eyebrow">Backend-aligned checklist</div>
                <h2 className="cardTitle">Current requirements and blockers</h2>
              </div>
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
      </section>

      <section className="stageSummaryGrid">
        {stageCards.map((step) => (
          <StageSummaryCard key={step.id} {...step} />
        ))}
      </section>

      <section className="grid3">
        <TierCard
          tier={1}
          title="Async Verified Human"
          status={tier1Status}
          description="Tier 1 is native async human verification and opens basic verified-human participation."
        >
          <div className="milestoneList">
            <span className="miniTag">Register account</span>
            <span className="miniTag">Open async review</span>
            <span className="miniTag">Juror-attested finalization</span>
          </div>
        </TierCard>

        <TierCard
          tier={2}
          title="Live Verified Human"
          status={tier3Status}
          description="Tier 2 is live juror-attested verification for high-trust participation."
        >
          <div className="milestoneList">
            <span className="miniTag">Live-session request</span>
            <span className="miniTag">Assigned jurors</span>
            <span className="miniTag">Final verdict</span>
          </div>
        </TierCard>

        <TierCard
          tier="Badges"
          title="Service authority"
          status={tier >= 2 ? "active" : "locked"}
          description="Juror, validator, node-operator, storage, treasury, and moderator authority comes from badges and roles, not from a hidden third PoH tier."
        >
          <div className="milestoneList">
            <span className="miniTag">Role enrollment</span>
            <span className="miniTag">Activation state</span>
            <span className="miniTag">Receipts and performance</span>
          </div>
        </TierCard>
      </section>

      <section className="grid2">
        <article className="card">
          <div className="cardBody formStack">
            <div className="sectionHead">
              <div>
                <div className="eyebrow">Stage 1</div>
                <h2 className="cardTitle">Local device and account readiness</h2>
              </div>
              <button className="btn" onClick={() => nav("/login")}>Open login</button>
            </div>

            <p className="cardDesc">
              Handle all local prerequisites first. This includes restoring the browser session, ensuring the local signer exists on this device,
              and registering the account on-chain before the rest of the PoH lifecycle is attempted.
            </p>

            <div className="statusSummary">
              <span className={`statusPill ${acct ? "ok" : ""}`}>{acct ? "Browser session loaded" : "No browser session"}</span>
              <span className={`statusPill ${hasLocalKeypair ? "ok" : ""}`}>{hasLocalKeypair ? "Local signer ready" : "Signer missing"}</span>
              <span className={`statusPill ${sessionKeyPresent ? "ok" : ""}`}>{sessionKeyPresent ? "Session key present" : "Session key missing"}</span>
              <span className={`statusPill ${registered ? "ok" : ""}`}>{registered ? "Registered on-chain" : "Registration needed"}</span>
            </div>

            <div className="buttonRowWide">
              <button
                className="btn btnPrimary"
                onClick={() => void registerAccount()}
                disabled={!acct || !hasLocalKeypair || registered || registerBusy || signerSubmission.busy}
              >
                {registerBusy ? "Registering…" : signerSubmission.busy ? "Waiting for signer…" : registered ? "Account registered" : "Register account"}
              </button>
              <button className="btn" onClick={() => void issueSessionKey()} disabled={!acct || !hasLocalKeypair || sessionBusy || signerSubmission.busy}>
                {sessionBusy ? "Issuing…" : signerSubmission.busy ? "Waiting for signer…" : "Issue session tx"}
              </button>
              <button
                className="btn btnGhost"
                onClick={() => {
                  void refreshPohSurface();
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
                <div className="eyebrow">Stage 2</div>
                <h2 className="cardTitle">Async Human Verification</h2>
              </div>
              <span className={`statusPill ${tier >= 1 ? "ok" : ""}`}>{tier >= 1 ? "Async verified" : "Async pending"}</span>
            </div>

            <p className="cardDesc">
              The v2.1 target path is native async juror-attested verification finalized on-chain. The email controls below are retained only as a legacy compatibility adapter while POH_ASYNC_* is introduced.
            </p>

            <label className="formField">
              <span>Legacy adapter email address</span>
              <input className="input" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="name@example.com" />
            </label>

            <div className="muted">
              Legacy email verification is not protocol authority in the v2.1 model. Use this adapter only while migrating deployments that have not yet enabled native async juror review.
            </div>

            <div className="buttonRowWide">
              <button className="btn" onClick={() => void beginEmailVerification()} disabled={!acct || !registered || emailBusy || tier >= 1 || signerSubmission.busy}>
                {emailBusy ? "Sending…" : signerSubmission.busy ? "Waiting for signer…" : "Send legacy code"}
              </button>
            </div>

            <div className="formGrid">
              {(securityPhrase || emailMasked) ? (
                <div className="calloutInfo formStack">
                  <div><strong>Official sender:</strong> {officialSender}</div>
                  {securityPhrase ? <div><strong>Security phrase:</strong> {securityPhrase}</div> : null}
                  {emailMasked ? <div><strong>Sent to:</strong> {emailMasked}</div> : null}
                  <div className="muted">Only trust the email if the phrase matches what is shown inside WeAll.</div>
                </div>
              ) : null}
              <label className="formField">
                <span>Request ID</span>
                <input className="input mono" value={requestId} onChange={(e) => setRequestId(e.target.value)} placeholder="Returned by verification begin" />
              </label>
              <label className="formField">
                <span>Legacy code</span>
                <input className="input mono" value={emailCode} onChange={(e) => setEmailCode(e.target.value)} placeholder="000000" />
              </label>
            </div>

            <button className="btn btnPrimary" onClick={() => void confirmEmailVerification()} disabled={!acct || !registered || confirmBusy || tier >= 1 || signerSubmission.busy}>
              {confirmBusy ? "Confirming…" : signerSubmission.busy ? "Waiting for signer…" : "Submit legacy Tier 1 adapter"}
            </button>
          </div>
        </article>
      </section>

      <section className="grid2">
        <article className="card">
          <div className="cardBody formStack">
            <div className="sectionHead">
              <div>
                <div className="eyebrow">Stage 3</div>
                <h2 className="cardTitle">Async escalation compatibility review</h2>
              </div>
              <span className={`statusPill ${tier >= 2 ? "ok" : ""}`}>{tier2Upload ? "Evidence ready" : "Compatibility path"}</span>
            </div>

            {!tier2VideoUploadEnabled ? (
              <div className="calloutInfo">
                Async escalation video intake is not enabled on this deployment. This compatibility surface stays explicit so it is not confused with the new canonical Tier 1 async path.
              </div>
            ) : (
              <>
                <p className="cardDesc">
                  This legacy Tier 2 request path is retained as an async escalation/follow-up compatibility control. It must not be presented as a permanent third account tier or as the required Tier 1 native async path.
                </p>
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
                <button className="btn btnPrimary" onClick={() => void submitTier2Request()} disabled={!acct || !tier2Upload || tier2RequestBusy || tier >= 2 || signerSubmission.busy}>
                  {tier2RequestBusy ? "Submitting…" : signerSubmission.busy ? "Waiting for signer…" : "Open async escalation request"}
                </button>
              </>
            )}
          </div>
        </article>

        <article className="card">
          <div className="cardBody formStack">
            <div className="sectionHead">
              <div>
                <div className="eyebrow">Stage 3</div>
                <h2 className="cardTitle">Live Verification live-session request</h2>
              </div>
              <span className={`statusPill ${tier >= 2 ? "ok" : ""}`}>{tier >= 2 ? "Live Verification complete" : "Live Verification pending"}</span>
            </div>

            <p className="cardDesc">
              Live Verification opens a live juror case after Async Verified Human. Once the backend and operators assign a real session, the case and session payloads appear below. The UI should present that state as discovered and authoritative, not guessed.
            </p>

            <button className="btn btnPrimary" onClick={() => void submitTier3Request()} disabled={!acct || tier3RequestBusy || tier >= 2 || tier < 1 || signerSubmission.busy}>
              {tier3RequestBusy ? "Submitting…" : signerSubmission.busy ? "Waiting for signer…" : tier < 1 ? "Finish Async Verification first" : "Open Live Verification request"}
            </button>
          </div>
        </article>
      </section>

      <section className="grid2">
        <article className="card">
          <div className="cardBody formStack">
            <div className="sectionHead">
              <div>
                <div className="eyebrow">Observed state</div>
                <h2 className="cardTitle">My async escalation compatibility cases</h2>
              </div>
              <span className="statusPill">{tier2Cases.length} case(s)</span>
            </div>
            {tier2Cases.length ? <div className="infoGrid">{tier2Cases.map((it: any, idx: number) => <CaseCard key={String(it?.case_id || idx)} item={it} />)}</div> : <div className="emptyState compactEmpty"><div className="emptyTitle">No async escalation compatibility cases yet.</div></div>}
          </div>
        </article>

        <article className="card">
          <div className="cardBody formStack">
            <div className="sectionHead">
              <div>
                <div className="eyebrow">Observed state</div>
                <h2 className="cardTitle">My Live Verification cases and sessions</h2>
              </div>
              <span className="statusPill">{tier3Cases.length} case(s)</span>
            </div>
            {tier3Cases.length ? <div className="infoGrid">{tier3Cases.map((it: any, idx: number) => <CaseCard key={String(it?.case_id || idx)} item={it} />)}</div> : <div className="emptyState compactEmpty"><div className="emptyTitle">No Live Verification cases yet.</div></div>}
            {tier3Sessions.length ? <JsonDetails title="Live session payloads" value={tier3Sessions} /> : null}
          </div>
        </article>
      </section>

      <section className="grid2">
        <article className="card">
          <div className="cardBody formStack">
            <div className="sectionHead">
              <div>
                <div className="eyebrow">Deployment capability</div>
                <h2 className="cardTitle">What this stack currently exposes</h2>
              </div>
            </div>

            <div className="progressList">
              <div className="progressRow"><span>Native async Tier 1</span><span className="statusPill">Target migration</span></div>
              <div className="progressRow"><span>Legacy async escalation intake</span><span className={`statusPill ${tier2VideoUploadEnabled ? "ok" : ""}`}>{tier2VideoUploadEnabled ? "Compatibility on" : "Unavailable here"}</span></div>
              <div className="progressRow"><span>Live Verification request submit</span><span className={`statusPill ${tier >= 1 ? "ok" : ""}`}>{tier >= 1 ? "Available after Async Verification" : "Locked until Async Verification"}</span></div>
            </div>
            <p className="cardDesc">Founder-only or bootstrap shortcuts stay off this surface so the UI remains aligned with real user-facing protocol behavior.</p>
          </div>
        </article>

        <article className="card">
          <div className="cardBody formStack">
            <div className="sectionHead">
              <div>
                <div className="eyebrow">Advanced details</div>
                <h2 className="cardTitle">Raw payloads and recent result</h2>
              </div>
            </div>
            <JsonDetails title="Current account state payload" value={acctState} />
            <JsonDetails title="Registration payload" value={registration} />
            {result ? <JsonDetails title="Last API result" value={result} /> : <div className="emptyState compactEmpty"><div className="emptyTitle">No recent action payload.</div></div>}
          </div>
        </article>
      </section>
    </div>
  );
}
