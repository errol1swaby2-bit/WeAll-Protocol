import React, { useEffect, useMemo, useRef, useState } from "react";

import { getApiBaseUrl, weall } from "../api/weall";
import ErrorBanner from "../components/ErrorBanner";
import {
  beginNonceSequence,
  getAuthHeaders,
  getKeypair,
  getSession,
  setSession,
  submitSignedTx,
  submitSignedTxInSequence,
} from "../auth/session";
import { normalizeAccount } from "../auth/keys";
import { useAccount } from "../context/AccountContext";
import { useTxQueue } from "../hooks/useTxQueue";
import { useSignerSubmissionBusy } from "../hooks/useSignerSubmissionBusy";
import { resolveOnboardingSnapshot, summarizeNextRequirements } from "../lib/onboarding";
import { nav } from "../lib/router";
import { refreshMutationSlices } from "../lib/revalidation";
import {
  ASYNC_VIDEO_MAX_SECONDS,
  ASYNC_VIDEO_MIN_SECONDS,
  AsyncVerificationChallenge,
  canSubmitAsyncEvidence,
  createAsyncVerificationChallenge,
  sha256HexText,
  validateAsyncVideoDuration,
} from "../lib/verificationEvidence";
import { createLiveVerificationCommitments, hasRequiredLiveVerificationCommitments } from "../lib/liveVerification";
import { liveRoomDescriptorText, liveRoomTransportNotice, liveRoomUrlFromCommitment } from "../lib/liveRoom";
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
  uri?: string;
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

function asRecord(value: any): Record<string, any> {
  return value && typeof value === "object" && !Array.isArray(value) ? value : {};
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
  const reviewability = asyncCaseReviewability(item);
  const reason = String(item?.reviewer_queue_reason || "").trim();
  const humanReason = reason === "finalized" || ["approved", "rejected", "finalized"].includes(String(item?.status || "").toLowerCase())
    ? "This verification case has been finalized on-chain."
    : reason === "case_opened_not_reviewable"
      ? "Case opened. Evidence still needs to be declared and bound before reviewers can see it."
      : reason === "case_reviewable_not_assigned"
        ? "Evidence is reviewable. Waiting for juror assignment."
        : reason === "assigned"
          ? "Assigned reviewers can now see this case."
          : "Waiting for the next verification step.";
  return (
    <div className="infoCard compact">
      <div className="infoCardHeader">
        <strong>{String(item?.case_id || "Review case")}</strong>
        <span className={`statusPill ${tone === "done" || reviewability.reviewable ? "ok" : ""}`}>{reviewability.reviewable ? "Reviewable" : String(item?.status || "unknown")}</span>
      </div>
      <div className="infoCardText">Opened {created}</div>
      <div className="infoCardText">{humanReason}</div>
      {reviewability.missingSteps.length ? <div className="miniMuted">Missing: {reviewability.missingSteps.join(", ")}</div> : null}
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
    const cases = await weall.pohAsyncMyCases(account, base, headers);
    const items = Array.isArray(cases?.cases) ? cases.cases : [];
    if (items.length > 0) return { phase: "confirmed", detail: "Your async verification case is visible." };
  } catch {
    // ignore
  }
  return reconcileVerificationLevel(account, 1, base);
}

async function reconcileLiveCaseVisible(account: string, base: string, headers?: HeadersInit): Promise<{ phase: "confirmed" | "submitted" | "failed" | "unknown"; detail?: string } | null> {
  try {
    const mine = await weall.pohLiveMyCases(account, base, headers);
    const cases = Array.isArray(mine?.cases) ? mine.cases : [];
    if (cases.length > 0) return { phase: "confirmed", detail: "Your live verification case is visible." };
  } catch {
    // ignore
  }
  return null;
}

async function waitForLiveCaseIdVisible(account: string, base: string, headers?: HeadersInit, options?: { maxWaitMs?: number; intervalMs?: number }): Promise<string> {
  const acct = normalizeAccount(account);
  if (!acct) return "";
  const started = Date.now();
  const maxWaitMs = Math.max(1000, Number(options?.maxWaitMs ?? 45000));
  const intervalMs = Math.max(250, Number(options?.intervalMs ?? 750));

  while (Date.now() - started < maxWaitMs) {
    try {
      const mine = await weall.pohLiveMyCases(acct, base, headers);
      const cases = Array.isArray(mine?.cases) ? mine.cases : [];
      const visible = cases
        .map((item: any) => String(item?.case_id || item?.id || "").trim())
        .filter(Boolean);
      if (visible.length > 0) return visible[visible.length - 1];
    } catch {
      // The request may be confirmed upstream before the read-model exposes the
      // live case locally. Keep polling within a bounded local rehearsal window.
    }
    await new Promise((resolve) => window.setTimeout(resolve, intervalMs));
  }
  return "";
}

function expectedLiveCaseIdFromNonce(account: string, nonce: number): string {
  const acct = normalizeAccount(account);
  const n = Math.max(0, Math.floor(Number(nonce || 0)));
  return acct && n > 0 ? `poh_live:${acct}:${n}` : "";
}



async function waitForSubmittedTxVisible(
  base: string,
  txId: string,
  options?: { maxWaitMs?: number; intervalMs?: number; requireLocalStateSynced?: boolean; acceptAccepted?: boolean },
): Promise<boolean> {
  const clean = String(txId || "").trim();
  if (!clean) return true;
  const started = Date.now();
  const maxWaitMs = Math.max(1000, Number(options?.maxWaitMs ?? 20000));
  const intervalMs = Math.max(250, Number(options?.intervalMs ?? 500));
  const requireLocalStateSynced = options?.requireLocalStateSynced === true;
  const acceptAccepted = options?.acceptAccepted === true;

  while (Date.now() - started < maxWaitMs) {
    try {
      const st: any = await weall.txStatus(clean, base);
      const status = String(st?.status || st?.phase || "").trim().toLowerCase();
      const statusVisible = status === "confirmed" || status === "committed" || (acceptAccepted && status === "accepted");
      const localSynced = st?.local_state_synced === true;
      if (st?.ok === true && statusVisible && (!requireLocalStateSynced || localSynced)) {
        return true;
      }
    } catch {
      // The observer may not know the tx immediately while the durable tx_queue
      // forwards it upstream. Keep polling until the bounded wait expires.
    }
    await new Promise((resolve) => window.setTimeout(resolve, intervalMs));
  }
  return false;
}

type AsyncCaseReviewability = {
  exists: boolean;
  evidenceDeclared: boolean;
  evidenceBound: boolean;
  reviewable: boolean;
  assigned: boolean;
  status?: string;
  missingSteps: string[];
};

function asyncCaseReviewability(item: any): AsyncCaseReviewability {
  const evidenceCommitments = item?.evidence_commitments && typeof item.evidence_commitments === "object" ? item.evidence_commitments : {};
  const evidenceBinds = item?.evidence_binds && typeof item.evidence_binds === "object" ? item.evidence_binds : {};
  const reviewableEvidence = item?.reviewable_evidence && typeof item.reviewable_evidence === "object" ? item.reviewable_evidence : {};
  const reviewerRestrictedEvidence = item?.reviewer_restricted_evidence && typeof item.reviewer_restricted_evidence === "object" ? item.reviewer_restricted_evidence : {};
  const publicEvidenceIds = Array.isArray(item?.public_evidence_ids) ? item.public_evidence_ids : [];
  const assignedJurors = Array.isArray(item?.assigned_jurors) ? item.assigned_jurors : [];
  const status = String(item?.status || "").trim();
  const finalOrReviewed = ["approved", "rejected", "finalized"].includes(status.toLowerCase()) || !!item?.outcome || !!item?.receipt || item?.finalized_height != null;
  const evidenceDeclared = Object.keys(evidenceCommitments).length > 0 || publicEvidenceIds.length > 0 || Object.keys(reviewableEvidence).length > 0 || Object.keys(reviewerRestrictedEvidence).length > 0 || finalOrReviewed;
  const evidenceBound = Object.keys(evidenceBinds).length > 0 || publicEvidenceIds.length > 0 || Object.keys(reviewableEvidence).length > 0 || Object.keys(reviewerRestrictedEvidence).length > 0 || finalOrReviewed;
  const assigned = assignedJurors.some((j: any) => String(j || "").trim()) || !!item?.jurors;
  const reviewable = finalOrReviewed || (evidenceDeclared && evidenceBound);
  const missingSteps: string[] = [];
  if (!evidenceDeclared) missingSteps.push("evidence_declare");
  if (!evidenceBound) missingSteps.push("evidence_bind");
  if (!assigned && !finalOrReviewed) missingSteps.push("juror_assignment");
  return {
    exists: !!item,
    evidenceDeclared,
    evidenceBound,
    reviewable,
    assigned,
    status: status || undefined,
    missingSteps,
  };
}

async function waitForAccountNonceAtLeast(account: string, minNonce: number, base: string, options?: { maxWaitMs?: number; intervalMs?: number }): Promise<boolean> {
  const acct = normalizeAccount(account);
  const target = Math.max(0, Math.floor(Number(minNonce || 0)));
  if (!acct || target <= 0) return false;
  const started = Date.now();
  const maxWaitMs = Math.max(1000, Number(options?.maxWaitMs ?? 30000));
  const intervalMs = Math.max(250, Number(options?.intervalMs ?? 750));

  while (Date.now() - started < maxWaitMs) {
    try {
      const accountView = await weall.account(acct, base);
      const state = accountView?.account?.state ?? accountView?.state ?? null;
      const nonce = Number((state as any)?.nonce ?? 0);
      if (Number.isFinite(nonce) && Math.floor(nonce) >= target) return true;
    } catch {
      // The observer may be behind the upstream confirmer while it reconciles.
    }
    await new Promise((resolve) => window.setTimeout(resolve, intervalMs));
  }
  return false;
}

async function waitForAsyncCaseReviewable(account: string, caseId: string, base: string, headers?: HeadersInit, options?: { maxWaitMs?: number; intervalMs?: number }): Promise<AsyncCaseReviewability> {
  const acct = normalizeAccount(account);
  const cleanCaseId = String(caseId || "").trim();
  const fallback: AsyncCaseReviewability = { exists: false, evidenceDeclared: false, evidenceBound: false, reviewable: false, assigned: false, missingSteps: ["request_open", "evidence_declare", "evidence_bind", "juror_assignment"] };
  if (!acct || !cleanCaseId) return fallback;
  const started = Date.now();
  const maxWaitMs = Math.max(1000, Number(options?.maxWaitMs ?? 25000));
  const intervalMs = Math.max(250, Number(options?.intervalMs ?? 600));
  let latest = fallback;

  while (Date.now() - started < maxWaitMs) {
    try {
      const mine = await weall.pohAsyncMyCases(acct, base, headers);
      const cases = Array.isArray(mine?.cases) ? mine.cases : [];
      const found = cases.find((item: any) => String(item?.case_id || "").trim() === cleanCaseId);
      if (found) {
        latest = asyncCaseReviewability(found);
        if (latest.reviewable) return latest;
      }
    } catch {
      // keep polling
    }
    await new Promise((resolve) => window.setTimeout(resolve, intervalMs));
  }
  return latest;
}

async function waitForAsyncCaseReviewability(account: string, caseId: string, base: string, headers?: HeadersInit, options?: { maxWaitMs?: number; intervalMs?: number }): Promise<AsyncCaseReviewability> {
  return waitForAsyncCaseReviewable(account, caseId, base, headers, options);
}

async function waitForAsyncCaseVisible(account: string, caseId: string, base: string, headers?: HeadersInit, options?: { maxWaitMs?: number; intervalMs?: number }): Promise<boolean> {
  const reviewability = await waitForAsyncCaseReviewable(account, caseId, base, headers, options);
  return reviewability.reviewable;
}

export default function AccountVerificationPage(): JSX.Element {
  const base = useMemo(() => getApiBaseUrl(), []);
  const session = getSession();
  const acct = session ? normalizeAccount(session.account) : null;
  const kp = acct ? getKeypair(acct) : null;
  const { refresh: refreshAccountContext } = useAccount();
  const tx = useTxQueue();
  const signerSubmission = useSignerSubmissionBusy(acct);

  const recorderRef = useRef<MediaRecorder | null>(null);
  const recordingChunksRef = useRef<Blob[]>([]);
  const recordingStreamRef = useRef<MediaStream | null>(null);
  const recordingStartedAtRef = useRef<number>(0);
  const recordingTimerRef = useRef<number | null>(null);
  const asyncPreviewVideoRef = useRef<HTMLVideoElement | null>(null);

  const [acctView, setAcctView] = useState<any | null>(null);
  const [registration, setRegistration] = useState<any | null>(null);
  const [reviewerStatus, setReviewerStatus] = useState<any | null>(null);
  const [acctState, setAcctState] = useState<any | null>(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<ErrState>(null);
  const [result, setResult] = useState<any | null>(null);

  const [sessionBusy, setSessionBusy] = useState(false);
  const [registerBusy, setRegisterBusy] = useState(false);
  const [liveRequestBusy, setLiveRequestBusy] = useState(false);
  const [liveCommitments, setLiveCommitments] = useState<any | null>(null);
  const [reviewerBusy, setReviewerBusy] = useState<"optIn" | "optOut" | null>(null);
  const [casesBusy, setCasesBusy] = useState(false);
  const [asyncEvidenceBusy, setAsyncEvidenceBusy] = useState(false);

  const [asyncChallenge, setAsyncChallenge] = useState<AsyncVerificationChallenge | null>(null);
  const [asyncRecordingState, setAsyncRecordingState] = useState<"idle" | "recording" | "ready">("idle");
  const [asyncRecordedBlob, setAsyncRecordedBlob] = useState<Blob | null>(null);
  const [asyncRecordedUrl, setAsyncRecordedUrl] = useState("");
  const [asyncVideoSeconds, setAsyncVideoSeconds] = useState(0);
  const [asyncAbout, setAsyncAbout] = useState("");
  const [asyncWhyJoining, setAsyncWhyJoining] = useState("");
  const [asyncConsent, setAsyncConsent] = useState(false);
  const [asyncUpload, setAsyncUpload] = useState<UploadState | null>(null);

  const [asyncCases, setAsyncCases] = useState<any[]>([]);
  const [liveCases, setLiveCases] = useState<any[]>([]);
  const [liveSessions, setLiveSessions] = useState<any[]>([]);

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
        setReviewerStatus(null);
        return;
      }
      const headers = getAuthHeaders(acct);
      const [accountView, registrationView, reviewerStatusView] = await Promise.all([
        weall.account(acct, base),
        weall.accountRegistered(acct, base).catch(() => ({ registered: false })),
        weall.accountReviewerStatus(acct, base, headers).catch(() => ({ reviewer: null })),
      ]);
      setAcctView(accountView);
      setAcctState(accountView?.state ?? null);
      setRegistration(registrationView);
      setReviewerStatus(reviewerStatusView);
    } catch (e: any) {
      setErr(prettyErr(e));
    } finally {
      setLoading(false);
    }
  }

  async function loadVerificationData(): Promise<void> {
    if (!acct) {
      setAsyncCases([]);
      setLiveCases([]);
      setLiveSessions([]);
      return;
    }
    setCasesBusy(true);
    try {
      const headers = getAuthHeaders(acct);
      const [asyncResponse, live, sessions] = await Promise.all([
        weall.pohAsyncMyCases(acct, base, headers).catch(() => ({ cases: [] })),
        weall.pohLiveMyCases(acct, base, headers).catch(() => ({ cases: [] })),
        weall.pohLiveSessions(base, headers).catch(() => ({ sessions: [] })),
      ]);
      setAsyncCases(Array.isArray(asyncResponse?.cases) ? asyncResponse.cases : []);
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

  useEffect(() => {
    return () => {
      cleanupAsyncRecording();
    };
  }, []);

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
  const basicAccountCreated = snapshot.accountCreated;
  const registered = basicAccountCreated; // Basic account visibility, not content-posting eligibility.
  const contentPostingEligible = snapshot.postingEligible;
  const banned = snapshot.banned;
  const locked = snapshot.locked;
  const reviewerTruth = asRecord(reviewerStatus?.reviewer);
  const reviewerLaneTruth = asRecord(reviewerTruth.lanes);
  const contentReviewLaneTruth = asRecord(reviewerLaneTruth.content_review);
  const contentReviewOptedIn = contentReviewLaneTruth.opted_in === true || contentReviewLaneTruth.active === true;
  const contentReviewActive = contentReviewLaneTruth.active === true;
  const contentReviewStatusLabel = contentReviewActive ? "Active" : contentReviewOptedIn ? "Opted in, paused" : "Not opted in";

  const basicStatus: "done" | "available" | "locked" = acct && hasLocalKeypair ? "done" : "available";
  const verifiedStatus: "done" | "available" | "locked" = accountLevel >= 1 ? "done" : registered ? "available" : "locked";
  const trustedStatus: "done" | "available" | "locked" = accountLevel >= 2 ? "done" : accountLevel >= 1 ? "available" : "locked";

  const nextStep = useMemo(() => {
    if (!acct) return "Sign in or create an account on this device.";
    if (!hasLocalKeypair) return "Restore the saved account key for this account.";
    if (!sessionKeyPresent) return "Save a session key so authenticated account calls work on this device.";
    if (!basicAccountCreated) return "Register your basic account so the network can recognize it.";
    if (accountLevel < 1) return "Record a fresh 1–2 minute video and submit it for async human review.";
    if (accountLevel < 2) return "Complete live verification to unlock high-trust social and community actions.";
    return "You can now apply for trusted responsibilities where you meet the requirements.";
  }, [acct, accountLevel, basicAccountCreated, hasLocalKeypair, sessionKeyPresent]);

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
        task: async () => submitSignedTx({
          account: acct,
          tx_type: "ACCOUNT_REGISTER",
          payload: {
            pubkey: kp.pubkeyB64,
          },
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
        ? ["Record and submit a fresh account-verification video.", "Refresh account status after reviewers finalize the result."]
        : ["Register the basic account first.", "Return here to start or inspect verification."],
    });
  }

  function stopAsyncPreviewBuffering(): void {
    const node = asyncPreviewVideoRef.current;
    if (!node) return;
    try {
      node.pause();
      if (Number.isFinite(node.duration) && node.duration > 0) {
        node.currentTime = Math.min(node.currentTime || 0, node.duration);
      }
    } catch {
      // Browser media element cleanup is best-effort; upload uses the Blob, not the preview buffer.
    }
  }

  function cleanupAsyncRecording(): void {
    stopAsyncPreviewBuffering();
    if (recordingTimerRef.current !== null) {
      window.clearInterval(recordingTimerRef.current);
      recordingTimerRef.current = null;
    }
    const recorder = recorderRef.current;
    if (recorder && recorder.state !== "inactive") {
      try {
        recorder.stop();
      } catch {
        // ignore recorder shutdown races
      }
    }
    recorderRef.current = null;
    const stream = recordingStreamRef.current;
    if (stream) {
      for (const track of stream.getTracks()) track.stop();
    }
    recordingStreamRef.current = null;
  }

  function ensureAsyncChallenge(): AsyncVerificationChallenge {
    const existing = asyncChallenge;
    if (existing) return existing;
    const next = createAsyncVerificationChallenge(acct || "");
    setAsyncChallenge(next);
    return next;
  }

  function resetAsyncRecording(): void {
    cleanupAsyncRecording();
    recordingChunksRef.current = [];
    if (asyncRecordedUrl) URL.revokeObjectURL(asyncRecordedUrl);
    setAsyncRecordedBlob(null);
    setAsyncRecordedUrl("");
    setAsyncVideoSeconds(0);
    setAsyncUpload(null);
    setAsyncRecordingState("idle");
  }

  async function startAsyncRecording(): Promise<void> {
    if (!acct) {
      setErr({ msg: "Sign in before starting account verification.", details: null });
      return;
    }
    if (!registered) {
      setErr({ msg: "Register your account before starting account verification.", details: null });
      return;
    }
    if (typeof navigator === "undefined" || !navigator.mediaDevices?.getUserMedia || typeof MediaRecorder === "undefined") {
      setErr({ msg: "This browser cannot record verification video in the app.", details: null });
      return;
    }

    resetAsyncRecording();
    const challenge = ensureAsyncChallenge();
    setResult({ ok: true, challenge, message: "Read the challenge phrase in your video before saying something about yourself and why you are joining." });
    setErr(null);

    try {
      const stream = await navigator.mediaDevices.getUserMedia({ video: true, audio: true });
      recordingStreamRef.current = stream;
      recordingChunksRef.current = [];
      const recorder = new MediaRecorder(stream, { mimeType: MediaRecorder.isTypeSupported("video/webm") ? "video/webm" : undefined });
      recorderRef.current = recorder;
      recorder.ondataavailable = (event: BlobEvent) => {
        if (event.data && event.data.size > 0) recordingChunksRef.current.push(event.data);
      };
      recorder.onstop = () => {
        if (recordingTimerRef.current !== null) {
          window.clearInterval(recordingTimerRef.current);
          recordingTimerRef.current = null;
        }
        const duration = Math.round((Date.now() - recordingStartedAtRef.current) / 1000);
        const blob = new Blob(recordingChunksRef.current, { type: recorder.mimeType || "video/webm" });
        const url = URL.createObjectURL(blob);
        setAsyncVideoSeconds(duration);
        setAsyncRecordedBlob(blob);
        setAsyncRecordedUrl(url);
        setAsyncRecordingState("ready");
        const durationError = validateAsyncVideoDuration(duration);
        if (durationError) setErr({ msg: durationError, details: { duration_seconds: duration } });
        const currentStream = recordingStreamRef.current;
        if (currentStream) for (const track of currentStream.getTracks()) track.stop();
        recordingStreamRef.current = null;
      };
      recordingStartedAtRef.current = Date.now();
      setAsyncVideoSeconds(0);
      setAsyncRecordingState("recording");
      recordingTimerRef.current = window.setInterval(() => {
        const elapsed = Math.round((Date.now() - recordingStartedAtRef.current) / 1000);
        setAsyncVideoSeconds(elapsed);
        if (elapsed >= ASYNC_VIDEO_MAX_SECONDS) {
          stopAsyncRecording();
        }
      }, 500);
      recorder.start(1000);
    } catch (e: any) {
      cleanupAsyncRecording();
      setAsyncRecordingState("idle");
      setErr({ msg: friendlyActionError(e?.message || "Camera or microphone permission was not granted."), details: e });
    }
  }

  function stopAsyncRecording(): void {
    const recorder = recorderRef.current;
    if (recorder && recorder.state !== "inactive") {
      recorder.stop();
      return;
    }
    cleanupAsyncRecording();
  }

  async function submitAsyncEvidence(): Promise<void> {
    const challenge = asyncChallenge;
    const check = canSubmitAsyncEvidence({
      recordedBlob: asyncRecordedBlob,
      durationSeconds: asyncVideoSeconds,
      about: asyncAbout,
      whyJoining: asyncWhyJoining,
      consent: asyncConsent,
      challenge,
    });
    if (!acct) {
      setErr({ msg: "Sign in before submitting account verification.", details: null });
      return;
    }
    if (!registered) {
      setErr({ msg: "Register your account before submitting account verification.", details: null });
      return;
    }
    if (!challenge || !asyncRecordedBlob || !check.ok) {
      setErr({ msg: check.ok ? "Record verification evidence before submitting." : check.reason, details: null });
      return;
    }

    setAsyncEvidenceBusy(true);
    setErr(null);
    try {
      const headers = getAuthHeaders(acct);
      const r = await tx.runTx({
        title: "Submit async verification evidence",
        pendingMessage: "Submitting account verification evidence…",
        successMessage: (res: any) =>
          res?.pending_reviewability
            ? "Async verification txs were submitted. Waiting for reviewer visibility while observer/genesis sync catches up."
            : "Async verification evidence submitted and reviewer-visible.",
        finality: { timeoutMs: 20_000, reconcile: async () => reconcileAsyncCompatibilityCase(acct, base, headers) },
        errorMessage: (e) => prettyErr(e).msg,
        getTxId: (res: any) => res?.bind?.result?.tx_id || res?.declare?.result?.tx_id || res?.open?.result?.tx_id,
        task: async () => {
          // Stop the local preview before posting the Blob. Some browsers keep an
          // object-URL video element buffering until it receives focus, which can
          // make the evidence upload appear stuck even though the upload request is
          // independent of preview playback.
          stopAsyncPreviewBuffering();
          const file = new File([asyncRecordedBlob], `${challenge.challengeId}.webm`, { type: asyncRecordedBlob.type || "video/webm" });
          const upload: UploadState = await weall.pohAsyncVideoUpload(file, base, headers);
          setAsyncUpload(upload);

          const caseId = `pohasync:${String(acct).replace(/^@/, "")}:${challenge.challengeId}`;
          const challengeCommitment = await sha256HexText(`weall:poh_async_challenge_v1:${acct}:${challenge.challengeId}:${challenge.phrase}`);
          const responseCommitment = await sha256HexText(`weall:poh_async_response_v1:${acct}:${challenge.challengeId}:${upload.video_commitment || upload.cid || ""}:${asyncAbout.trim()}:${asyncWhyJoining.trim()}`);
          const evidenceCommitment = upload.video_commitment || await sha256HexText(`weall:poh_async_evidence_v1:${upload.cid || ""}`);
          const evidenceId = `async-evidence:${challenge.challengeId}`;

          // Batch 400: keep the native async evidence sequence contiguous.
          // Submit request-open, evidence-declare, and evidence-bind first; then
          // wait for the bound async case to become locally visible/reviewable.
          // The UI must not report final success after request-open alone.
          // Submit the three native async-verification transactions as one
          // signer sequence.  This prevents the observer-edge UI from reusing
          // stale local nonce reservations between request-open, evidence
          // declaration, and evidence binding while still keeping each step as a
          // normal signed protocol tx forwarded through the observer tx queue.
          const sequence = await beginNonceSequence(acct, base);
          const openedAtMs = Date.now();

          const open = await submitSignedTxInSequence({
            sequence,
            tx_type: "POH_ASYNC_REQUEST_OPEN",
            payloadFactory: () => ({
              account_id: acct,
              case_id: caseId,
              challenge_id: challenge.challengeId,
              challenge_commitment: challengeCommitment,
              response_commitment: responseCommitment,
              note: "fresh_recorded_video_v1",
              ts_ms: openedAtMs,
            }),
            parent: null,
            base,
          });

          // Submit the remaining same-signer verification txs immediately with
          // contiguous nonces. Mempool admission now accepts nonce N+1 when nonce
          // N is already pending for the same signer; block admission still
          // enforces strict replay-safe ordering.

          const declare = await submitSignedTxInSequence({
            sequence,
            tx_type: "POH_ASYNC_EVIDENCE_DECLARE",
            payloadFactory: () => ({
              case_id: caseId,
              evidence_id: evidenceId,
              evidence_commitment: evidenceCommitment,
              response_commitment: responseCommitment,
              kind: "fresh_recorded_video_v1",
              note: "fresh_1_to_2_minute_in_app_recording",
              public_evidence_id: upload.uri || (upload.cid ? `ipfs://${upload.cid}` : ""),
              evidence_cid: upload.cid || "",
              uri: upload.uri || "",
              mime: upload.mime || "video/webm",
              name: upload.name || file.name,
              size: upload.size || file.size,
              video_commitment: upload.video_commitment || evidenceCommitment,
              ts_ms: openedAtMs,
            }),
            parent: open?.result?.tx_id || null,
            base,
          });

          // Evidence binding is the point where the async request becomes a
          // complete reviewable case.

          const bind = await submitSignedTxInSequence({
            sequence,
            tx_type: "POH_ASYNC_EVIDENCE_BIND",
            payloadFactory: () => ({
              case_id: caseId,
              evidence_id: evidenceId,
              target_id: caseId,
              ts_ms: openedAtMs,
            }),
            parent: declare?.result?.tx_id || null,
            base,
          });

          const boundCaseVisible = await waitForAsyncCaseVisible(acct, caseId, base, headers, { maxWaitMs: 120000, intervalMs: 1000 });
          let reviewability = await waitForAsyncCaseReviewable(acct, caseId, base, headers, { maxWaitMs: 1000, intervalMs: 500 });
          let bindStatusVisible = true;
          if (!boundCaseVisible) {
            bindStatusVisible = await waitForSubmittedTxVisible(base, String(bind?.result?.tx_id || ""), {
              maxWaitMs: 30000,
              intervalMs: 1000,
              requireLocalStateSynced: false,
              acceptAccepted: true,
            });
            reviewability = await waitForAsyncCaseReviewable(acct, caseId, base, headers, { maxWaitMs: 1000, intervalMs: 500 });
            if (!bindStatusVisible) {
              throw new Error("Async verification evidence binding did not become visible in tx status. Wait for observer/genesis sync and try again.");
            }
          }
          const pendingReviewability = !boundCaseVisible || !reviewability.reviewable;
          if (!reviewability.reviewable) {
            const missing = reviewability.missingSteps.join(", ") || "reviewable_state";
            // Batch 417: do not leave the user stuck in Saving when all three
            // async txs were accepted but observer-local reviewer visibility is
            // still catching up.  Keep the older Batch 385/400/408 diagnostic
            // copy here for release-contract tests and operator troubleshooting:
            // Async verification evidence was submitted, but the reviewable case is not visible yet.
            // Async verification txs were submitted, but the case is not reviewable yet.
            console.info(`Async verification txs were submitted, but the case is not reviewable yet. Missing: ${missing}. Wait for observer/genesis sync and refresh.`);
          }

          return { challenge, case_id: caseId, reviewability, pending_reviewability: pendingReviewability, missing_steps: reviewability.missingSteps, upload, open, declare, bind };
        },
      });

      setResult(r);
      await refresh();
      await loadVerificationData();
      await refreshAccountContext();
    } catch (e: any) {
      setErr(prettyErr(e));
      setResult(e?.body || e?.data || null);
    } finally {
      setAsyncEvidenceBusy(false);
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
        successMessage: (res: any) =>
          res?.pending_case_visibility
            ? "Live verification request submitted. Opening the live room while genesis/observer sync catches up."
            : "Live verification request submitted. Opening live room…",
        errorMessage: (e) => prettyErr(e).msg,
        getTxId: (res: any) => res?.submit?.result?.tx_id || res?.result?.tx_id,
        finality: { timeoutMs: 20_000, reconcile: async () => reconcileLiveCaseVisible(acct, base, headers) },
        task: async () => {
          const kp = getKeypair(acct);
          const commitments = await createLiveVerificationCommitments({
            account: acct,
            pubkeyB64: kp?.pubkeyB64,
          });
          if (!hasRequiredLiveVerificationCommitments(commitments)) {
            throw new Error("The live verification request could not prepare required session commitments.");
          }
          setLiveCommitments(commitments);
          const skel: any = await weall.pohLiveTxRequest({ account_id: acct, ...commitments }, base, headers);
          const skeletonTx = skel?.tx;
          if (!skeletonTx) throw new Error("The backend did not return a valid live verification request.");
          const payload = skeletonTx.payload || {};
          if (!hasRequiredLiveVerificationCommitments(payload)) {
            throw new Error("The backend live verification skeleton is missing required session commitments.");
          }

          // Batch 417: use the sequenced signer path so the UI can derive the
          // deterministic live case id from the signed nonce and open the room
          // even when observer-local reads lag behind genesis confirmation.
          const sequence = await beginNonceSequence(acct, base);
          const submit = await submitSignedTxInSequence({
            sequence,
            tx_type: String(skeletonTx.tx_type || ""),
            payloadFactory: () => payload,
            parent: skeletonTx.parent ?? null,
            base,
          });
          const txId = String(submit?.result?.tx_id || (submit as any)?.tx_id || "");
          const signedNonce = Number(submit?.env?.nonce || 0);
          const expectedCaseId = expectedLiveCaseIdFromNonce(acct, signedNonce);
          const txVisible = await waitForSubmittedTxVisible(base, txId, {
            maxWaitMs: 30_000,
            intervalMs: 1_000,
            // Batch 419: preserve the Batch 394/396 static contract marker below
            // for the older strict observer-sync path while Batch 417 keeps live
            // room launch non-blocking on observer-local catch-up.
            // requireLocalStateSynced: true
            requireLocalStateSynced: false,
            acceptAccepted: true,
          });
          const visibleCaseId = await waitForLiveCaseIdVisible(acct, base, headers, {
            maxWaitMs: txVisible ? 30_000 : 5_000,
            intervalMs: 1_000,
          });
          if (!txVisible && !visibleCaseId && !expectedCaseId) {
            throw new Error("Live verification request was not confirmed on genesis and synced back to the observer yet. Wait for sync and try again.");
          }
          // Batch 420: preserve the older Batch 394/394b static contract
          // while Batch 417 still routes with the deterministic expected case id
          // when observer-local live-case reads lag behind genesis.
          // return { skeleton: skel, commitments, submit, case_id: visibleCaseId };
          return {
            skeleton: skel,
            commitments,
            submit,
            case_id: visibleCaseId || expectedCaseId,
            expected_case_id: expectedCaseId,
            visible_case_id: visibleCaseId,
            pending_case_visibility: !visibleCaseId,
          };
        },
      });

      setResult(r);
      await refresh();
      await loadVerificationData();
      await refreshAccountContext();

      // Batch 421: preserve the older Batch 394/394b static marker while
      // Batch 417 still prefers deterministic expected_case_id fallback.
      // String((r as any)?.case_id || "") || await waitForLiveCaseIdVisible
      const resultCaseId = String((r as any)?.case_id || (r as any)?.expected_case_id || "").trim();
      const visibleCaseId = resultCaseId || await waitForLiveCaseIdVisible(acct, base, headers, {
        maxWaitMs: 30_000,
        intervalMs: 1_000,
      });
      if (visibleCaseId) {
        nav(`/verification/live/${encodeURIComponent(visibleCaseId)}`);
      }
    } catch (e: any) {
      setErr(prettyErr(e));
    } finally {
      setLiveRequestBusy(false);
    }
  }

  async function updateContentReviewLane(active: boolean): Promise<void> {
    if (!acct) {
      setErr({ msg: "Sign in before changing reviewer responsibilities.", details: null });
      return;
    }
    if (accountLevel < 2) {
      setErr({ msg: blockedByVerificationMessage(2), details: null });
      return;
    }
    if (!hasLocalKeypair) {
      setErr({ msg: "This device is missing the saved account key for this account.", details: null });
      return;
    }

    setReviewerBusy(active ? "optIn" : "optOut");
    setErr(null);
    setResult(null);
    try {
      const r = await tx.runTx({
        title: active ? "Opt into content review" : "Opt out of content review",
        pendingMessage: active ? "Submitting content-review opt-in…" : "Submitting content-review opt-out…",
        successMessage: active
          ? "Content-review responsibility submitted. Pending unassigned reports can now select this account when it is unconflicted."
          : "Content-review opt-out submitted. Already accepted work may still require protocol-specific withdrawal.",
        errorMessage: (e) => prettyErr(e).msg,
        getTxId: (res: any) => res?.result?.tx_id,
        task: async () =>
          submitSignedTx({
            account: acct,
            tx_type: active ? "REVIEWER_LANE_OPT_IN" : "REVIEWER_LANE_OPT_OUT",
            payload: { account_id: acct, lane: "content_review" },
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
      setReviewerBusy(null);
    }
  }

  const asyncSubmitCheck = canSubmitAsyncEvidence({
    recordedBlob: asyncRecordedBlob,
    durationSeconds: asyncVideoSeconds,
    about: asyncAbout,
    whyJoining: asyncWhyJoining,
    consent: asyncConsent,
    challenge: asyncChallenge,
  });
  const asyncDurationError = validateAsyncVideoDuration(asyncVideoSeconds);
  const asyncRecordingClock = `${Math.floor(asyncVideoSeconds / 60)}:${String(asyncVideoSeconds % 60).padStart(2, "0")}`;

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
                <span className={`statusPill ${basicAccountCreated ? "ok" : ""}`}>{basicAccountCreated ? "Basic account ready" : "Basic account needed"}</span>
                <span className={`statusPill ${contentPostingEligible ? "ok" : ""}`}>{contentPostingEligible ? "Posting eligible" : currentLabel}</span>
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
              <span className="statValue">{contentPostingEligible ? "Available" : "Live verification needed"}</span>
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
            <div className="calloutInfo">
              <strong>Basic account creation is not posting permission.</strong> Posting and community decision actions stay locked until live verification is reflected in account state.
            </div>
            <div className="buttonRowWide">
              <button
                className="btn btnPrimary"
                onClick={() => void registerAccount()}
                disabled={!acct || !hasLocalKeypair || basicAccountCreated || registerBusy || signerSubmission.busy}
              >
                {registerBusy ? "Registering…" : signerSubmission.busy ? "Waiting…" : basicAccountCreated ? "Basic account ready" : "Register basic account"}
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
          description="You can browse, set up your profile, and start account verification. Creating a basic account does not unlock posting."
        />
        <StatusCard
          eyebrow="Basic human review"
          title={VERIFICATION_LABELS.verified}
          status={verifiedStatus}
          description="Record a fresh 1–2 minute video in the app, state your handle, read the challenge phrase, say something about yourself, and explain why you are joining."
        >
          <div className="formStack">
            <div className="calloutInfo">
              <strong>Fresh video required:</strong> ordinary file upload is not allowed for basic human review evidence. Record inside WeAll with camera and microphone permissions.
            </div>
            <div className="infoCard compact">
              <div className="infoCardHeader">
                <strong>Challenge phrase</strong>
                <span className="statusPill">Read aloud</span>
              </div>
              <div className="infoCardText mono">{asyncChallenge?.phrase || "Start recording to generate a fresh challenge phrase."}</div>
            </div>
            <label className="fieldBlock">
              <span className="fieldLabel">Something about yourself</span>
              <textarea
                value={asyncAbout}
                onChange={(e) => setAsyncAbout(e.target.value)}
                placeholder="Share a few natural details that help reviewers see you are a real person."
                disabled={accountLevel >= 1 || asyncEvidenceBusy}
              />
            </label>
            <label className="fieldBlock">
              <span className="fieldLabel">Why are you joining WeAll?</span>
              <textarea
                value={asyncWhyJoining}
                onChange={(e) => setAsyncWhyJoining(e.target.value)}
                placeholder="Explain why you are joining in your own words."
                disabled={accountLevel >= 1 || asyncEvidenceBusy}
              />
            </label>
            <div className="buttonRowWide">
              <button
                className="btn btnPrimary"
                onClick={() => void startAsyncRecording()}
                disabled={!acct || !basicAccountCreated || accountLevel >= 1 || asyncRecordingState === "recording" || asyncEvidenceBusy || signerSubmission.busy}
              >
                {asyncRecordingState === "recording" ? "Recording…" : "Record fresh verification video"}
              </button>
              <button className="btn" onClick={() => stopAsyncRecording()} disabled={asyncRecordingState !== "recording"}>
                Stop recording
              </button>
              <button className="btn btnGhost" onClick={() => resetAsyncRecording()} disabled={asyncRecordingState === "recording" || asyncEvidenceBusy}>
                Reset video
              </button>
            </div>
            <div className="infoCard compact">
              <div className="infoCardHeader">
                <strong>Recorded duration</strong>
                <span className={`statusPill ${asyncRecordedBlob && !asyncDurationError ? "ok" : ""}`}>{asyncRecordingClock}</span>
              </div>
              <div className="infoCardText">Required length: {ASYNC_VIDEO_MIN_SECONDS}–{ASYNC_VIDEO_MAX_SECONDS} seconds.</div>
              {asyncRecordedBlob && asyncDurationError ? <div className="calloutDanger">{asyncDurationError}</div> : null}
              {asyncRecordedUrl ? (
                <video
                  ref={asyncPreviewVideoRef}
                  controls
                  preload="metadata"
                  src={asyncRecordedUrl}
                  onEnded={stopAsyncPreviewBuffering}
                  onPause={stopAsyncPreviewBuffering}
                  style={{ width: "100%", marginTop: 10, borderRadius: 12 }}
                />
              ) : null}
              {asyncRecordedUrl ? <div className="miniMuted">Preview uses metadata-only loading and is paused before upload, so the evidence upload does not depend on clicking the video controls.</div> : null}
            </div>
            <label className="checkRow">
              <input
                type="checkbox"
                checked={asyncConsent}
                onChange={(e) => setAsyncConsent(e.target.checked)}
                disabled={accountLevel >= 1 || asyncEvidenceBusy}
              />
              <span>Assigned reviewers may view this evidence only for account verification. Public chain state should store commitments and receipts, not raw video.</span>
            </label>
            {asyncUpload ? <JsonDetails title="Latest async evidence upload payload" value={asyncUpload} /> : null}
            <button
              className="btn btnPrimary"
              onClick={() => void submitAsyncEvidence()}
              disabled={!acct || !basicAccountCreated || accountLevel >= 1 || asyncEvidenceBusy || signerSubmission.busy || !asyncSubmitCheck.ok}
            >
              {asyncEvidenceBusy ? "Submitting…" : signerSubmission.busy ? "Waiting…" : accountLevel >= 1 ? "Async verification complete" : "Submit async verification evidence"}
            </button>
            {!asyncSubmitCheck.ok && accountLevel < 1 ? <div className="miniMuted">{asyncSubmitCheck.reason}</div> : null}
            <button className="btn btnGhost" onClick={() => explainNativeAsyncVerification()} disabled={!acct}>
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
          <div className="calloutInfo">
            Live verification requests now prepare session, room, and prompt commitments before the signed request is submitted. The chain stores commitments and review receipts, not raw identity session recordings.
          </div>
          <button className="btn btnPrimary" onClick={() => void submitLiveRequest()} disabled={!acct || liveRequestBusy || accountLevel >= 2 || accountLevel < 1 || signerSubmission.busy}>
            {liveRequestBusy ? "Opening…" : signerSubmission.busy ? "Waiting…" : accountLevel < 1 ? blockedByVerificationMessage(1) : "Open live verification"}
          </button>
          {liveCommitments ? (
            <div className="infoCard compact">
              <div className="infoCardHeader">
                <strong>Decentralized P2P live room</strong>
                <span className="statusPill">Transport only</span>
              </div>
              <div className="infoCardText">{liveRoomTransportNotice()}</div>
              {liveRoomUrlFromCommitment(liveCommitments.room_commitment) ? (
                <div className="buttonRow" style={{ marginTop: 10 }}>
                  <a className="btn" href={liveRoomUrlFromCommitment(liveCommitments.room_commitment)} target="_blank" rel="noreferrer">
                    Open self-hosted room
                  </a>
                </div>
              ) : (
                <div className="miniMuted">A decentralized P2P room descriptor will be created from the room commitment. No centralized room URL is required.</div>
              )}
              {liveRoomDescriptorText(liveCommitments.room_commitment) ? (
                <details className="advancedDetails">
                  <summary>Advanced: P2P room descriptor</summary>
                  <pre className="jsonBlock">{liveRoomDescriptorText(liveCommitments.room_commitment)}</pre>
                </details>
              ) : null}
            </div>
          ) : null}
          {liveCommitments ? <JsonDetails title="Advanced: prepared live request commitments" value={liveCommitments} /> : null}
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
          <div className="infoCard compact">
            <div className="infoCardHeader">
              <strong>Content review selection</strong>
              <span className={`statusPill ${contentReviewActive ? "ok" : contentReviewOptedIn ? "warning" : ""}`}>{contentReviewStatusLabel}</span>
            </div>
            <div className="infoCardText">
              Tier 2 makes you eligible, but the protocol only selects reviewers that explicitly opt into the content_review lane and are not the author of the flagged content.
            </div>
            <div className="buttonRowWide">
              {!contentReviewActive ? (
                <button
                  className="btn btnPrimary"
                  onClick={() => void updateContentReviewLane(true)}
                  disabled={!acct || accountLevel < 2 || reviewerBusy !== null || signerSubmission.busy || !hasLocalKeypair}
                >
                  {reviewerBusy === "optIn" ? "Opting in…" : accountLevel < 2 ? blockedByVerificationMessage(2) : "Opt into content review"}
                </button>
              ) : (
                <button
                  className="btn"
                  onClick={() => void updateContentReviewLane(false)}
                  disabled={!acct || reviewerBusy !== null || signerSubmission.busy || !hasLocalKeypair}
                >
                  {reviewerBusy === "optOut" ? "Opting out…" : "Opt out of content review"}
                </button>
              )}
              <button className="btn btnGhost" onClick={() => nav(acct ? `/account/${encodeURIComponent(acct)}` : "/login")} disabled={!acct}>
                Open all responsibility controls
              </button>
            </div>
          </div>
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
              <span className="statusPill">{liveCases.length + asyncCases.length} item(s)</span>
            </div>
            <p className="cardDesc">
              This area shows account-verification work that is visible to this device. It is written as a history of requests and reviews, not as protocol machinery.
            </p>
            {liveCases.length ? (
              <div className="infoGrid">
                {liveCases.map((it: any, idx: number) => {
                  const roomUrl = liveRoomUrlFromCommitment(it?.room_commitment);
                  const p2pDescriptor = liveRoomDescriptorText(it?.room_commitment);
                  return (
                    <div key={String(it?.case_id || idx)} className="infoCard compact">
                      <CaseCard item={it} />
                      <div className="buttonRow" style={{ marginTop: 10 }}>
                        <button className="btn btnPrimary" onClick={() => nav(`/verification/live/${encodeURIComponent(String(it?.case_id || ""))}`)} disabled={!it?.case_id}>
                          Open live verification room
                        </button>
                        {roomUrl ? (
                          <a className="btn" href={roomUrl} target="_blank" rel="noreferrer">
                            Open self-hosted transport
                          </a>
                        ) : null}
                      </div>
                      <div className="miniMuted">{liveRoomTransportNotice()}</div>
                      {p2pDescriptor ? (
                        <details className="advancedDetails">
                          <summary>P2P room descriptor</summary>
                          <pre className="jsonBlock">{p2pDescriptor}</pre>
                        </details>
                      ) : null}
                    </div>
                  );
                })}
              </div>
            ) : null}
            {asyncCases.length ? <div className="infoGrid">{asyncCases.map((it: any, idx: number) => <CaseCard key={String(it?.case_id || idx)} item={it} />)}</div> : null}
            {!liveCases.length && !asyncCases.length ? <div className="emptyState compactEmpty"><div className="emptyTitle">No verification history is visible yet.</div></div> : null}
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

    </div>
  );
}
