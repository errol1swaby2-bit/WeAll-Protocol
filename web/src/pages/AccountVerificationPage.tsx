import React, { useEffect, useMemo, useRef, useState } from "react";

import { getApiBaseUrl, weall } from "../api/weall";
import ErrorBanner from "../components/ErrorBanner";
import PohSubmissionStatusNotice from "../components/PohSubmissionStatusNotice";
import VerificationHistoryPanel from "../components/VerificationHistoryPanel";
import TrustedResponsibilitiesPanel from "../components/TrustedResponsibilitiesPanel";
import PohStepProgress from "../components/PohStepProgress";
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
import {
  ensureEvidenceKemKeypair,
  loadEvidenceKemKeypair,
  encryptEvidenceBlob,
  unwrapEvidenceKeyForRecipient,
  wrapEvidenceKeyForRecipient,
} from "../auth/evidenceCrypto";
import { useAccount } from "../context/AccountContext";
import { useTxQueue } from "../hooks/useTxQueue";
import { useSignerSubmissionBusy } from "../hooks/useSignerSubmissionBusy";
import { resolveOnboardingSnapshot, summarizeNextRequirements } from "../lib/onboarding";
import { currentHashPath, nav } from "../lib/router";
import {
  allowedAsyncPohStep,
  allowedLivePohStep,
  asyncPohRoute,
  livePohRoute,
  parseAsyncPohRoute,
  parseLivePohJourneyRoute,
  type AsyncPohGuideStep,
  type LivePohGuideStep,
} from "../lib/pohGuidedRoutes";
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
import {
  clearReconciledPohJournal,
  normalizePohJournalBase,
  readPohSubmissionJournal,
  savePohSubmissionJournal,
  type PohJournalKind,
  type PohJournalPhase,
  type PohJournalRead,
} from "../lib/pohSubmissionJournal";
import { liveRoomDescriptorText, liveRoomTransportNotice, liveRoomUrlFromCommitment } from "../lib/liveRoom";
import {
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
  provider_id?: string;
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

function missingAsyncReviewerEnvelopes(item: any): string[] {
  const jurors = Array.isArray(item?.assigned_jurors) ? item.assigned_jurors.map(String).filter(Boolean) : [];
  if (!jurors.length) return [];
  const currentRound = Number(item?.followup_round || 0);
  const encrypted = Object.entries(asRecord(item?.evidence_commitments))
    .filter(([, value]) => {
      const record = asRecord(value);
      return String(record.storage_mode || "").toLowerCase() === "encrypted_blob" && Number(record.followup_round || 0) === currentRound;
    })
    .map(([id]) => id);
  const binds = Object.values(asRecord(item?.evidence_binds)).map(asRecord);
  return jurors.filter((juror: string) => encrypted.some((id) => !binds.some((bind) =>
    String(bind.evidence_id || "") === id &&
    Array.isArray(bind.key_envelope_principals) && bind.key_envelope_principals.includes(juror),
  )));
}

function CaseCard({ item, onFinishReviewerAccess, working = false }: { item: any; onFinishReviewerAccess?: (caseId: string) => void; working?: boolean }): JSX.Element {
  const created = item?.created_at_ms ? new Date(item.created_at_ms).toLocaleString() : "—";
  const tone = statusTone(String(item?.status || ""));
  const reviewability = asyncCaseReviewability(item);
  const missingReviewerAccess = missingAsyncReviewerEnvelopes(item);
  const reason = String(item?.reviewer_queue_reason || "").trim();
  const humanReason = reason === "finalized" || ["approved", "rejected", "finalized"].includes(String(item?.status || "").toLowerCase())
    ? "This verification case has been finalized on-chain."
    : reason === "case_opened_not_reviewable"
      ? "Case opened. Evidence still needs to be declared and bound before reviewers can see it."
      : reason === "case_reviewable_not_assigned"
        ? "Evidence is reviewable. Waiting for juror assignment."
        : reason === "assigned"
          ? (missingReviewerAccess.length ? "Reviewer assigned. Encrypted video access must be finished before acceptance." : "Reviewer assigned and encrypted evidence access prepared.")
          : "Waiting for the next verification step.";
  return (
    <div className="infoCard compact">
      <div className="infoCardHeader">
        <strong>{String(item?.case_id || "Review case")}</strong>
        <span className={`statusPill ${(tone === "done" || reviewability.reviewable) && !missingReviewerAccess.length ? "ok" : ""}`}>{missingReviewerAccess.length ? "Reviewer access pending" : reviewability.reviewable ? "Reviewable" : String(item?.status || "unknown")}</span>
      </div>
      <div className="infoCardText">Opened {created}</div>
      <div className="infoCardText">{humanReason}</div>
      {reviewability.missingSteps.length ? <div className="miniMuted">Missing: {reviewability.missingSteps.join(", ")}</div> : null}
      {missingReviewerAccess.length && onFinishReviewerAccess ? (
        <div className="formStack">
          <div className="miniMuted">Evidence access missing for: {missingReviewerAccess.join(", ")}</div>
          <button className="btn" disabled={working} onClick={() => onFinishReviewerAccess(String(item.case_id || ""))}>
            {working ? "Binding reviewer evidence…" : "Complete reviewer evidence access"}
          </button>
        </div>
      ) : null}
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

async function waitForAsyncAssignedCase(account: string, caseId: string, base: string, headers?: HeadersInit, maxWaitMs = 120000): Promise<any> {
  const deadline = Date.now() + Math.max(1000, maxWaitMs);
  while (Date.now() < deadline) {
    try {
      const mine = await weall.pohAsyncMyCases(account, base, headers);
      const cases = Array.isArray(mine?.cases) ? mine.cases : [];
      const found = cases.find((item: any) => String(item?.case_id || "").trim() === String(caseId || "").trim());
      const assigned = Array.isArray(found?.assigned_jurors) ? found.assigned_jurors.filter(Boolean) : [];
      if (found && assigned.length > 0) return found;
    } catch {
      // Keep polling while the producing node commits assignment.
    }
    await new Promise((resolve) => window.setTimeout(resolve, 750));
  }
  throw new Error("Async verification reviewer assignment did not become visible before timeout.");
}

export default function AccountVerificationPage(): JSX.Element {
  const base = useMemo(() => getApiBaseUrl(), []);
  const [guidedRoutePath, setGuidedRoutePath] = useState(() => currentHashPath());
  const session = getSession();
  const acct = session ? normalizeAccount(session.account) : null;
  const kp = acct ? getKeypair(acct) : null;
  const { refresh: refreshAccountContext } = useAccount();
  const tx = useTxQueue();
  const signerSubmission = useSignerSubmissionBusy(acct);

  const recorderRef = useRef<MediaRecorder | null>(null);
  const recordingPreviewRef = useRef<HTMLVideoElement | null>(null);
  const asyncStepHeadingRef = useRef<HTMLHeadingElement | null>(null);
  const liveStepHeadingRef = useRef<HTMLHeadingElement | null>(null);
  const asyncFocusInitializedRef = useRef(false);
  const liveFocusInitializedRef = useRef(false);
  const recordingChunksRef = useRef<Blob[]>([]);
  const recordingStreamRef = useRef<MediaStream | null>(null);
  const recordingStartedAtRef = useRef<number>(0);
  const recordingTimerRef = useRef<number | null>(null);

  const [acctView, setAcctView] = useState<any | null>(null);
  const [registration, setRegistration] = useState<any | null>(null);
  const [reviewerStatus, setReviewerStatus] = useState<any | null>(null);
  const [acctState, setAcctState] = useState<any | null>(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<ErrState>(null);
  const [result, setResult] = useState<any | null>(null);

  const [sessionBusy, setSessionBusy] = useState(false);
  const [liveRequestBusy, setLiveRequestBusy] = useState(false);
  const [liveCommitments, setLiveCommitments] = useState<any | null>(null);
  const [liveGuideStep, setLiveGuideStep] = useState<LivePohGuideStep>("explain");
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
  // F2: UI progression is local guidance only, never a PoH tier or chain outcome.
  // Keep recorded evidence in component memory; do not persist video or secrets.
  const [asyncGuideStep, setAsyncGuideStep] = useState<AsyncPohGuideStep>("explain");

  const [asyncCases, setAsyncCases] = useState<any[]>([]);
  const [liveCases, setLiveCases] = useState<any[]>([]);
  const [liveSessions, setLiveSessions] = useState<any[]>([]);
  // Preserve last-seen cases, but never treat a failed history lookup as an empty history.
  const [verificationHistoryReady, setVerificationHistoryReady] = useState({ async: false, live: false });
  const [asyncJournal, setAsyncJournal] = useState<PohJournalRead>(() => acct ? readPohSubmissionJournal(acct, "async") : { status: "unavailable" });
  const [liveJournal, setLiveJournal] = useState<PohJournalRead>(() => acct ? readPohSubmissionJournal(acct, "live") : { status: "unavailable" });
  const asyncJournalBlocked = asyncJournal.status !== "none";
  const isAsyncJourneyRoute = parseAsyncPohRoute(guidedRoutePath) !== null;
  const isLiveJourneyRoute = parseLivePohJourneyRoute(guidedRoutePath) !== null;
  const isVerificationLanding = !isAsyncJourneyRoute && !isLiveJourneyRoute;

  function goAsyncStep(stage: AsyncPohGuideStep): void {
    setAsyncGuideStep(stage);
    nav(asyncPohRoute(stage));
  }

  function goLiveStep(stage: LivePohGuideStep): void {
    setLiveGuideStep(stage);
    nav(livePohRoute(stage));
  }
  const liveJournalBlocked = liveJournal.status !== "none";

  function rereadPohJournals(): void {
    if (!acct) {
      setAsyncJournal({ status: "unavailable" });
      setLiveJournal({ status: "unavailable" });
      return;
    }
    setAsyncJournal(readPohSubmissionJournal(acct, "async"));
    setLiveJournal(readPohSubmissionJournal(acct, "live"));
  }

  function recordPohStage(kind: PohJournalKind, phase: PohJournalPhase, caseId: string, txId = ""): void {
    if (!acct) throw new Error("poh_journal_missing_account");
    savePohSubmissionJournal({ account: acct, nodeBase: base, kind, phase, caseId, txId });
    rereadPohJournals();
  }

  function requireNoUnresolvedPoh(kind: PohJournalKind): void {
    if (!acct || readPohSubmissionJournal(acct, kind).status !== "none") {
      throw new Error(
        "An earlier verification request may still be pending on this account. Reconcile its original case on the original node before creating another; do not retry automatically.",
      );
    }
  }

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
      setVerificationHistoryReady({ async: false, live: false });
      return;
    }
    setCasesBusy(true);
    setVerificationHistoryReady({ async: false, live: false });
    try {
      const headers = getAuthHeaders(acct);
      const [asyncResponse, live, sessions] = await Promise.allSettled([
        weall.pohAsyncMyCases(acct, base, headers),
        weall.pohLiveMyCases(acct, base, headers),
        weall.pohLiveSessions(base, headers),
      ]);
      const asyncReady = asyncResponse.status === "fulfilled" && asyncResponse.value?.ok === true && Array.isArray(asyncResponse.value?.cases);
      const liveReady = live.status === "fulfilled" && live.value?.ok === true && Array.isArray(live.value?.cases);
      // Stale data may remain visible for inspection, but never re-enable new
      // signed actions until the selected node confirms the actual history.
      if (asyncReady && asyncResponse.status === "fulfilled") {
        setAsyncCases(asyncResponse.value.cases);
        const pending = readPohSubmissionJournal(acct, "async");
        const match = pending.status === "pending"
          ? asyncResponse.value.cases.find((item: any) => String(item?.case_id || "") === pending.record.caseId)
          : null;
        if (match && pending.status === "pending") {
          // Only canonical case visibility on the original node resolves the
          // uncertainty that a request was never admitted. This is not tier approval.
          clearReconciledPohJournal(acct, "async", base, String(match.case_id));
        }
      }
      if (liveReady && live.status === "fulfilled") {
        setLiveCases(live.value.cases);
        const pending = readPohSubmissionJournal(acct, "live");
        const match = pending.status === "pending" && pending.record.caseId
          ? live.value.cases.find((item: any) => String(item?.case_id || "") === pending.record.caseId)
          : null;
        if (match && pending.status === "pending") {
          clearReconciledPohJournal(acct, "live", base, String(match.case_id));
        }
      }
      rereadPohJournals();
      if (sessions.status === "fulfilled" && Array.isArray(sessions.value?.sessions)) {
        setLiveSessions(sessions.value.sessions);
      }
      setVerificationHistoryReady({ async: asyncReady, live: liveReady });
    } catch (e: any) {
      setVerificationHistoryReady({ async: false, live: false });
      setErr(prettyErr(e));
    } finally {
      setCasesBusy(false);
    }
  }

  async function refreshVerificationSurface(): Promise<void> {
    await refreshMutationSlices(refresh, refreshAccountContext, loadVerificationData);
  }

  useEffect(() => {
    const onGuidedRouteChange = () => setGuidedRoutePath(currentHashPath());
    window.addEventListener("hashchange", onGuidedRouteChange);
    return () => window.removeEventListener("hashchange", onGuidedRouteChange);
  }, []);

  useEffect(() => {
    rereadPohJournals();
    const asyncPending = acct ? readPohSubmissionJournal(acct, "async") : { status: "none" as const };
    const livePending = acct ? readPohSubmissionJournal(acct, "live") : { status: "none" as const };
    if (asyncPending.status !== "none") goAsyncStep("track");
    if (livePending.status !== "none") goLiveStep("track");
    void refresh();
    void loadVerificationData();
    // Storage updates from another tab can block a duplicate request before
    // the signer is used. This is defense in depth, not a cross-tab mutex.
    const onStorage = (event: StorageEvent) => {
      if (event.key === null || event.key.startsWith("weall.poh_submission_pending_v1::")) rereadPohJournals();
    };
    window.addEventListener("storage", onStorage);
    return () => window.removeEventListener("storage", onStorage);
  }, [acct, base]);

  useEffect(() => {
    return () => {
      cleanupAsyncRecording();
    };
  }, []);

  // Camera preview is rendered only after React enters "recording".
  // Attach the captured local stream to the mounted video element.
  useEffect(() => {
    const preview = recordingPreviewRef.current;
    const stream = recordingStreamRef.current;
    if (asyncRecordingState !== "recording" || !preview || !stream) return;
    preview.srcObject = stream;
    void preview.play().catch(() => {
      // Browser autoplay policy may require user interaction; capture continues.
    });
    return () => {
      if (preview.srcObject === stream) preview.srcObject = null;
    };
  }, [asyncRecordingState]);

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
  // Moving between guided stages unmounts the previous button. Restore
  // keyboard/screen-reader context on the new heading, without moving focus
  // away from the initial page heading during the first render.
  useEffect(() => {
    if (!asyncFocusInitializedRef.current) {
      asyncFocusInitializedRef.current = true;
      return;
    }
    asyncStepHeadingRef.current?.focus();
  }, [asyncGuideStep]);

  useEffect(() => {
    if (!liveFocusInitializedRef.current) {
      liveFocusInitializedRef.current = true;
      return;
    }
    liveStepHeadingRef.current?.focus();
  }, [liveGuideStep]);

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

  function cleanupAsyncRecording(): void {
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
    setAsyncConsent(false);
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
    if (!verificationHistoryReady.async) {
      setErr({ msg: "Cannot verify earlier PoH cases on the selected node. Refresh case history before signing a new evidence case.", details: null });
      return;
    }
    if (!challenge || !asyncRecordedBlob || !check.ok) {
      setErr({ msg: check.ok ? "Record verification evidence before submitting." : check.reason, details: null });
      return;
    }

    setAsyncEvidenceBusy(true);
    setErr(null);
    // HTTP evidence storage and chain declaration are distinct operations.
    // This marker survives errors after a successful encrypted upload.
    let acceptedUpload: UploadState | null = null;
    let caseTransactionsSubmitted = false;
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
        getTxId: (res: any) => res?.access_bind?.result?.tx_id || res?.bind?.result?.tx_id || res?.declare?.result?.tx_id || res?.open?.result?.tx_id,
        task: async () => {
          requireNoUnresolvedPoh("async");
          const caseId = `pohasync:${String(acct).replace(/^@/, "")}:${challenge.challengeId}`;
          const evidenceContext = `weall:poh-evidence:v1:${caseId}:${acct}`;
          const subjectKem = ensureEvidenceKemKeypair(acct);
          const accountView = await weall.account(acct, base);
          const registeredKem = String(asRecord(accountView?.state).evidence_encryption?.public_key || "").trim();
          if (!registeredKem || registeredKem !== subjectKem.publicKeyB64) {
            throw new Error("Your account has no matching registered ML-KEM evidence key. Complete account setup or restore the original recovery file before uploading identity evidence.");
          }
          const encryptedEvidence = await encryptEvidenceBlob({
            blob: asyncRecordedBlob,
            filename: `${challenge.challengeId}.webm`,
            context: evidenceContext,
          });
          const uploadHeaders = new Headers(headers || {});
          uploadHeaders.set("X-WeAll-Evidence-Encryption", "aes-256-gcm");
          uploadHeaders.set("X-WeAll-Evidence-Context-Commitment", encryptedEvidence.encryptionContextCommitment);
          uploadHeaders.set("X-WeAll-Evidence-Ciphertext-Commitment", encryptedEvidence.ciphertextCommitment);
          // Write before the first external side effect. A crash, lost HTTP
          // reply or tab reload must never license a second evidence upload.
          recordPohStage("async", "upload_started", caseId);
          goAsyncStep("track");
          const upload: UploadState = await weall.pohAsyncVideoUpload(encryptedEvidence.file, base, uploadHeaders);
          if (!String(upload?.cid || "").trim()) {
            throw new Error("The media endpoint returned no ciphertext CID; the signed case was not submitted.");
          }
          acceptedUpload = upload;
          recordPohStage("async", "encrypted_uploaded", caseId);
          setAsyncUpload(upload);
          // Storage acceptance is a separate phase from canonical case review.
          // The tracking screen never implies that signed transactions finalized.
          goAsyncStep("track");

          const challengeCommitment = await sha256HexText(`weall:poh_async_challenge_v1:${acct}:${challenge.challengeId}:${challenge.phrase}`);
          const responseCommitment = await sha256HexText(`weall:poh_async_response_v1:${acct}:${challenge.challengeId}:${encryptedEvidence.ciphertextCommitment}:${asyncAbout.trim()}:${asyncWhyJoining.trim()}`);
          const evidenceCommitment = encryptedEvidence.ciphertextCommitment;
          const evidenceId = `async-evidence:${challenge.challengeId}`;

          // Batch 400: keep the native async evidence sequence contiguous.
          // Submit request-open, evidence-declare, and evidence-bind first; then
          // wait for deterministic reviewer assignment and add reviewer envelopes.
          // Submit the remaining same-signer verification txs immediately with
          // the reserved nonce cursor. Mempool admission now accepts nonce N+1 when nonce
          // N is already pending for the same signer. Legacy evidence_cid and
          // video_commitment plaintext fields are intentionally not submitted.
          const sequence = await beginNonceSequence(acct, base);
          recordPohStage("async", "signed_started", caseId);
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
              note: "encrypted_fresh_recorded_video_v1",
              ts_ms: openedAtMs,
            }),
            parent: null,
            base,
          });
          recordPohStage("async", "signed_returned", caseId, String(open?.result?.tx_id || ""));
          const declare = await submitSignedTxInSequence({
            sequence,
            tx_type: "POH_ASYNC_EVIDENCE_DECLARE",
            payloadFactory: () => ({
              case_id: caseId,
              evidence_id: evidenceId,
              evidence_commitment: evidenceCommitment,
              response_commitment: responseCommitment,
              encrypted: true,
              encryption_algorithm: "aes-256-gcm",
              ciphertext_cid: upload.cid || "",
              ciphertext_commitment: encryptedEvidence.ciphertextCommitment,
              encryption_context_commitment: encryptedEvidence.encryptionContextCommitment,
              provider_ids: [String(upload.provider_id || "").trim()].filter(Boolean),
              ciphertext_mime: "application/octet-stream",
              ciphertext_size: upload.size || encryptedEvidence.file.size,
              kind: "encrypted_fresh_recorded_video_v1",
              note: "client_side_encrypted_recording",
              ts_ms: openedAtMs,
            }),
            parent: open?.result?.tx_id || null,
            base,
          });

          const subjectEnvelope = await wrapEvidenceKeyForRecipient({
            contentKey: encryptedEvidence.contentKey,
            recipientPublicKeyB64: subjectKem.publicKeyB64,
            context: `${evidenceContext}:${acct}`,
          });
          const bind = await submitSignedTxInSequence({
            sequence,
            tx_type: "POH_ASYNC_EVIDENCE_BIND",
            payloadFactory: () => ({
              case_id: caseId,
              evidence_id: evidenceId,
              target_id: caseId,
              key_envelope_commitments: { [acct]: subjectEnvelope },
              evidence_root_commitment: encryptedEvidence.ciphertextCommitment,
              followup_round: 0,
              ts_ms: Date.now(),
            }),
            parent: declare?.result?.tx_id || null,
            base,
          });

          const assignedCase = await waitForAsyncAssignedCase(acct, caseId, base, headers);
          const assignedJurors = Array.isArray(assignedCase?.assigned_jurors)
            ? assignedCase.assigned_jurors
            : [];
          const reviewerIds: string[] = Array.from(
            new Set<string>(
              assignedJurors
                .map((value: unknown): string => String(value ?? "").trim())
                .filter((value: string): boolean => value.length > 0),
            ),
          );
          const keyEnvelopes: Record<string, any> = { [acct]: subjectEnvelope };
          for (const recipient of reviewerIds) {
            const view = await weall.account(recipient, base);
            const state = view?.state && typeof view.state === "object" ? view.state : view;
            const publicKeyB64 = String(state?.evidence_encryption?.public_key || state?.evidence_encryption?.pubkey || "").trim();
            if (!publicKeyB64) throw new Error(`Assigned reviewer ${recipient} has no registered ML-KEM evidence key.`);
            keyEnvelopes[recipient] = await wrapEvidenceKeyForRecipient({
              contentKey: encryptedEvidence.contentKey,
              recipientPublicKeyB64: publicKeyB64,
              context: `${evidenceContext}:${recipient}`,
            });
          }

          let accessBind: any = null;
          if (reviewerIds.length > 0) {
            const accessSequence = await beginNonceSequence(acct, base);
            accessBind = await submitSignedTxInSequence({
              sequence: accessSequence,
              tx_type: "POH_ASYNC_EVIDENCE_BIND",
              payloadFactory: () => ({
                case_id: caseId,
                evidence_id: evidenceId,
                target_id: caseId,
                key_envelope_commitments: keyEnvelopes,
                evidence_root_commitment: encryptedEvidence.ciphertextCommitment,
                followup_round: Number(assignedCase.followup_round || 0),
                ts_ms: Date.now(),
              }),
              parent: bind?.result?.tx_id || null,
              base,
            });
          }

          // A successful local evidence bind does not mean the assigned reviewer
          // has access. Wait for the *second* bind to be applied and reconciled.
          if (accessBind) {
            const accessTxId = String(accessBind?.result?.tx_id || "").trim();
            if (!accessTxId || !(await waitForSubmittedTxVisible(base, accessTxId, {
              maxWaitMs: 90_000,
              intervalMs: 1000,
              requireLocalStateSynced: true,
            }))) {
              throw new Error("Reviewer evidence binding is submitted but not yet confirmed and synchronized. Open verification history to complete access; do not upload the video again.");
            }
          }
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

          caseTransactionsSubmitted = true;
          return { challenge, case_id: caseId, reviewability, pending_reviewability: pendingReviewability, missing_steps: reviewability.missingSteps, upload, open, declare, bind, access_bind: accessBind };
        },
      });

      setResult(r);
      await refresh();
      await loadVerificationData();
      await refreshAccountContext();
    } catch (e: any) {
      const original = prettyErr(e);
      if (acct && readPohSubmissionJournal(acct, "async").status !== "none") {
        // Even when the request failed before a visible acknowledgement,
        // an earlier side effect may have been admitted. Track, do not retry.
        goAsyncStep("track");
        rereadPohJournals();
      }
      if (acceptedUpload) {
        goAsyncStep("track");
        setErr({
          msg: caseTransactionsSubmitted
            ? "Verification transactions were submitted, but refreshing their status failed. Check verification history before retrying."
            : "Encrypted video upload succeeded, but a later signed verification or reviewer-access step failed. Check transaction status before retrying; do not re-upload the recording.",
          details: { stage: caseTransactionsSubmitted ? "post_submission_refresh" : "post_upload_chain_steps", original_error: original.msg },
        });
      } else {
        setErr(original);
      }
      setResult(e?.body || e?.data || null);
    } finally {
      setAsyncEvidenceBusy(false);
    }
  }

  async function finishAsyncReviewerAccess(caseId: string): Promise<void> {
    if (!acct || !caseId) return;
    setAsyncEvidenceBusy(true);
    setErr(null);
    try {
      const headers = getAuthHeaders(acct);
      const detail = await weall.pohAsyncCase(caseId, base, headers);
      const item = asRecord(detail?.case ?? detail);
      const reviewerIds = missingAsyncReviewerEnvelopes(item);
      if (!reviewerIds.length) {
        await loadVerificationData();
        return;
      }
      const applicantKeys = loadEvidenceKemKeypair(acct);
      if (!applicantKeys?.secretKeyB64) {
        throw new Error("The original applicant evidence-encryption key is not in this browser. Restore the original recovery file before finishing reviewer access; do not record a new video.");
      }
      const context = `weall:poh-evidence:v1:${caseId}:${acct}`;
      const reviewers: Record<string, string> = {};
      for (const reviewer of reviewerIds) {
        const accountView = await weall.account(reviewer, base);
        const publicKey = String(asRecord(accountView?.state).evidence_encryption?.public_key || "").trim();
        if (!publicKey) throw new Error(`Assigned reviewer ${reviewer} must register an ML-KEM evidence key before review can continue.`);
        reviewers[reviewer] = publicKey;
      }
      const sequence = await beginNonceSequence(acct, base);
      const txIds: string[] = [];
      const currentRound = Number(item.followup_round || 0);
      const binds = Object.values(asRecord(item.evidence_binds)).map(asRecord);
      for (const [evidenceId, evidenceUnknown] of Object.entries(asRecord(item.evidence_commitments))) {
        const evidence = asRecord(evidenceUnknown);
        if (String(evidence.storage_mode || "").toLowerCase() !== "encrypted_blob" || Number(evidence.followup_round || 0) !== currentRound) continue;
        const bind = binds.find((row) => String(row.evidence_id || "") === evidenceId);
        const envelopes = asRecord(bind?.key_envelope_commitments);
        const subjectEnvelope = asRecord(envelopes[acct]);
        if (!Object.keys(subjectEnvelope).length) throw new Error("Original applicant evidence envelope is unavailable. Sign in with the original recovery key before continuing.");
        const contentKey = await unwrapEvidenceKeyForRecipient({
          envelope: subjectEnvelope,
          recipientSecretKeyB64: applicantKeys.secretKeyB64,
          context: `${context}:${acct}`,
        });
        const amendedEnvelopes: Record<string, any> = { ...envelopes };
        for (const [reviewer, publicKey] of Object.entries(reviewers)) {
          amendedEnvelopes[reviewer] = await wrapEvidenceKeyForRecipient({
            contentKey,
            recipientPublicKeyB64: publicKey,
            context: `${context}:${reviewer}`,
          });
        }
        const committed = String(evidence.encrypted_blob_commitment || evidence.evidence_commitment || "").trim();
        if (!committed) throw new Error("Missing canonical encrypted evidence commitment.");
        const res = await submitSignedTxInSequence({
          sequence,
          tx_type: "POH_ASYNC_EVIDENCE_BIND",
          payloadFactory: () => ({
            case_id: caseId,
            evidence_id: evidenceId,
            target_id: caseId,
            key_envelope_commitments: amendedEnvelopes,
            evidence_root_commitment: committed,
            followup_round: currentRound,
            ts_ms: Date.now(),
          }),
          parent: null,
          base,
        });
        txIds.push(String(res?.result?.tx_id || ""));
      }
      if (!txIds.length) throw new Error("No encrypted evidence was available for reviewer access.");
      for (const txId of txIds) {
        if (!txId || !(await waitForSubmittedTxVisible(base, txId, { maxWaitMs: 90_000, requireLocalStateSynced: true }))) {
          throw new Error("Reviewer evidence binding is not yet confirmed and synced. Refresh this case before attempting another submission.");
        }
      }
      await loadVerificationData();
      await refresh();
      setResult({ case_id: caseId, evidence_access: "submitted_and_locally_confirmed", tx_ids: txIds });
    } catch (error: any) {
      setErr(prettyErr(error));
    } finally {
      setAsyncEvidenceBusy(false);
    }
  }

  async function submitLiveRequest(): Promise<void> {
    if (!acct) {
      setErr({ msg: "Sign in before opening live verification.", details: null });
      return;
    }
    if (!verificationHistoryReady.live) {
      setErr({ msg: "Live case history is unavailable on this node. Refresh before signing a new live verification request.", details: null });
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
          requireNoUnresolvedPoh("live");
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
          // The case ID is not known until the signed nonce returns. A
          // pre-dispatch marker with an empty ID deliberately requires
          // manual reconciliation if the response is lost.
          recordPohStage("live", "signed_started", "");
          goLiveStep("track");
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
          recordPohStage("live", "signed_returned", expectedCaseId, txId);
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
      if (acct && readPohSubmissionJournal(acct, "live").status !== "none") {
        goLiveStep("track");
        rereadPohJournals();
      }
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
  const asyncPreparationReady = asyncAbout.trim().length >= 10 && asyncWhyJoining.trim().length >= 10;
  const asyncStepNames = ["Understand", "Prepare", "Record", "Review", "Submit", "Track"] as const;
  const asyncStepIds = ["explain", "prepare", "record", "review", "submit", "track"] as const;

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
                onClick={() => nav("/onboarding/register")}
                disabled={!acct || !hasLocalKeypair || basicAccountCreated || signerSubmission.busy}
              >
                {signerSubmission.busy ? "Waiting…" : basicAccountCreated ? "Basic account ready" : "Finish account registration"}
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
        {accountLevel < 1 ? (
          <StatusCard
            eyebrow="Basic human review"
            title={VERIFICATION_LABELS.verified}
            status={verifiedStatus}
            description="Complete your first human review through six separate stages. Every upload, signed case, reviewer decision and account tier is verified separately."
          >
            <div className="formStack" data-testid="async-guided-journey">
              <PohStepProgress
                label="Async verification steps"
                steps={asyncStepIds.map((id, index) => ({ id, label: asyncStepNames[index] }))}
                current={asyncGuideStep}
                detail={asyncGuideStep === "track"
                  ? "Review progress only. Uploaded evidence and submitted transactions are not proof of completed human verification."
                  : undefined}
              />

                            <PohSubmissionStatusNotice
                kind="async"
                journal={asyncJournal}
                currentNodeBase={base}
                onTrack={() => goAsyncStep("track")}
              />

              {asyncGuideStep === "explain" ? (
                <div className="formStack" data-testid="async-step-explain">
                  <h3 ref={asyncStepHeadingRef} tabIndex={-1}>Before you record</h3>
                  <div className="calloutInfo">
                    <strong>Fresh video required:</strong> Record inside WeAll with camera and microphone permission for 1–2 minutes; ordinary file upload is not allowed for basic human review evidence. Say your handle, read the generated challenge phrase, and describe yourself and why you want to join.
                  </div>
                  <p className="miniMuted">
                    The recording stays on this device until you explicitly submit encrypted evidence. An independent reviewer and canonical account-state update, not the recording itself, determine your verification tier.
                  </p>
                  {asyncCases.length > 0 ? (
                    <div className="calloutInfo" data-testid="async-existing-cases">
                      You have {asyncCases.length} visible verification case(s). Inspect verification history and outstanding reviewer access before starting another request.
                      <button type="button" className="btn" onClick={() => goAsyncStep("track")}>
                        Inspect existing verification cases
                      </button>
                    </div>
                  ) : null}
                  <button
                    type="button"
                    className="btn btnPrimary"
                    onClick={() => goAsyncStep("prepare")}
                    disabled={!acct || !basicAccountCreated || !hasLocalKeypair || !sessionKeyPresent || !verificationHistoryReady.async || asyncJournalBlocked || casesBusy || asyncEvidenceBusy || signerSubmission.busy}
                  >
                    Prepare verification
                  </button>
                  {!basicAccountCreated ? <p className="miniMuted">Register your basic account on the network before starting verification.</p> : null}
                  {!verificationHistoryReady.async ? <p className="calloutDanger" data-testid="async-history-unavailable" role="status">{casesBusy ? "Checking earlier cases…" : "Case history unavailable. A failed lookup is not evidence that no case exists. Refresh the account view before starting a new case."}</p> : null}
                </div>
              ) : null}

              {asyncGuideStep === "prepare" ? (
                <div className="formStack" data-testid="async-step-prepare">
                  <h3 ref={asyncStepHeadingRef} tabIndex={-1}>Prepare your answers</h3>
                  <p className="cardDesc">Prepare what you will say. Both descriptions must have at least ten characters. Continue to recording when you are ready.</p>
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
                    <button type="button" className="btn" onClick={() => goAsyncStep("explain")}>Back to explanation</button>
                    <button
                      type="button"
                      className="btn btnPrimary"
                      disabled={!asyncPreparationReady || !registered || !verificationHistoryReady.async || asyncJournalBlocked || casesBusy || asyncEvidenceBusy || signerSubmission.busy}
                      onClick={() => {
                        ensureAsyncChallenge();
                        goAsyncStep("record");
                      }}
                    >
                      Continue to recording
                    </button>
                  </div>
                </div>
              ) : null}

              {asyncGuideStep === "record" ? (
                <div className="formStack" data-testid="async-step-record">
                  <h3 ref={asyncStepHeadingRef} tabIndex={-1}>Record your verification video</h3>
                  <div className="infoCard compact">
                    <div className="infoCardHeader">
                      <strong>Challenge phrase</strong>
                      <span className="statusPill">Read aloud</span>
                    </div>
                    <div className="infoCardText mono">{asyncChallenge?.phrase || "Start recording to generate a fresh challenge phrase."}</div>
                  </div>
                  <div className="buttonRowWide">
                    <button
                      type="button"
                      className="btn btnPrimary"
                      onClick={() => void startAsyncRecording()}
                      disabled={!acct || !basicAccountCreated || accountLevel >= 1 || asyncRecordingState === "recording" || asyncEvidenceBusy || signerSubmission.busy}
                    >
                      {asyncRecordingState === "recording" ? "Recording…" : "Record fresh verification video"}
                    </button>
                    <button type="button" className="btn" onClick={() => stopAsyncRecording()} disabled={asyncRecordingState !== "recording"}>
                      Stop recording
                    </button>
                    <button type="button" className="btn btnGhost" onClick={() => resetAsyncRecording()} disabled={asyncRecordingState === "recording" || asyncEvidenceBusy}>
                      Reset video
                    </button>
                  </div>
                  {asyncRecordingState === "recording" ? (
                    <div className="infoCard compact" data-testid="async-evidence-live-preview">
                      <div className="infoCardHeader">
                        <strong>Live camera preview — recording locally</strong>
                        <span className="statusPill">Camera and microphone active</span>
                      </div>
                      <video ref={recordingPreviewRef} autoPlay muted playsInline style={{ width: "100%", marginTop: 10, borderRadius: 12 }} />
                      <p className="miniMuted">Live camera preview is local. Nothing is uploaded until you submit encrypted evidence.</p>
                    </div>
                  ) : null}
                  <div className="infoCard compact">
                    <div className="infoCardHeader">
                      <strong>Recorded duration</strong>
                      <span className={`statusPill ${asyncRecordedBlob && !asyncDurationError ? "ok" : ""}`}>{asyncRecordingClock}</span>
                    </div>
                    <div className="infoCardText">Required length: {ASYNC_VIDEO_MIN_SECONDS}–{ASYNC_VIDEO_MAX_SECONDS} seconds.</div>
                    {asyncRecordedBlob && asyncDurationError ? <div className="calloutDanger">{asyncDurationError}</div> : null}
                  </div>
                  <div className="buttonRowWide">
                    <button type="button" className="btn" onClick={() => goAsyncStep("prepare")} disabled={asyncRecordingState === "recording"}>Back to preparation</button>
                    <button
                      type="button"
                      className="btn btnPrimary"
                      disabled={!asyncRecordedBlob || !!asyncDurationError || asyncRecordingState !== "ready"}
                      onClick={() => goAsyncStep("review")}
                    >
                      Review recorded video
                    </button>
                  </div>
                </div>
              ) : null}

              {asyncGuideStep === "review" ? (
                <div className="formStack" data-testid="async-step-review">
                  <h3 ref={asyncStepHeadingRef} tabIndex={-1}>Review your recording and consent</h3>
                  
                  {asyncRecordedUrl ? (
                    <div data-testid="async-evidence-playback-review">
                      <p className="miniMuted">Video playback is preloaded locally. Reviewer decryption remains gated by on-chain acceptance.</p>
                      <video controls playsInline preload="auto" src={asyncRecordedUrl} style={{ width: "100%", marginTop: 10, borderRadius: 12 }} />
                    </div>
                  ) : <p className="calloutDanger">Recording unavailable. Return to the recording stage.</p>}
                  <p className="miniMuted">Recorded duration: {asyncRecordingClock}. Required: {ASYNC_VIDEO_MIN_SECONDS}–{ASYNC_VIDEO_MAX_SECONDS} seconds.</p>
                  <label className="checkRow">
                    <input
                      type="checkbox"
                      checked={asyncConsent}
                      onChange={(e) => setAsyncConsent(e.target.checked)}
                      disabled={accountLevel >= 1 || asyncEvidenceBusy}
                    />
                    <span>Assigned reviewers may view this evidence only for account verification. Public chain state should store commitments and receipts, not raw video.</span>
                  </label>
                  <div className="buttonRowWide">
                    <button
                      type="button"
                      className="btn"
                      onClick={() => {
                        resetAsyncRecording();
                        goAsyncStep("record");
                      }}
                    >
                      Retake video
                    </button>
                    <button type="button" className="btn" onClick={() => goAsyncStep("prepare")}>Edit descriptions</button>
                    <button
                      type="button"
                      className="btn btnPrimary"
                      disabled={!asyncSubmitCheck.ok || asyncEvidenceBusy || signerSubmission.busy}
                      onClick={() => goAsyncStep("submit")}
                    >
                      Continue to encrypted submission
                    </button>
                  </div>
                  {!asyncSubmitCheck.ok ? <p className="miniMuted">{asyncSubmitCheck.reason}</p> : null}
                </div>
              ) : null}

              {asyncGuideStep === "submit" ? (
                <div className="formStack" data-testid="async-step-submit">
                  <h3 ref={asyncStepHeadingRef} tabIndex={-1}>Submit encrypted evidence</h3>
                  
                  <p className="cardDesc">
                    This action first uploads encrypted evidence, then submits signed case and access transactions. A successful upload does not mean reviewers were assigned, transactions finalized, or your tier increased.
                  </p>
                  <button
                    type="button"
                    className="btn btnPrimary"
                    onClick={() => void submitAsyncEvidence()}
                    disabled={!acct || !basicAccountCreated || !verificationHistoryReady.async || asyncJournalBlocked || casesBusy || accountLevel >= 1 || asyncEvidenceBusy || signerSubmission.busy || !asyncSubmitCheck.ok || !!asyncUpload}
                  >
                    {asyncEvidenceBusy ? "Submitting…" : signerSubmission.busy ? "Waiting…" : "Submit async verification evidence"}
                  </button>
                  {!asyncSubmitCheck.ok && accountLevel < 1 ? <div className="miniMuted">{asyncSubmitCheck.reason}</div> : null}
                  <button type="button" className="btn" disabled={asyncEvidenceBusy || !!asyncUpload} onClick={() => goAsyncStep("review")}>Back to review</button>
                  <button className="btn btnGhost" onClick={() => explainNativeAsyncVerification()} disabled={!acct}>
                    Show verification next steps
                  </button>
                </div>
              ) : null}

              {asyncGuideStep === "track" ? (
                <div className="formStack" data-testid="async-step-track">
                  <h3 ref={asyncStepHeadingRef} tabIndex={-1}>Track verification status</h3>
                  
                  {asyncUpload ? (
                    <div className="calloutInfo" data-testid="async-upload-accepted">
                      Encrypted evidence storage accepted the upload. The signed case, reviewer access, and finality remain separate checks.
                      If a later step fails, check verification history before re-uploading. Do not repeat an uncertain signed submission.
                    </div>
                  ) : (
                    <p className="calloutInfo">Existing cases may be visible below. Refresh the network view before deciding whether any new request is appropriate.</p>
                  )}
                  {asyncUpload ? <JsonDetails title="Latest async evidence upload payload" value={asyncUpload} /> : null}
                  {!verificationHistoryReady.async && !casesBusy ? <p className="calloutDanger" role="status">The selected node could not verify your current case history. Previously displayed cases may be stale.</p> : null}
                  <button
                    type="button"
                    className="btn btnPrimary"
                    onClick={() => void refreshVerificationSurface()}
                    disabled={loading || casesBusy || asyncEvidenceBusy}
                  >
                    {loading || casesBusy || asyncEvidenceBusy ? "Checking…" : "Refresh canonical verification status"}
                  </button>
                  <p className="miniMuted">Only a canonical account tier update confirms verification. The case history below lists visible request and reviewer progress.</p>
                </div>
              ) : null}
            </div>
          </StatusCard>
        ) : (
          <StatusCard
            eyebrow="Basic human review"
            title={VERIFICATION_LABELS.verified}
            status="done"
            description="The current canonical account view indicates basic verification. Continue to live verification if you need trusted participation."
          />
        )}
        {accountLevel >= 1 ? (
          <StatusCard
            eyebrow="Live human review"
            title={VERIFICATION_LABELS.trusted}
            status={trustedStatus}
            description="Live verification is a separate, higher-trust review. Opening a room or submitting a signed request is not the final reviewer decision."
          >
            {accountLevel >= 2 ? (
              <div className="calloutInfo" data-testid="live-verification-complete">
                The canonical account view reports Tier 2. Any separate reviewer or validator authority still requires its own eligibility and authorization.
              </div>
            ) : (
              <div className="formStack" data-testid="live-guided-journey">
                <PohStepProgress
                  label="Live verification steps"
                  steps={[
                    { id: "explain", label: "Understand" },
                    { id: "request", label: "Request" },
                    { id: "track", label: "Track" },
                  ]}
                  current={liveGuideStep}
                  detail={liveGuideStep === "track"
                    ? "Case visibility is not a completed reviewer decision or a canonical tier increase."
                    : undefined}
                />
                                <PohSubmissionStatusNotice
                  kind="live"
                  journal={liveJournal}
                  currentNodeBase={base}
                  onTrack={() => goLiveStep("track")}
                />

                {liveGuideStep === "explain" ? (
                  <div className="formStack" data-testid="live-step-explain">
                  <h3 ref={liveStepHeadingRef} tabIndex={-1}>Before live verification</h3>
                    <p className="cardDesc">
                      The live session prepares session, room, and prompt commitments before it submits a signed request. Independent attendance, reviewer decisions, canonical receipts and synchronized account state remain separate steps.
                    </p>
                    <div className="calloutInfo">
                      Camera, microphone and peer-to-peer transport must be available for participation. No third-party identity service is required, but a prepared room does not prove that other participants can connect.
                    </div>
                    {liveCases.length > 0 ? (
                      <div className="calloutInfo" data-testid="live-existing-cases">
                        {liveCases.length} live case(s) are visible. Inspect and reopen an existing case before requesting a replacement.
                        <button type="button" className="btn" onClick={() => goLiveStep("track")}>Inspect existing live cases</button>
                      </div>
                    ) : null}
                    <button type="button" className="btn btnPrimary" disabled={!acct || !hasLocalKeypair || !sessionKeyPresent || !verificationHistoryReady.live || liveJournalBlocked || casesBusy || liveRequestBusy || signerSubmission.busy} onClick={() => goLiveStep("request")}>
                      Prepare live verification request
                    </button>
                    {!verificationHistoryReady.live ? <p className="calloutDanger" data-testid="live-history-unavailable" role="status">{casesBusy ? "Checking earlier cases…" : "Live case history unavailable. Reconcile previous requests before opening a new signed request."}</p> : null}
                  </div>
                ) : null}
                {liveGuideStep === "request" ? (
                  <div className="formStack" data-testid="live-step-request">
                  <h3 ref={liveStepHeadingRef} tabIndex={-1}>Request a live session</h3>
                    <p className="cardDesc">Opening a live verification request signs and sends a new protocol action. Do not repeat a request with uncertain status; use the case history and transaction receipt to reconcile first.</p>
                    <button
                      type="button"
                      className="btn btnPrimary"
                      onClick={() => void submitLiveRequest()}
                      disabled={!acct || !hasLocalKeypair || !sessionKeyPresent || !verificationHistoryReady.live || liveJournalBlocked || casesBusy || liveRequestBusy || accountLevel >= 2 || accountLevel < 1 || signerSubmission.busy}
                    >
                      {liveRequestBusy ? "Opening…" : signerSubmission.busy ? "Waiting…" : "Open live verification"}
                    </button>
                    <div className="buttonRowWide">
                      <button type="button" className="btn" disabled={liveRequestBusy} onClick={() => goLiveStep("explain")}>Back to explanation</button>
                      <button type="button" className="btn" disabled={liveRequestBusy} onClick={() => goLiveStep("track")}>Check existing request status</button>
                    </div>
                    {liveCommitments ? (
                      <div className="infoCard compact">
                        <div className="infoCardHeader">
                          <strong>Prepared decentralized P2P room</strong>
                          <span className="statusPill">Transport only</span>
                        </div>
                        <div className="infoCardText">{liveRoomTransportNotice()}</div>
                        {liveRoomUrlFromCommitment(liveCommitments.room_commitment) ? (
                          <div className="buttonRow">
                            <a className="btn" href={liveRoomUrlFromCommitment(liveCommitments.room_commitment)} target="_blank" rel="noreferrer">Open self-hosted room</a>
                          </div>
                        ) : (
                          <p className="miniMuted">No centralized room URL is required. The room descriptor is prepared locally; other participants and transport availability have not yet been verified.</p>
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
                  </div>
                ) : null}
                {liveGuideStep === "track" ? (
                  <div className="formStack" data-testid="live-step-track">
                  <h3 ref={liveStepHeadingRef} tabIndex={-1}>Track your live case</h3>
                    <p className="cardDesc">
                      A case becomes actionable only when it appears in canonical verification history. A deterministic expected case ID or pending request is not proof of finalized verification.
                    </p>
                    <button type="button" className="btn btnPrimary" disabled={loading || casesBusy || liveRequestBusy} onClick={() => void refreshVerificationSurface()}>
                      {loading || casesBusy || liveRequestBusy ? "Checking…" : "Refresh live case status"}
                    </button>
                    {liveCases.map((item: any, idx: number) => (
                      <div className="infoCard compact" key={String(item?.case_id || idx)}>
                        <CaseCard item={item} />
                        <button
                          type="button"
                          className="btn"
                          disabled={!item?.case_id}
                          onClick={() => nav(`/verification/live/${encodeURIComponent(String(item?.case_id || ""))}`)}
                        >
                          Open recorded live case
                        </button>
                      </div>
                    ))}
                    {liveCases.length === 0 && verificationHistoryReady.live ? <p className="miniMuted">No canonical live case is visible yet. The node may be catching up; do not blindly resubmit a signed request.</p> : null}
                    {!verificationHistoryReady.live ? <p className="calloutDanger" role="status">The node could not confirm live case history. Any earlier case view may be stale. Reconcile before trying again.</p> : null}
                    <button type="button" className="btn" disabled={liveRequestBusy} onClick={() => goLiveStep("explain")}>Back to explanation</button>
                  </div>
                ) : null}
              </div>
            )}
        </StatusCard>
        ) : null}
      </section>

      <TrustedResponsibilitiesPanel
        account={acct}
        accountLevel={accountLevel}
        contentReviewActive={contentReviewActive}
        contentReviewOptedIn={contentReviewOptedIn}
        contentReviewStatusLabel={contentReviewStatusLabel}
        reviewerBusy={reviewerBusy}
        signerBusy={signerSubmission.busy}
        hasLocalKeypair={hasLocalKeypair}
        onUpdateContentReviewLane={(active) => void updateContentReviewLane(active)}
      />

      <VerificationHistoryPanel
        asyncCases={asyncCases}
        liveCases={liveCases}
        liveSessions={liveSessions}
        asyncHistoryReady={verificationHistoryReady.async}
        liveHistoryReady={verificationHistoryReady.live}
        loading={loading}
        casesBusy={casesBusy}
        onRefresh={() => void refreshVerificationSurface()}
        accountState={acctState}
        registrationView={registration}
        lastResult={result}
        renderAsyncCase={(item) => (
          <CaseCard
            item={item}
            onFinishReviewerAccess={(caseId) => void finishAsyncReviewerAccess(caseId)}
            working={asyncEvidenceBusy || signerSubmission.busy}
          />
        )}
        renderLiveCase={(item) => {
          const roomUrl = liveRoomUrlFromCommitment(item?.room_commitment);
          const descriptor = liveRoomDescriptorText(item?.room_commitment);
          return (
            <div className="infoCard compact">
              <CaseCard item={item} />
              <div className="buttonRow" style={{ marginTop: 10 }}>
                <button
                  className="btn btnPrimary"
                  disabled={!item?.case_id}
                  onClick={() => nav(`/verification/live/${encodeURIComponent(String(item?.case_id || ""))}`)}
                >
                  Open live verification room
                </button>
                {roomUrl ? (
                  <a className="btn" href={roomUrl} target="_blank" rel="noreferrer">
                    Open self-hosted transport
                  </a>
                ) : null}
              </div>
              <div className="miniMuted">{liveRoomTransportNotice()}</div>
              {descriptor ? (
                <details className="advancedDetails">
                  <summary>P2P room descriptor</summary>
                  <pre className="jsonBlock">{descriptor}</pre>
                </details>
              ) : null}
            </div>
          );
        }}
      />

    </div>
  );
}
