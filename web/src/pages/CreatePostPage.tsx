import React, { useEffect, useMemo, useState } from "react";

import { getApiBaseUrl, weall } from "../api/weall";
import ErrorBanner from "../components/ErrorBanner";
import { beginNonceSequence, ensureBackendSession, getAuthHeaders, getKeypair, getSession, submitSignedTxInSequence, syncNonceReservation } from "../auth/session";
import { normalizeAccount } from "../auth/keys";
import { useAccount } from "../context/AccountContext";
import { useSignerSubmissionBusy } from "../hooks/useSignerSubmissionBusy";
import { useTxQueue } from "../hooks/useTxQueue";
import { useMutationRefresh } from "../hooks/useMutationRefresh";
import {
  getDurableOperatorTarget,
  getMediaReplicationTarget,
} from "../lib/capabilities";
import {
  POSTING_MIN_TIER,
  resolveOnboardingSnapshot,
  summarizeNextRequirements,
} from "../lib/onboarding";
import { nav } from "../lib/router";
import { useAppConfig } from "../lib/config";
import { maybeRepairDevBootstrapSession } from "../lib/devBootstrap";
import { reconcilePostVisible } from "../lib/contentRevalidation";
import { refreshMutationSlices } from "../lib/revalidation";
import { actionableTxError, txPendingKey } from "../lib/txAction";

function prettyErr(e: any): { msg: string; details: any } {
  if (!e) return null as any;
  return actionableTxError(e, "Post submission failed.");
}

async function sleep(ms: number): Promise<void> {
  await new Promise((r) => setTimeout(r, ms));
}

async function waitForTxConfirmed(
  base: string,
  txId: string,
  opts?: { maxWaitMs?: number; intervalMs?: number },
) {
  const maxWaitMs = Math.max(1000, Number(opts?.maxWaitMs ?? 8000));
  const intervalMs = Math.max(200, Number(opts?.intervalMs ?? 400));
  const started = Date.now();

  while (Date.now() - started < maxWaitMs) {
    const st: any = await weall.txStatus(txId, base);
    if (st?.status === "confirmed") return st;
    if (st?.status === "unknown") return st;
    await sleep(intervalMs);
  }
  return { ok: true, tx_id: txId, status: "pending" };
}

async function waitForMediaDurable(
  cid: string,
  base: string,
  opts?: { maxWaitMs?: number; intervalMs?: number },
) {
  const maxWaitMs = Math.max(1000, Number(opts?.maxWaitMs ?? 6000));
  const intervalMs = Math.max(250, Number(opts?.intervalMs ?? 500));
  const started = Date.now();
  let last: any = null;

  while (Date.now() - started < maxWaitMs) {
    last = await weall.mediaStatus(cid, base);
    if (last?.durable === true) return last;
    await sleep(intervalMs);
  }
  return last;
}

function deterministicId(prefix: string, account: string, nonce: number): string {
  return `${prefix}:${account}:${nonce}`;
}

function advanceSequencePastNonce(sequence: { nextNonce: number }, nonce: number): void {
  const used = Math.max(0, Math.floor(Number(nonce) || 0));
  if (used <= 0) return;
  sequence.nextNonce = Math.max(Math.floor(sequence.nextNonce || 1), used + 1);
}

function isSubmittedOrConfirmed(status: any): boolean {
  const normalized = String(status?.status || "").trim().toLowerCase();
  return normalized === "confirmed" || normalized === "pending" || normalized === "unknown";
}

async function waitForAccountNonceAtLeast(
  account: string,
  expectedNonce: number,
  base: string,
  opts?: { maxWaitMs?: number; intervalMs?: number },
) {
  const maxWaitMs = Math.max(1000, Number(opts?.maxWaitMs ?? 20000));
  const intervalMs = Math.max(200, Number(opts?.intervalMs ?? 500));
  const started = Date.now();
  let last: any = null;

  while (Date.now() - started < maxWaitMs) {
    last = await weall.account(account, base);
    const current = Number(last?.state?.nonce ?? 0);
    if (Number.isFinite(current) && current >= expectedNonce) {
      return last;
    }
    await sleep(intervalMs);
  }

  throw {
    message: "account_nonce_not_advanced",
    data: {
      account,
      expected_nonce: expectedNonce,
      last: last || null,
    },
  };
}

function parseTags(raw: string): string[] {
  return raw
    .split(/[\s,]+/g)
    .map((s) => s.trim().replace(/^#/, ""))
    .filter(Boolean)
    .slice(0, 20);
}

function formatBytes(bytes: number): string {
  const n = Number(bytes || 0);
  if (!Number.isFinite(n) || n <= 0) return "0 B";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${Math.round(n / 1024)} KB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MB`;
}

const MAX_MEDIA_UPLOAD_BYTES = 10 * 1024 * 1024;
const SUPPORTED_MEDIA_PREFIXES = ["image/", "video/", "audio/"];

function readComposerGroupIdFromHash(): string {
  if (typeof window === "undefined") return "";
  const hash = String(window.location.hash || "");
  const qidx = hash.indexOf("?");
  if (qidx < 0) return "";
  const qs = hash.slice(qidx + 1);
  const params = new URLSearchParams(qs);
  return String(params.get("group_id") || "").trim();
}

function validateSelectedFile(file: File | null): string | null {
  if (!file) return null;
  const mime = String(file.type || "").trim().toLowerCase();
  const supported = SUPPORTED_MEDIA_PREFIXES.some((prefix) => mime.startsWith(prefix));
  if (!supported) {
    return "Only image, video, and audio uploads are supported in this composer.";
  }
  if (Number(file.size || 0) > MAX_MEDIA_UPLOAD_BYTES) {
    return `This file is larger than the current ${formatBytes(MAX_MEDIA_UPLOAD_BYTES)} upload limit.`;
  }
  return null;
}

export default function CreatePostPage(): JSX.Element {
  const config = useAppConfig();
  const base = useMemo(() => getApiBaseUrl(), []);
  const session = getSession();
  const acct = session ? normalizeAccount(session.account) : null;
  const kp = acct ? getKeypair(acct) : null;
  const canSign = !!kp?.secretKeyB64;
  const { refresh: refreshAccountContext } = useAccount();
  const tx = useTxQueue();
  const signerSubmission = useSignerSubmissionBusy(acct);

  const replicationTarget = getMediaReplicationTarget();
  const durableOperatorTarget = getDurableOperatorTarget();

  const [acctState, setAcctState] = useState<any | null>(null);
  const [registration, setRegistration] = useState<any | null>(null);
  const [err, setErr] = useState<{ msg: string; details: any } | null>(null);

  const [text, setText] = useState<string>("");
  const [tags, setTags] = useState<string>("");
  const [visibility, setVisibility] = useState<"public" | "followers" | "group" | "private">(
    "public",
  );
  const [file, setFile] = useState<File | null>(null);
  const [localPreviewUrl, setLocalPreviewUrl] = useState<string>("");
  const [composerGroupId, setComposerGroupId] = useState<string>(() => readComposerGroupIdFromHash());

  const [busy, setBusy] = useState<boolean>(false);
  const [status, setStatus] = useState<string>("");
  const [last, setLast] = useState<any>(null);
  const [createdPostId, setCreatedPostId] = useState<string>("");
  const [uploadInfo, setUploadInfo] = useState<any | null>(null);
  const [mediaDurability, setMediaDurability] = useState<any | null>(null);

  const signerBusyElsewhere = signerSubmission.busy && !busy;

  useMutationRefresh({
    entityTypes: ["content"],
    account: acct,
    onRefresh: async () => {
      await refresh();
      await refreshAccountContext();
    },
  });

  async function refresh(): Promise<void> {
    if (!acct) {
      setAcctState(null);
      setRegistration(null);
      return;
    }
    try {
      const [a, r] = await Promise.all([
        weall.account(acct, base),
        weall.accountRegistered(acct, base),
      ]);
      setAcctState(a);
      setRegistration(r);
    } catch (e: any) {
      setErr(prettyErr(e));
    }
  }

  useEffect(() => {
    void refresh();
  }, [acct]);

  useEffect(() => {
    const sync = () => setComposerGroupId(readComposerGroupIdFromHash());
    sync();
    window.addEventListener("hashchange", sync);
    return () => window.removeEventListener("hashchange", sync);
  }, []);

  useEffect(() => {
    if (!file) {
      setLocalPreviewUrl("");
      return;
    }
    const next = URL.createObjectURL(file);
    setLocalPreviewUrl(next);
    return () => URL.revokeObjectURL(next);
  }, [file]);

  const snapshot = resolveOnboardingSnapshot({
    account: acct,
    session,
    keypair: kp,
    accountView: acctState,
    registrationView: registration,
  });

  async function repairDevSessionIfNeeded(): Promise<boolean> {
    const repaired = await maybeRepairDevBootstrapSession(config).catch(() => false);
    if (repaired) {
      await syncNonceReservation(acct || "", base).catch(() => 0);
      await refresh();
      await refreshAccountContext();
    }
    return repaired;
  }

  async function revalidateAfterSubmit(postId: string, body: string): Promise<void> {
    await refreshMutationSlices(
      async () => {
        if (!acct || !postId) return;
        await reconcilePostVisible({
          postId,
          account: acct,
          body,
          groupId: composerGroupId || null,
          base,
        });
      },
      refresh,
      refreshAccountContext,
    );
  }

  async function submit(): Promise<void> {
    setErr(null);
    setLast(null);
    setCreatedPostId("");
    setUploadInfo(null);
    setMediaDurability(null);

    if (!acct || !canSign) {
      setErr({
        msg: "You are not logged in on this device.",
        details:
          "Go to Settings and make sure this browser has both a session and the matching local signing keypair.",
      });
      return;
    }

    if (!snapshot.registered) {
      setErr({
        msg: "Posting is blocked until this account is registered.",
        details: { registration, account_state: acctState?.state ?? null },
      });
      return;
    }

    const tierNow = Number(acctState?.state?.poh_tier ?? 0);
    if (tierNow < POSTING_MIN_TIER) {
      setErr({
        msg: `Posting is locked until Tier ${POSTING_MIN_TIER} is active.`,
        details: { poh_tier: tierNow, account_state: acctState?.state ?? null },
      });
      return;
    }

    if (snapshot.banned || snapshot.locked) {
      setErr({
        msg: `This account is ${snapshot.banned ? "banned" : "locked"}.`,
        details: acctState?.state ?? null,
      });
      return;
    }

    if (signerBusyElsewhere) {
      setErr({
        msg: "Another signed action for this account is already running in this or another tab.",
        details: {
          account: acct,
          pending_count: signerSubmission.pendingCount,
          hint: "Wait for the other action to finish, then publish again.",
        },
      });
      return;
    }

    const body = text.trim();
    if (!body && !file) {
      setErr({ msg: "Write something or attach a file.", details: null });
      return;
    }

    const fileError = validateSelectedFile(file);
    if (fileError) {
      setErr({ msg: fileError, details: { max_bytes: MAX_MEDIA_UPLOAD_BYTES, file_type: file?.type || null } });
      return;
    }

    const tagList = parseTags(tags);

    setBusy(true);
    try {
      await syncNonceReservation(acct, base);
      await refresh();
      await refreshAccountContext();

      let expectedPostId = "";
      const result = await tx.runTx({
        title: "Create post",
        pendingKey: txPendingKey(["content-post-create", acct, composerGroupId || "root"]),
        pendingMessage: "Uploading media and preparing your post…",
        successMessage: (res: any) =>
          res?.postId ? `Post submitted: ${res.postId}` : "Post submitted successfully.",
        errorMessage: (e) => prettyErr(e).msg,
        getTxId: (res: any) => res?.postTxId,
        finality: {
          timeoutMs: 20000,
          mutation: { entityType: "content", account: acct || undefined, routeHint: composerGroupId ? `/groups/${encodeURIComponent(composerGroupId)}` : "/feed", txType: "CONTENT_POST_CREATE" },
          reconcile: async () => {
            return expectedPostId
              ? reconcilePostVisible({
                  postId: expectedPostId,
                  account: acct,
                  body,
                  groupId: composerGroupId || null,
                  base,
                })
              : null;
          },
        },
        task: async () => {
          let mediaIds: string[] = [];
          let finalUploadInfo: any | null = null;
          let finalDurability: any | null = null;
          let finalPostId = "";
          let finalPostTxId = "";
          let finalResult: any = null;

          const sequence = await beginNonceSequence(acct, base);

          if (file) {
            setStatus("Ensuring backend session");
            try {
              await ensureBackendSession({
                account: acct,
                ttlSeconds: 24 * 60 * 60,
                base,
              });
            } catch (error: any) {
              const repaired = await repairDevSessionIfNeeded();
              if (!repaired) throw error;
              await ensureBackendSession({
                account: acct,
                ttlSeconds: 24 * 60 * 60,
                base,
              });
            }

            setStatus("Uploading media");
            let headers = getAuthHeaders(acct);
            if (!headers["x-weall-account"] || !headers["x-weall-session-key"]) {
              await ensureBackendSession({
                account: acct,
                ttlSeconds: 24 * 60 * 60,
                base,
              });
              headers = getAuthHeaders(acct);
            }
            let up: any;
            try {
              up = await weall.mediaUpload(file, base, headers);
            } catch (error: any) {
              const status = Number(error?.status || 0);
              const payloadCode = String(error?.payload?.error?.code || error?.payload?.code || "").trim();
              const message = String(error?.message || "").trim();
              const sessionish = status === 500 || status === 401 || status === 403 || payloadCode === "session_invalid" || payloadCode === "pubkey_not_authorized" || message === "session_invalid" || message === "pubkey is not an active key on this account";
              if (sessionish) {
                const repaired = await repairDevSessionIfNeeded();
                if (repaired) {
                  await ensureBackendSession({
                    account: acct,
                    ttlSeconds: 24 * 60 * 60,
                    base,
                  });
                } else {
                  await ensureBackendSession({
                    account: acct,
                    ttlSeconds: 24 * 60 * 60,
                    base,
                  });
                }
                headers = getAuthHeaders(acct);
                up = await weall.mediaUpload(file, base, headers);
              } else {
                throw error;
              }
            }
            if (!up || up.ok !== true) throw up;
            finalUploadInfo = up;
            setUploadInfo(up);

            const cid =
              String(up.cid || "").trim() ||
              String(up.upload_ref || "").trim() ||
              String(up.ref || "").trim() ||
              String(up.path || "").trim() ||
              String(up.key || "").trim();

            if (!cid) throw { message: "media_upload_missing_cid", data: up };

            const pinRequest = up?.pin_request || null;
            const pinEnvelope = pinRequest?.envelope || null;
            const pinSubmitted = pinRequest?.submitted === true;
            const pinTxId = String(pinRequest?.tx_id || "").trim();

            if (pinSubmitted && pinEnvelope) {
              const submittedNonce = Number(pinEnvelope?.nonce || 0);
              advanceSequencePastNonce(sequence, submittedNonce);

              if (submittedNonce > 0) {
                setStatus("Waiting for pin request to advance chain nonce");
                await waitForAccountNonceAtLeast(acct, submittedNonce, base, {
                  maxWaitMs: 25000,
                  intervalMs: 500,
                });
                const refreshedChainNonce = await syncNonceReservation(acct, base);
                sequence.nextNonce = Math.max(sequence.nextNonce, Math.floor(refreshedChainNonce) + 1);
              }
            } else if (pinEnvelope) {
              setStatus("Submitting pin request");
              const pinPayload = { ...(pinEnvelope.payload || {}) };
              if (typeof pinPayload.ts_ms === "number" && pinPayload.ts_ms === 0) {
                pinPayload.ts_ms = Date.now();
              }
              const pinReq: any = await submitSignedTxInSequence({
                sequence,
                tx_type: String(pinEnvelope.tx_type || "IPFS_PIN_REQUEST"),
                payloadFactory: () => pinPayload,
                parent: pinEnvelope.parent ?? null,
                base,
              });
              const pinNonce = Number(pinReq?.env?.nonce || 0);
              if (pinNonce > 0) {
                setStatus("Waiting for pin request to advance chain nonce");
                await waitForAccountNonceAtLeast(acct, pinNonce, base, {
                  maxWaitMs: 25000,
                  intervalMs: 500,
                });
                const refreshedChainNonce = await syncNonceReservation(acct, base);
                sequence.nextNonce = Math.max(sequence.nextNonce, Math.floor(refreshedChainNonce) + 1);
              }
            }

            setStatus("Checking durability");
            const durable: any = await waitForMediaDurable(cid, base);
            finalDurability = durable;
            setMediaDurability(durable);

            setStatus("Declaring media");
            const declare: any = await submitSignedTxInSequence({
              sequence,
              tx_type: "CONTENT_MEDIA_DECLARE",
              payloadFactory: (nonce) => {
                const media_id = deterministicId("media", acct, nonce);
                return {
                  media_id,
                  cid,
                  upload_ref: cid,
                  mime: file.type || null,
                  bytes: file.size || null,
                  name: file.name || null,
                };
              },
              parent: null,
              base,
            });

            const declareTxId = String(declare?.result?.tx_id || "").trim();
            const declareNonce = Number(declare?.env?.nonce || 0);
            if (declareNonce > 0) {
              setStatus("Waiting for media declaration to advance chain nonce");
              await waitForAccountNonceAtLeast(acct, declareNonce, base, {
                maxWaitMs: 25000,
                intervalMs: 500,
              });
              const refreshedChainNonce = await syncNonceReservation(acct, base);
              sequence.nextNonce = Math.max(sequence.nextNonce, Math.floor(refreshedChainNonce) + 1);
            } else if (declareTxId) {
              const declareStatus: any = await waitForTxConfirmed(base, declareTxId, {
                maxWaitMs: 5000,
                intervalMs: 400,
              });
              if (!isSubmittedOrConfirmed(declareStatus)) {
                throw {
                  message: "media_declare_submit_failed",
                  data: {
                    tx_id: declareTxId,
                    status: declareStatus || null,
                  },
                };
              }
            }

            const declaredId = String(declare?.env?.payload?.media_id || "").trim();
            if (!declaredId) throw { message: "media_declare_missing_media_id", data: declare };
            mediaIds = [declaredId];
          }

          setStatus("Submitting post");
          const res: any = await submitSignedTxInSequence({
            sequence,
            tx_type: "CONTENT_POST_CREATE",
            payloadFactory: (nonce) => {
              const post_id = deterministicId("post", acct, nonce);
              return {
                post_id,
                body: body || null,
                visibility: composerGroupId ? "group" : visibility,
                tags: tagList.length ? tagList : null,
                media: mediaIds.length ? mediaIds : null,
                group_id: composerGroupId || null,
              };
            },
            parent: null,
            base,
          });

          const postTxId = String(res?.result?.tx_id || "").trim();
          const postNonce = Number(res?.env?.nonce || 0);
          if (postNonce > 0) {
            setStatus("Waiting for post submission to advance chain nonce");
            await waitForAccountNonceAtLeast(acct, postNonce, base, {
              maxWaitMs: 25000,
              intervalMs: 500,
            });
          } else if (postTxId) {
            const postSubmissionStatus: any = await waitForTxConfirmed(base, postTxId, {
              maxWaitMs: 5000,
              intervalMs: 400,
            });
            if (!isSubmittedOrConfirmed(postSubmissionStatus)) {
              throw {
                message: "post_create_submit_failed",
                data: {
                  tx_id: postTxId,
                  status: postSubmissionStatus || null,
                },
              };
            }
          }

          finalPostId = String(res?.env?.payload?.post_id || "").trim();
          expectedPostId = finalPostId;
          finalPostTxId = postTxId;
          finalResult = res;

          return {
            uploadInfo: finalUploadInfo,
            mediaDurability: finalDurability,
            postId: finalPostId,
            postTxId: finalPostTxId,
            result: finalResult,
            submitted: true,
          };
        },
      });

      setUploadInfo(result.uploadInfo);
      setMediaDurability(result.mediaDurability);
      setCreatedPostId(result.postId || "");
      setLast(result.result);
      setStatus("Done");
      setText("");
      setTags("");
      setFile(null);

      await revalidateAfterSubmit(String(result.postId || ""), body);
    } catch (e: any) {
      setStatus("Error");
      const formatted = prettyErr(e);
      if (
        String(formatted?.msg || '').trim() === 'session_invalid' ||
        String(formatted?.details?.message || '').trim() === 'session_invalid' ||
        String(formatted?.details?.error?.code || '').trim() === 'session_invalid' ||
        String(formatted?.details?.error?.code || '').trim() === 'pubkey_not_authorized' ||
        String(formatted?.msg || '').trim() === 'pubkey is not an active key on this account'
      ) {
        try {
          const repaired = await repairDevSessionIfNeeded();
          if (!repaired) {
            await ensureBackendSession({
              account: acct,
              ttlSeconds: 24 * 60 * 60,
              base,
            });
          }
          await refresh();
          await refreshAccountContext();
        } catch {
          // keep original error visible
        }
        setErr({
          msg: 'This browser is holding a stale backend session or an old local signer. We attempted to repair it; try publish again.',
          details: formatted.details,
        });
      } else if (String(formatted?.msg || "").trim() === "signer_busy_elsewhere") {
        setErr({
          msg: "Another signed action for this account is already running in this or another tab.",
          details: {
            account: acct,
            pending_count: signerSubmission.pendingCount,
            hint: "Wait for the other action to finish, then try publish again.",
          },
        });
      } else if (formatted?.details?.error?.code === "bad_nonce") {
        await syncNonceReservation(acct, base);
        await refresh();
        await refreshAccountContext();
        setErr({
          msg: "Your local signing nonce was stale. We refreshed chain state; publish again.",
          details: formatted.details,
        });
      } else if (
        formatted?.msg === "pin_request_submit_failed" ||
        formatted?.msg === "media_declare_submit_failed" ||
        formatted?.msg === "post_create_submit_failed" ||
        formatted?.msg === "account_nonce_not_advanced"
      ) {
        await syncNonceReservation(acct, base);
        await refresh();
        await refreshAccountContext();
        setErr({
          msg: "A publish step was submitted but the chain nonce did not advance in time. Wait a moment, refresh, and try again.",
          details: formatted.details,
        });
      } else {
        setErr(formatted);
      }
      setLast(e?.payload || e?.body || e?.data || e);
    } finally {
      setBusy(false);
    }
  }

  const tier = snapshot.tier;
  const registered = snapshot.registered;
  const bodyLen = text.trim().length;
  const tagListPreview = parseTags(tags);
  const previewType = file?.type || "";
  const fileValidationError = validateSelectedFile(file);
  const previewGateway = String(uploadInfo?.cid || "").trim()
    ? weall.mediaGatewayUrl(String(uploadInfo.cid), base)
    : "";
  const canPublish = snapshot.canPost && !!(text.trim() || file) && !busy && !signerBusyElsewhere && !fileValidationError;

  const readinessChecks = summarizeNextRequirements(snapshot);

  const flowSteps = [
    {
      label: "Draft",
      state: bodyLen || file ? "ready" : "pending",
      detail: bodyLen || file ? "Content prepared." : "Write text or attach media.",
    },
    {
      label: "Upload",
      state: uploadInfo ? "done" : file ? (busy ? "active" : "pending") : "idle",
      detail: file
        ? uploadInfo
          ? `CID ${String(uploadInfo?.cid || "").trim() || "recorded"}`
          : "Selected media will upload first."
        : "Skipped when no file is attached.",
    },
    {
      label: "Durability",
      state: mediaDurability?.durable ? "done" : mediaDurability ? "active" : file ? "pending" : "idle",
      detail: file
        ? mediaDurability?.durable
          ? "Replication threshold reached."
          : mediaDurability
            ? "Replication is still catching up; publish can still complete."
            : "Observed after upload so you can see whether replication has caught up yet."
        : "No durability check needed.",
    },
    {
      label: "Declare",
      state: uploadInfo && !busy ? "done" : file ? "pending" : "idle",
      detail: file
        ? "Creates the on-chain media record used by the post."
        : "No media declaration needed.",
    },
    {
      label: "Publish",
      state: createdPostId ? "done" : busy ? "active" : canPublish ? "ready" : "pending",
      detail: createdPostId
        ? createdPostId
        : canPublish
          ? signerBusyElsewhere
            ? "Another signed action must finish before publish can reserve the next nonce."
            : "Ready to sign and submit."
          : "Complete the checks above to publish.",
    },
  ];

  let nextAction = { label: "Publish your post", href: "", action: submit as (() => void) | null };
  if (!snapshot.hasSession || !snapshot.hasLocalSigner) {
    nextAction = { label: snapshot.next.label, href: snapshot.next.route, action: null };
  } else if (!registered || tier < POSTING_MIN_TIER) {
    nextAction = { label: snapshot.next.label, href: snapshot.next.route, action: null };
  } else if (createdPostId) {
    nextAction = {
      label: "Open new thread",
      href: `/thread/${encodeURIComponent(createdPostId)}`,
      action: null,
    };
  }

  const observedReplication = Number(mediaDurability?.replication_factor ?? 0);
  const observedOperators = Number(mediaDurability?.ok_unique_ops ?? 0);

  return (
    <div className="pageStack pageNarrow actionPage createPostPage">
      <section className="card heroCard actionHeroCard">
        <div className="cardBody heroBody compactHero">
          <div className="heroSplit">
            <div>
              <div className="eyebrow">Creator flow</div>
              <h1 className="heroTitle heroTitleSm">Create a post</h1>
              <p className="heroText">
                Compose a public post, optionally attach media, then walk through upload, media
                declaration, and publish. Durability is observed after upload so the UI stays honest
                about what is confirmed now versus what may still be replicating.
              </p>
            </div>

            <div className="heroInfoPanel">
              <div className="heroInfoTitle">Readiness</div>
              <div className="heroInfoList">
                <span className={`statusPill ${snapshot.hasSession ? "ok" : ""}`}>
                  {snapshot.hasSession ? "Session present" : "No session"}
                </span>
                <span className={`statusPill ${snapshot.hasLocalSigner ? "ok" : ""}`}>
                  {snapshot.hasLocalSigner ? "Signing ready" : "No local signer"}
                </span>
                <span className={`statusPill ${tier >= POSTING_MIN_TIER ? "ok" : ""}`}>
                  Tier {tier}
                </span>
                <span className={`statusPill ${registered ? "ok" : ""}`}>
                  {registered ? "Registered" : "Not registered"}
                </span>
              </div>
            </div>
          </div>

          <div className="statsGrid statsGridCompact">
            <div className="statCard">
              <span className="statLabel">Account</span>
              <span className="statValue mono">{acct || "Not signed in"}</span>
            </div>
            <div className="statCard">
              <span className="statLabel">Body length</span>
              <span className="statValue">{bodyLen}</span>
            </div>
            <div className="statCard">
              <span className="statLabel">Attachment</span>
              <span className="statValue">{file ? formatBytes(file.size) : "None"}</span>
            </div>
            <div className="statCard">
              <span className="statLabel">Audience</span>
              <span className="statValue">Public</span>
            </div>
          </div>
        </div>
      </section>

      <ErrorBanner message={err?.msg} details={err?.details} onRetry={() => void refreshMutationSlices(refresh, refreshAccountContext)} onDismiss={() => setErr(null)} />

      <section className="detailFocusStrip actionFocusStrip">
        <article className="detailFocusCard">
          <div className="detailFocusLabel">Primary object</div>
          <div className="detailFocusValue">Post composer</div>
          <div className="detailFocusText">This route exists to complete one publish flow. Feed browsing and discussion belong back on the hub.</div>
        </article>
        <article className="detailFocusCard">
          <div className="detailFocusLabel">Current publish posture</div>
          <div className="detailFocusValue">{canPublish ? "Ready to submit" : signerBusyElsewhere ? "Signer lane busy" : "Needs attention"}</div>
          <div className="detailFocusText">{canPublish ? "The signer lane is open and the account posture is sufficient for post submission." : String(readinessChecks.find((item) => !item.ok)?.hint || "Resolve the unmet posting prerequisites shown below before publishing.")}</div>
        </article>
        <article className="detailFocusCard">
          <div className="detailFocusLabel">Truth model</div>
          <div className="detailFocusValue">Submission ≠ visibility</div>
          <div className="detailFocusText">The composer reports upload, declaration, and publish separately so the page stays honest about what is confirmed right now.</div>
        </article>
      </section>

      <section className="grid2">
        <article className="card">
          <div className="cardBody formStack">
            <div className="sectionHead">
              <div>
                <div className="eyebrow">Compose</div>
                <h2 className="cardTitle">What do you want to share?</h2>
              </div>
              <div className="statusSummary">
                <span className="statusPill mono">{base || "(no api base)"}</span>
                {status ? (
                  <span className={`statusPill ${status === "Done" ? "ok" : ""}`}>{status}</span>
                ) : null}
              </div>
            </div>

            <div className="surfaceSummaryGrid">
              {readinessChecks.map((item) => (
                <div key={item.label} className="surfaceSummaryCard">
                  <span className="surfaceSummaryLabel">{item.label}</span>
                  <strong className="surfaceSummaryValue">{item.ok ? "Ready" : "Needs attention"}</strong>
                  <span className="surfaceSummaryHint">{item.hint}</span>
                </div>
              ))}
              <div className="surfaceSummaryCard">
                <span className="surfaceSummaryLabel">Signer lane</span>
                <strong className="surfaceSummaryValue">{signerBusyElsewhere ? "Busy" : "Open"}</strong>
                <span className="surfaceSummaryHint">
                  {signerBusyElsewhere
                    ? `Another signed action is already using this account (${signerSubmission.pendingCount} in flight).`
                    : "This account can safely reserve the next nonce for publish."}
                </span>
              </div>
            </div>

            <label className="fieldLabel">
              Post body
              <textarea
                value={text}
                onChange={(e) => setText(e.target.value)}
                placeholder="Write something thoughtful, useful, or timely…"
                rows={10}
              />
            </label>

            <div className="grid2 formGrid">
              <label className="fieldLabel">
                Audience
                <input value="Public" readOnly />
              </label>

              <label className="fieldLabel">
                Tags
                <input
                  value={tags}
                  onChange={(e) => setTags(e.target.value)}
                  placeholder="identity governance builders"
                />
              </label>
            </div>

            <div className="calloutInfo">
              <strong>Current publishing truth</strong>
              <div style={{ marginTop: 6 }}>
                This deployment currently publishes public posts only. Followers-only, group-only, and private composer options stay hidden until the backend supports them end to end.
              </div>
            </div>

            <div className="actionStateRow">
              <span className="actionStateLabel">Submission model</span>
              <span className="actionStateText">
                Upload, media declaration, and post creation are separate protocol steps. Submission can succeed before every downstream read surface reflects the final result.
              </span>
            </div>

            <label className="uploadZone">
              <span className="uploadTitle">Attachment</span>
              <span className="uploadHint">
                Optional. Images, audio, and video up to {formatBytes(MAX_MEDIA_UPLOAD_BYTES)} use
                the upload → declare → publish flow.
              </span>
              <input
                type="file"
                accept="image/*,video/*,audio/*"
                onChange={(e) => setFile(e.target.files?.[0] || null)}
              />
              <span className="uploadMeta">
                {file ? `${file.name} · ${formatBytes(file.size)}` : "No file selected"}
              </span>
            </label>

            {fileValidationError ? (
              <div className="calloutDanger">{fileValidationError}</div>
            ) : null}

            {file ? (
              <div className="buttonRow">
                <button className="btn btnGhost" onClick={() => setFile(null)} disabled={busy}>
                  Remove attachment
                </button>
              </div>
            ) : null}

            <div className="buttonRow buttonRowWide">
              <button className="btn btnPrimary" onClick={submit} disabled={!canPublish}>
                {busy ? "Publishing…" : "Publish post"}
              </button>
              {nextAction.action ? null : (
                <button className="btn" onClick={() => nav(nextAction.href)} disabled={busy}>
                  {nextAction.label}
                </button>
              )}
              <button className="btn" onClick={() => nav("/feed")} disabled={busy}>
                Back to feed
              </button>
            </div>

            {!canPublish ? (
              <div className="emptyPanel compact">
                <strong>Not ready to publish yet.</strong>
                <span>
                  {!snapshot.hasSession
                    ? "Create or restore a local session first."
                    : !snapshot.hasLocalSigner
                      ? "Restore the local signing keypair in Settings."
                      : !registered
                        ? "Finish account registration before posting."
                        : tier < POSTING_MIN_TIER
                          ? `Finish PoH so Tier ${POSTING_MIN_TIER} is unlocked.`
                          : fileValidationError
                            ? fileValidationError
                            : "Add text or a file to continue."}
                </span>
              </div>
            ) : null}
          </div>
        </article>

        <article className="card">
          <div className="cardBody formStack">
            <div className="sectionHead">
              <div>
                <div className="eyebrow">Preview</div>
                <h2 className="cardTitle">Before you submit</h2>
              </div>
              <span className={`statusPill ${createdPostId ? "ok" : canPublish ? "ok" : ""}`}>
                {createdPostId ? "Published" : signerBusyElsewhere ? "Waiting for another action" : canPublish ? "Ready to publish" : "Draft in progress"}
              </span>
            </div>

            <div className="statusSummary">
              <span className={`statusPill ${tier >= POSTING_MIN_TIER ? "ok" : ""}`}>
                {tier >= POSTING_MIN_TIER ? "Posting unlocked" : `Tier ${POSTING_MIN_TIER} required`}
              </span>
              <span className={`statusPill ${registered ? "ok" : ""}`}>
                {registered ? "Account registered" : "Registration required"}
              </span>
              <span className="statusPill">public</span>
            </div>

            <div className="feedBodyText">{text.trim() || "Your draft preview appears here."}</div>

            {tagListPreview.length ? (
              <div className="milestoneList">
                {tagListPreview.map((tag) => (
                  <span key={tag} className="miniTag">
                    #{tag}
                  </span>
                ))}
              </div>
            ) : null}

            {file ? (
              <div className="feedMediaCard">
                <div className="feedMediaTitle">Selected media</div>
                <div className="feedMediaMeta">
                  {file.name} · {file.type || "unknown type"} · {formatBytes(file.size)}
                </div>

                {previewType.startsWith("image/") && localPreviewUrl ? (
                  <img
                    src={localPreviewUrl}
                    alt={file.name}
                    style={{ width: "100%", borderRadius: 12, marginTop: 10 }}
                  />
                ) : null}
                {previewType.startsWith("video/") && localPreviewUrl ? (
                  <video
                    src={localPreviewUrl}
                    controls
                    style={{ width: "100%", borderRadius: 12, marginTop: 10 }}
                  />
                ) : null}
                {previewType.startsWith("audio/") && localPreviewUrl ? (
                  <audio src={localPreviewUrl} controls style={{ width: "100%", marginTop: 10 }} />
                ) : null}
              </div>
            ) : (
              <div className="emptyPanel compact">
                <strong>No attachment selected.</strong>
                <span>You can still publish a text-only post.</span>
              </div>
            )}

            <div className="infoCard">
              <div className="sectionHead">
                <div>
                  <div className="eyebrow">Flow</div>
                  <h3 className="cardTitle">Publishing checklist</h3>
                </div>
              </div>
              <div className="progressList">
                {flowSteps.map((step) => (
                  <div key={step.label} className={`progressItem ${step.state}`}>
                    <div className="progressState" />
                    <div>
                      <strong>{step.label}</strong>
                      <div className="infoCardText">{step.detail}</div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div className="infoCard">
              <div className="feedMediaTitle">Durability expectations</div>
              <div className="progressList">
                <div className="progressRow">
                  <span>Target replication factor</span>
                  <span className="statusPill">{replicationTarget}</span>
                </div>
                <div className="progressRow">
                  <span>Target confirmed operators</span>
                  <span className="statusPill">{durableOperatorTarget}</span>
                </div>
                <div className="progressRow">
                  <span>Observed replication factor</span>
                  <span className={`statusPill ${observedReplication >= replicationTarget ? "ok" : ""}`}>
                    {mediaDurability ? observedReplication : "—"}
                  </span>
                </div>
                <div className="progressRow">
                  <span>Observed confirmed operators</span>
                  <span className={`statusPill ${observedOperators >= durableOperatorTarget ? "ok" : ""}`}>
                    {mediaDurability ? observedOperators : "—"}
                  </span>
                </div>
                <div className="progressRow">
                  <span>Durable now</span>
                  <span className={`statusPill ${mediaDurability?.durable ? "ok" : ""}`}>
                    {mediaDurability ? (mediaDurability.durable ? "Yes" : "Not yet") : "Pending check"}
                  </span>
                </div>
              </div>
              <div className="infoCardText">
                Media durability is a storage signal, not a second publish button. Your post can be
                created once the media reference is declared, while replication may still continue in
                the background.
              </div>
            </div>

            {uploadInfo ? (
              <div className="feedMediaCard">
                <div className="feedMediaTitle">Upload result</div>
                <div className="feedMediaMeta mono">CID: {String(uploadInfo?.cid || "(missing)")}</div>
                <div className="feedMediaMeta">
                  Pinned on upload: {uploadInfo?.pinned_on_upload ? "yes" : "no"}
                </div>
                {previewGateway ? (
                  <div className="buttonRow" style={{ marginTop: 10 }}>
                    <a className="btn" href={previewGateway} target="_blank" rel="noreferrer">
                      Open gateway preview
                    </a>
                  </div>
                ) : null}
              </div>
            ) : null}

            {mediaDurability ? (
              <details className="detailsPanel" open>
                <summary>Durability status</summary>
                <div className="statusSummary" style={{ marginTop: 8 }}>
                  <span className={`statusPill ${mediaDurability?.durable ? "ok" : ""}`}>
                    {mediaDurability?.durable ? "Durable" : "Pending replication"}
                  </span>
                  <span className="statusPill">
                    RF {Number(mediaDurability?.replication_factor ?? 0)}
                  </span>
                  <span className="statusPill">
                    Ops {Number(mediaDurability?.ok_unique_ops ?? 0)}
                  </span>
                </div>
                <pre className="codePanel mono">{JSON.stringify(mediaDurability, null, 2)}</pre>
              </details>
            ) : null}

            {createdPostId ? (
              <div className="buttonRow buttonRowWide">
                <button
                  className="btn btnPrimary"
                  onClick={() => nav(`/thread/${encodeURIComponent(createdPostId)}`)}
                >
                  Open new thread
                </button>
                <button
                  className="btn"
                  onClick={() => nav(`/content/${encodeURIComponent(createdPostId)}`)}
                >
                  Open content page
                </button>
              </div>
            ) : null}

            {last ? (
              <details className="detailsPanel">
                <summary>Raw submission payload</summary>
                <pre className="codePanel mono">{JSON.stringify(last, null, 2)}</pre>
              </details>
            ) : null}
          </div>
        </article>
      </section>
    </div>
  );
}
