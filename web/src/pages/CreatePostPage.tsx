import React, { useEffect, useMemo, useState } from "react";

import { getApiBaseUrl, weall } from "../api/weall";
import ErrorBanner from "../components/ErrorBanner";
import { getAuthHeaders, getKeypair, getSession, submitSignedTxWithNonce } from "../auth/session";
import { normalizeAccount } from "../auth/keys";
import { useAccount } from "../context/AccountContext";
import { useTxQueue } from "../hooks/useTxQueue";
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

function prettyErr(e: any): { msg: string; details: any } {
  const details = e?.body || e?.data || e;
  const msg = details?.message || e?.message || "error";
  return { msg, details };
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

export default function CreatePostPage(): JSX.Element {
  const base = useMemo(() => getApiBaseUrl(), []);
  const session = getSession();
  const acct = session ? normalizeAccount(session.account) : null;
  const kp = acct ? getKeypair(acct) : null;
  const canSign = !!kp?.secretKeyB64;
  const { refresh: refreshAccountContext } = useAccount();
  const tx = useTxQueue();

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

  const [busy, setBusy] = useState<boolean>(false);
  const [status, setStatus] = useState<string>("");
  const [last, setLast] = useState<any>(null);
  const [createdPostId, setCreatedPostId] = useState<string>("");
  const [uploadInfo, setUploadInfo] = useState<any | null>(null);
  const [mediaDurability, setMediaDurability] = useState<any | null>(null);

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

    const body = text.trim();
    if (!body && !file) {
      setErr({ msg: "Write something or attach a file.", details: null });
      return;
    }

    const tagList = parseTags(tags);

    setBusy(true);
    try {
      const result = await tx.runTx({
        title: "Create post",
        pendingMessage: "Uploading media and preparing your post…",
        successMessage: (res: any) =>
          res?.postId ? `Post created: ${res.postId}` : "Post submitted successfully.",
        errorMessage: (e) => prettyErr(e).msg,
        getTxId: (res: any) => res?.postTxId,
        task: async () => {
          let mediaIds: string[] = [];
          let finalUploadInfo: any | null = null;
          let finalDurability: any | null = null;
          let finalPostId = "";
          let finalPostTxId = "";
          let finalResult: any = null;

          if (file) {
            setStatus("Uploading media");
            const headers = getAuthHeaders(acct);
            const up: any = await weall.mediaUpload(file, base, headers);
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

            if (up?.pin_request_tx?.tx) {
              setStatus("Submitting pin request");
              const pinReqTx = up.pin_request_tx.tx;
              const pinPayload = { ...(pinReqTx.payload || {}) };
              if (typeof pinPayload.ts_ms === "number" && pinPayload.ts_ms === 0) {
                pinPayload.ts_ms = Date.now();
              }
              await submitSignedTxWithNonce({
                account: acct,
                tx_type: String(pinReqTx.tx_type || "IPFS_PIN_REQUEST"),
                payloadFactory: () => pinPayload,
                parent: pinReqTx.parent ?? null,
                base,
              });
            }

            setStatus("Checking durability");
            const durable: any = await waitForMediaDurable(cid, base);
            finalDurability = durable;
            setMediaDurability(durable);

            setStatus("Declaring media");
            const declare: any = await submitSignedTxWithNonce({
              account: acct,
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
            if (declareTxId) await waitForTxConfirmed(base, declareTxId);

            const declaredId = String(declare?.env?.payload?.media_id || "").trim();
            if (!declaredId) throw { message: "media_declare_missing_media_id", data: declare };
            mediaIds = [declaredId];
          }

          setStatus("Submitting post");
          const res: any = await submitSignedTxWithNonce({
            account: acct,
            tx_type: "CONTENT_POST_CREATE",
            payloadFactory: (nonce) => {
              const post_id = deterministicId("post", acct, nonce);
              return {
                post_id,
                body: body || null,
                visibility,
                tags: tagList.length ? tagList : null,
                media: mediaIds.length ? mediaIds : null,
              };
            },
            parent: null,
            base,
          });

          const postTxId = String(res?.result?.tx_id || "").trim();
          if (postTxId) await waitForTxConfirmed(base, postTxId);

          finalPostId = String(res?.env?.payload?.post_id || "").trim();
          finalPostTxId = postTxId;
          finalResult = res;

          return {
            uploadInfo: finalUploadInfo,
            mediaDurability: finalDurability,
            postId: finalPostId,
            postTxId: finalPostTxId,
            result: finalResult,
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

      await refresh();
      await refreshAccountContext();
    } catch (e: any) {
      setStatus("Error");
      setErr(prettyErr(e));
      setLast(e?.body || e?.data || e);
    } finally {
      setBusy(false);
    }
  }

  const tier = snapshot.tier;
  const registered = snapshot.registered;
  const bodyLen = text.trim().length;
  const tagListPreview = parseTags(tags);
  const previewType = file?.type || "";
  const previewGateway = String(uploadInfo?.cid || "").trim()
    ? weall.mediaGatewayUrl(String(uploadInfo.cid), base)
    : "";
  const canPublish = snapshot.canPost && !!(text.trim() || file) && !busy;

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
            ? "Still waiting on replication."
            : "Checked after upload."
        : "No durability check needed.",
    },
    {
      label: "Declare",
      state: uploadInfo && !busy ? "done" : file ? "pending" : "idle",
      detail: file
        ? "Creates a declared media reference before publish."
        : "No media declaration needed.",
    },
    {
      label: "Publish",
      state: createdPostId ? "done" : busy ? "active" : canPublish ? "ready" : "pending",
      detail: createdPostId
        ? createdPostId
        : canPublish
          ? "Ready to sign and submit."
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
    <div className="pageStack pageNarrow">
      <section className="card heroCard">
        <div className="cardBody heroBody compactHero">
          <div className="heroSplit">
            <div>
              <div className="eyebrow">Creator flow</div>
              <h1 className="heroTitle heroTitleSm">Create a post</h1>
              <p className="heroText">
                Compose text, optionally attach media, then let the client walk through upload,
                durability, declaration, and publish. The page now also explains what durable media
                means for this deployment.
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
          </div>
        </div>
      </section>

      <ErrorBanner message={err?.msg} details={err?.details} onRetry={refresh} onDismiss={() => setErr(null)} />

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

            <div className="infoGrid">
              {readinessChecks.map((item) => (
                <div key={item.label} className="infoCard compact">
                  <div className="infoCardHeader">
                    <span className={`statusPill ${item.ok ? "ok" : ""}`}>
                      {item.ok ? "Ready" : "Needs attention"}
                    </span>
                    <strong>{item.label}</strong>
                  </div>
                  <div className="infoCardText">{item.hint}</div>
                </div>
              ))}
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
                Visibility
                <select value={visibility} onChange={(e) => setVisibility(e.target.value as typeof visibility)}>
                  <option value="public">Public</option>
                  <option value="followers" disabled>
                    Followers (soon)
                  </option>
                  <option value="group" disabled>
                    Group (soon)
                  </option>
                  <option value="private" disabled>
                    Private (soon)
                  </option>
                </select>
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

            <label className="uploadZone">
              <span className="uploadTitle">Attachment</span>
              <span className="uploadHint">
                Optional. Images, audio, and video use the upload → durability → declare flow.
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
                {createdPostId ? "Published" : canPublish ? "Ready to publish" : "Draft in progress"}
              </span>
            </div>

            <div className="statusSummary">
              <span className={`statusPill ${tier >= POSTING_MIN_TIER ? "ok" : ""}`}>
                {tier >= POSTING_MIN_TIER ? "Posting unlocked" : `Tier ${POSTING_MIN_TIER} required`}
              </span>
              <span className={`statusPill ${registered ? "ok" : ""}`}>
                {registered ? "Account registered" : "Registration required"}
              </span>
              <span className="statusPill">{visibility}</span>
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
                Media becomes durable when enough operators confirm successful pinning to satisfy the
                current deployment thresholds.
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
