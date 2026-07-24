import fs from "node:fs";
import path from "node:path";
import { APIRequestContext, Browser, BrowserContext, Page, expect } from "@playwright/test";

export type M2Actor = {
  account: string;
  role?: string;
  recovery: Record<string, unknown>;
};

export type M2ActorManifest = {
  schema_version: number;
  kind: "async" | "live";
  api_base: string;
  case_id: string;
  applicant: M2Actor;
  reviewers: M2Actor[];
};

const DEFAULT_M2_BROWSER_JOURNEY_TIMEOUT_MS = 600_000;
const DEFAULT_M2_LOCAL_MEDIA_TIMEOUT_MS = 120_000;

export function m2BrowserJourneyTimeoutMs(): number {
  const parsed = Number(process.env.WEALL_M2_BROWSER_TIMEOUT_MS || DEFAULT_M2_BROWSER_JOURNEY_TIMEOUT_MS);
  if (!Number.isFinite(parsed)) return DEFAULT_M2_BROWSER_JOURNEY_TIMEOUT_MS;
  return Math.max(180_000, Math.floor(parsed));
}

export function m2LocalMediaTimeoutMs(): number {
  const parsed = Number(process.env.WEALL_M2_LOCAL_MEDIA_TIMEOUT_MS || DEFAULT_M2_LOCAL_MEDIA_TIMEOUT_MS);
  if (!Number.isFinite(parsed)) return DEFAULT_M2_LOCAL_MEDIA_TIMEOUT_MS;
  return Math.max(30_000, Math.floor(parsed));
}

export async function waitForLiveLocalMedia(page: Page, actorLabel: string): Promise<void> {
  const timeoutMs = m2LocalMediaTimeoutMs();
  try {
    await expect.poll(
      async () => page.getByTestId("live-local-video").evaluate((node: HTMLVideoElement) => Boolean(node.srcObject)).catch(() => false),
      { timeout: timeoutMs, message: `${actorLabel} local media should become available after live-room check-in` },
    ).toBe(true);
  } catch (error) {
    const status = await page.getByTestId("live-p2p-status").textContent().catch(() => "");
    const roomError = await page.locator(".errorText").last().textContent().catch(() => "");
    throw new Error(
      `${actorLabel} local media did not become ready within ${timeoutMs}ms; status=${String(status || "").trim() || "unknown"}; error=${String(roomError || "").trim() || "none"}; cause=${String(error)}`,
    );
  }
}

export function loadM2ActorManifest(expectedKind: "async" | "live"): M2ActorManifest {
  const rawPath = String(process.env.WEALL_M2_ACTOR_MANIFEST || "").trim();
  if (!rawPath) throw new Error("WEALL_M2_ACTOR_MANIFEST is required for the mandatory M2 browser journey");
  const resolved = path.resolve(rawPath);
  const value = JSON.parse(fs.readFileSync(resolved, "utf8"));
  if (!value || value.kind !== expectedKind || !value.api_base || !value.case_id) {
    throw new Error(`invalid M2 ${expectedKind} actor manifest: ${resolved}`);
  }
  if (!value.applicant?.account || !Array.isArray(value.reviewers) || value.reviewers.length < 1) {
    throw new Error(`M2 ${expectedKind} actor manifest has no applicant or reviewers: ${resolved}`);
  }
  return value as M2ActorManifest;
}

export async function createActorContext(browser: Browser, baseURL: string, actor: M2Actor, apiBase: string): Promise<{ context: BrowserContext; page: Page }> {
  const context = await browser.newContext({ baseURL, permissions: ["camera", "microphone"] });
  const page = await context.newPage();
  await page.goto("/");
  await page.evaluate(async ({ actorValue, apiBaseValue }) => {
    const recoveryModule = await import("/src/auth/recoveryFile.ts");
    const keysModule = await import("/src/auth/keys.ts");
    const evidenceModule = await import("/src/auth/evidenceCrypto.ts");
    const sessionModule = await import("/src/auth/session.ts");
    const recovery = recoveryModule.parseRecoveryKeyFileText(JSON.stringify(actorValue.recovery));
    keysModule.saveKeypair(recovery.account, {
      pubkeyB64: recovery.publicKeyB64,
      secretKeyB64: recovery.secretKeyB64,
    });
    if (recovery.recoveryAuthorityPublicKeyB64 && recovery.recoveryAuthoritySecretKeyB64) {
      keysModule.saveRecoveryAuthorityKeypair(recovery.account, {
        pubkeyB64: recovery.recoveryAuthorityPublicKeyB64,
        secretKeyB64: recovery.recoveryAuthoritySecretKeyB64,
      });
    }
    if (recovery.evidenceKemPublicKeyB64 && recovery.evidenceKemSecretKeyB64) {
      evidenceModule.saveEvidenceKemKeypair(recovery.account, {
        publicKeyB64: recovery.evidenceKemPublicKeyB64,
        secretKeyB64: recovery.evidenceKemSecretKeyB64,
      });
    }
    await sessionModule.loginOnThisDevice({ account: recovery.account, ttlSeconds: 60 * 60, base: apiBaseValue });
  }, { actorValue: actor, apiBaseValue: apiBase });
  const stored = await page.evaluate(() => JSON.parse(localStorage.getItem("weall_session_v1") || "{}"));
  expect(stored.account).toBe(actor.account);
  expect(String(stored.sessionKey || "")).not.toBe("");
  return { context, page };
}

export async function submitSkeleton(page: Page, apiBase: string, account: string, method: string, payload: Record<string, unknown>): Promise<string> {
  return page.evaluate(async ({ apiBaseValue, accountValue, methodValue, payloadValue }) => {
    const apiModule = await import("/src/api/weall.ts");
    const sessionModule = await import("/src/auth/session.ts");
    const api: any = apiModule.weall;
    const factory = api[methodValue];
    if (typeof factory !== "function") throw new Error(`unknown skeleton method: ${methodValue}`);
    const headers = sessionModule.getAuthHeaders(accountValue);
    const skeleton = await factory(payloadValue, apiBaseValue, headers);
    const tx = skeleton?.tx;
    if (!tx?.tx_type || !tx?.payload) throw new Error(`invalid skeleton from ${methodValue}: ${JSON.stringify(skeleton)}`);
    const result = await sessionModule.submitSignedTx({
      account: accountValue,
      tx_type: tx.tx_type,
      payload: tx.payload,
      parent: tx.parent ?? null,
      base: apiBaseValue,
      headers,
    });
    const txId = String(result?.tx_id || "").trim();
    if (!txId) throw new Error(`submission did not return tx_id: ${JSON.stringify(result)}`);
    return txId;
  }, { apiBaseValue: apiBase, accountValue: account, methodValue: method, payloadValue: payload });
}

export async function submitDirect(page: Page, apiBase: string, account: string, txType: string, payload: Record<string, unknown>): Promise<string> {
  return page.evaluate(async ({ apiBaseValue, accountValue, txTypeValue, payloadValue }) => {
    const sessionModule = await import("/src/auth/session.ts");
    const result = await sessionModule.submitSignedTx({
      account: accountValue,
      tx_type: txTypeValue,
      payload: payloadValue,
      base: apiBaseValue,
      headers: sessionModule.getAuthHeaders(accountValue),
    });
    const txId = String(result?.tx_id || "").trim();
    if (!txId) throw new Error(`submission did not return tx_id: ${JSON.stringify(result)}`);
    return txId;
  }, { apiBaseValue: apiBase, accountValue: account, txTypeValue: txType, payloadValue: payload });
}

export async function waitForConfirmed(request: APIRequestContext, apiBase: string, txId: string, timeoutMs = 120_000): Promise<Record<string, unknown>> {
  const deadline = Date.now() + timeoutMs;
  let last: any = null;
  while (Date.now() < deadline) {
    const response = await request.get(`${apiBase}/v1/tx/status/${encodeURIComponent(txId)}`);
    last = await response.json();
    const status = String(last?.status || "").toLowerCase();
    if (status === "confirmed") return last;
    if (["invalid", "rejected", "failed"].includes(status)) throw new Error(`transaction ${txId} failed: ${JSON.stringify(last)}`);
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  throw new Error(`transaction ${txId} did not confirm: ${JSON.stringify(last)}`);
}

export async function waitForTier(request: APIRequestContext, apiBase: string, account: string, tier: number, timeoutMs = 180_000): Promise<Record<string, unknown>> {
  const deadline = Date.now() + timeoutMs;
  let last: any = null;
  while (Date.now() < deadline) {
    const response = await request.get(`${apiBase}/v1/accounts/${encodeURIComponent(account)}`);
    const body = await response.json();
    last = body?.state || body?.account?.state || {};
    if (Number(last?.poh_tier || 0) >= tier) return last;
    await new Promise((resolve) => setTimeout(resolve, 750));
  }
  throw new Error(`${account} did not reach Tier ${tier}: ${JSON.stringify(last)}`);
}

export async function waitForAsyncCase(
  request: APIRequestContext,
  apiBase: string,
  caseId: string,
  predicate: (record: Record<string, any>) => boolean,
  timeoutMs = 120_000,
): Promise<Record<string, any>> {
  const deadline = Date.now() + timeoutMs;
  let last: Record<string, any> = {};
  while (Date.now() < deadline) {
    const response = await request.get(`${apiBase}/v1/poh/async/case/${encodeURIComponent(caseId)}`);
    const body = await response.json();
    last = (body?.case && typeof body.case === "object") ? body.case : {};
    if (predicate(last)) return last;
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  throw new Error(`async case ${caseId} did not reach expected state: ${JSON.stringify(last)}`);
}

export async function submitEncryptedAsyncFollowup(args: {
  page: Page;
  apiBase: string;
  caseId: string;
  applicant: string;
  recipients: string[];
}): Promise<{ evidenceId: string; declareTxId: string; bindTxId: string; ciphertextCid: string }> {
  return args.page.evaluate(async ({ apiBaseValue, caseIdValue, applicantValue, recipientValues }) => {
    const apiModule = await import("/src/api/weall.ts");
    const keysModule = await import("/src/auth/keys.ts");
    const sessionModule = await import("/src/auth/session.ts");
    const evidenceModule = await import("/src/auth/evidenceCrypto.ts");

    const applicant = keysModule.normalizeAccount(applicantValue);
    const recipients = Array.from(new Set([applicant, ...recipientValues.map((value) => keysModule.normalizeAccount(value))].filter(Boolean)));
    const context = `weall:poh-evidence:v1:${String(caseIdValue || "").trim()}:${applicant}`;
    const plaintext = new Blob([`M2 encrypted evidence ${caseIdValue} ${Date.now()}`], { type: "video/webm" });
    const encrypted = await evidenceModule.encryptEvidenceBlob({
      blob: plaintext,
      filename: "m2-followup.webm",
      context,
    });

    const authHeaders = sessionModule.getAuthHeaders(applicant);
    const uploadHeaders = {
      ...authHeaders,
      "x-weall-evidence-encryption": "aes-256-gcm",
      "x-weall-evidence-context-commitment": encrypted.encryptionContextCommitment,
      "x-weall-evidence-ciphertext-commitment": encrypted.ciphertextCommitment,
    };
    const upload = await apiModule.weall.pohAsyncVideoUpload(encrypted.file, apiBaseValue, uploadHeaders);
    const cid = String(upload?.cid || "").trim();
    const providerId = String(upload?.provider_id || "").trim();
    if (!cid || !providerId) throw new Error(`invalid encrypted upload response: ${JSON.stringify(upload)}`);

    const keyEnvelopeCommitments: Record<string, unknown> = {};
    for (const recipient of recipients) {
      const response = await fetch(`${apiBaseValue}/v1/accounts/${encodeURIComponent(recipient)}`, {
        method: "GET",
        headers: authHeaders,
        cache: "no-store",
      });
      if (!response.ok) throw new Error(`account lookup failed for ${recipient}: HTTP ${response.status}`);
      const body = await response.json();
      const publicKeyB64 = String(body?.state?.evidence_encryption?.public_key || "").trim();
      if (!publicKeyB64) throw new Error(`missing ML-KEM evidence public key for ${recipient}`);
      keyEnvelopeCommitments[recipient] = await evidenceModule.wrapEvidenceKeyForRecipient({
        contentKey: encrypted.contentKey,
        recipientPublicKeyB64: publicKeyB64,
        context: `${context}:${recipient}`,
      });
    }

    const sequence = await sessionModule.beginNonceSequence(applicant, apiBaseValue);
    const evidenceId = `m2-encrypted-followup:${Date.now()}:${Math.random().toString(16).slice(2)}`;
    const declared = await sessionModule.submitSignedTxInSequence({
      sequence,
      tx_type: "POH_ASYNC_EVIDENCE_DECLARE",
      payloadFactory: () => ({
        case_id: caseIdValue,
        evidence_id: evidenceId,
        encrypted: true,
        encryption_algorithm: "aes-256-gcm",
        ciphertext_cid: cid,
        ciphertext_commitment: encrypted.ciphertextCommitment,
        encryption_context_commitment: encrypted.encryptionContextCommitment,
        provider_ids: [providerId],
        ciphertext_size: Number(upload?.size || encrypted.file.size),
        filename: "m2-followup.webm",
        kind: "encrypted_browser_followup_v1",
        ts_ms: 0,
      }),
      base: apiBaseValue,
      headers: authHeaders,
    });
    const bound = await sessionModule.submitSignedTxInSequence({
      sequence,
      tx_type: "POH_ASYNC_EVIDENCE_BIND",
      payloadFactory: () => ({
        case_id: caseIdValue,
        evidence_id: evidenceId,
        target_id: caseIdValue,
        key_envelope_commitments: keyEnvelopeCommitments,
        evidence_root_commitment: encrypted.ciphertextCommitment,
        followup_round: 1,
        ts_ms: 0,
      }),
      base: apiBaseValue,
      headers: authHeaders,
    });
    const declareTxId = String(declared?.result?.tx_id || "").trim();
    const bindTxId = String(bound?.result?.tx_id || "").trim();
    if (!declareTxId || !bindTxId) throw new Error("encrypted evidence transactions did not return tx IDs");
    return { evidenceId, declareTxId, bindTxId, ciphertextCid: cid };
  }, {
    apiBaseValue: args.apiBase,
    caseIdValue: args.caseId,
    applicantValue: args.applicant,
    recipientValues: args.recipients,
  });
}
