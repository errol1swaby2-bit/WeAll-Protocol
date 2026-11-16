import { expect, test, type BrowserContext, type Page, type APIRequestContext } from "@playwright/test";
import { randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";

/**
 * Two independent REAL browser accounts -> one actual local WeAll executor.
 * No API fixtures, dev bootstrap, direct state edits, fabricated confirmations,
 * or disabled signature/authorization checks. A one-node local receipt cannot
 * prove multi-validator BFT or production PoH authority.
 */
const BASE_URL = process.env.PLAYWRIGHT_BASE_URL ?? "http://127.0.0.1:5173";
const REQUIRE_REAL_STACK = process.env.WEALL_REQUIRE_REAL_ACCOUNT_CUSTODY_E2E === "1";

type Recovery = {
  type: "weall_recovery_key";
  version: 2;
  account: string;
  publicKeyB64: string;
  secretKeyB64: string;
  recoveryAuthorityPublicKeyB64: string;
};

async function backendRequired(request: APIRequestContext): Promise<void> {
  try {
    const r = await request.get("/v1/status", { timeout: 8_000 });
    if (r.ok() && (await r.json())?.ok === true) return;
  } catch {
    // The harness must fail, not silently skip, when real-stack proof is required.
  }
  if (REQUIRE_REAL_STACK) throw new Error("m4_real_backend_required");
  test.skip(true, "real backend is not running");
}

async function submitAndCapture(page: Page, click: () => Promise<void>): Promise<string> {
  const seen = page.waitForResponse(
    (response) => response.request().method() === "POST"
      && new URL(response.url()).pathname === "/v1/tx/submit",
    { timeout: 60_000 },
  );
  await click();
  const response = await seen;
  expect(response.ok(), "canonical signed submission must be accepted by the real API").toBe(true);
  const result = await response.json();
  const txId = String(result?.tx_id || result?.result?.tx_id || result?.submit?.tx_id || "");
  // WeAll canonical transaction IDs include the `tx:` domain prefix.
  expect(txId).toMatch(/^tx:[0-9a-f]{64}$/i);
  return txId;
}

async function confirmed(request: APIRequestContext, txId: string): Promise<any> {
  const deadline = Date.now() + 120_000;
  let last: any = null;
  while (Date.now() < deadline) {
    const r = await request.get(`/v1/tx/status/${encodeURIComponent(txId)}`, { timeout: 10_000 });
    if (r.ok()) {
      last = await r.json();
      const status = String(last?.status || "").toLowerCase();
      if (status === "rejected" || status === "failed" || last?.apply_ok === false) {
        throw new Error(`m4_canonical_apply_rejected:${txId}`);
      }
      if (status === "confirmed" && last?.apply_ok === true
        && last?.local_state_synced !== false && Number(last?.height || 0) > 0
        && String(last?.block_id || "")) return last;
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  throw new Error(`m4_canonical_receipt_not_confirmed:${txId}:${String(last?.status || "unknown")}`);
}

async function accountState(request: APIRequestContext, account: string): Promise<any> {
  const path = `/v1/accounts/${encodeURIComponent(account)}`;
  const deadline = Date.now() + 60_000;
  while (Date.now() < deadline) {
    const r = await request.get(path, { timeout: 10_000 });
    if (r.ok()) {
      const body = await r.json();
      if (body?.account === account && body?.state?.active_keys?.length === 1) return body;
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  throw new Error("m4_account_read_model_missing:" + account);
}

async function profileState(request: APIRequestContext, account: string, displayName: string): Promise<any> {
  const path = `/v1/accounts/${encodeURIComponent(account)}/profile`;
  const deadline = Date.now() + 60_000;
  while (Date.now() < deadline) {
    const r = await request.get(path, { timeout: 10_000 });
    if (r.ok()) {
      const body = await r.json();
      if (body?.account === account && body?.profile?.display_name === displayName) return body;
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  throw new Error("m4_profile_read_model_missing:" + account);
}

async function newAccount(page: Page, account: string): Promise<Recovery> {
  await page.goto("/#/login");
  await expect(page.getByTestId("create-account-key-form")).toBeVisible();
  await page.getByLabel("Choose a handle").fill(account);
  await page.getByRole("button", { name: "Create account key" }).click();
  await expect(page.getByTestId("recovery-save-step")).toBeVisible({ timeout: 30_000 });

  // The temporary Playwright download belongs only to this context.
  // Never attach recovery content to public evidence/logs.
  const downloadSeen = page.waitForEvent("download");
  await page.getByRole("button", { name: /Download recovery file/ }).click();
  const download = await downloadSeen;
  const raw = await readFile(await download.path(), "utf8");
  const recovery = JSON.parse(raw) as Recovery;
  expect(recovery.type).toBe("weall_recovery_key");
  expect(recovery.version).toBe(2);
  expect(recovery.account).toBe(account);
  expect(Buffer.from(recovery.secretKeyB64, "base64")).toHaveLength(32);
  expect(Buffer.from(recovery.publicKeyB64, "base64")).toHaveLength(1952);

  await page.getByTestId("verify-created-recovery-json").fill(raw);
  await expect(page.getByTestId("recovery-verification-status")).toContainText("Recovery verified", { timeout: 30_000 });
  await page.getByRole("button", { name: "Continue to network registration" }).click();
  await page.waitForURL(/#\/onboarding\/register$/);
  await expect(page.getByTestId("guided-account-registration")).toBeVisible();
  return recovery;
}

async function profileUpdate(page: Page, account: string, name: string): Promise<string> {
  await page.goto("/#/profile");
  await expect(page.getByText(account).first()).toBeVisible({ timeout: 30_000 });
  await page.getByRole("button", { name: "Edit public profile", exact: true }).click();
  await page.getByLabel("Display name").fill(name);
  const submit = page.getByTestId("profile-submit-action");
  try {
    await expect(submit).toBeEnabled({ timeout: 12_000 });
  } catch {
    // Only nonsecret readiness flags are exposed; never log typed fields,
    // recoveries, signer seeds, signed envelopes, or session bearers.
    const blockers = await submit.getAttribute("data-submit-blockers");
    const accountReadOutcome = await submit.getAttribute("data-account-read-outcome");
    throw new Error("m4_profile_submit_blocked:" + (blockers || "unknown")
      + ":account_read=" + (accountReadOutcome || "unknown"));
  }
  return submitAndCapture(page, () => submit.click());
}

async function storedKeys(page: Page, self: string, other: string): Promise<{
  selfSession: string | null; selfSecret: string | null; otherSecret: string | null;
  otherMetadata: string | null; selfSecretPersisted: string | null;
}> {
  return page.evaluate(({ self, other }) => ({
    selfSession: localStorage.getItem("weall_session_v1"),
    selfSecret: sessionStorage.getItem(`weall_secret::${self}`),
    otherSecret: sessionStorage.getItem(`weall_secret::${other}`),
    otherMetadata: localStorage.getItem(`weall_keypair::${other}`),
    selfSecretPersisted: localStorage.getItem(`weall_secret::${self}`),
  }), { self, other });
}

/**
 * Deliberately invoke WeAll's real browser signing and /v1/tx/submit path,
 * bypassing only the frontend button to verify that the BACKEND rejects
 * ineligible Tier-0 social writes. No test authority or mutated state.
 * A network failure, malformed payload, or missing auth is NOT a valid pass.
 */
async function verifyCanonicalTier0SocialDenial(
  page: Page,
  request: APIRequestContext,
  account: string,
  txType: "CONTENT_POST_CREATE" | "CONTENT_COMMENT_CREATE" | "CONTENT_REACTION_SET" | "CONTENT_FLAG",
  payload: Record<string, string>,
): Promise<void> {
  const outcome = await page.evaluate(async ({ account, txType, payload }) => {
    // Resolved by the dev server's Vite module endpoint; intentionally not
    // bundled into the production frontend.
    // @ts-ignore - Vite dev-only absolute module specifier
    const { submitSignedTx } = await import("/src/auth/session.ts");
    try {
      const result = await submitSignedTx({
        account, tx_type: txType, payload, parent: null,
      });
      return {
        accepted: true,
        id: String(result?.tx_id || result?.result?.tx_id || ""),
        status: 200,
        reason: "",
      };
    } catch (e: any) {
      const payloadError = e?.payload?.error || e?.payload?.detail || {};
      const detail = typeof payloadError === "object" && payloadError !== null ? payloadError : {};
      return {
        accepted: false,
        id: "",
        status: Number(e?.status || 0),
        reason: String(detail?.code || detail?.message || e?.message || "").slice(0, 160),
      };
    }
  }, { account, txType, payload });

  // The generated admission index intentionally permits Tier0 comments so
  // the public lobby can work. For an ordinary comment, the real apply layer
  // MUST reject Tier0; mempool acceptance cannot count as a permission pass.
  if (outcome.accepted) {
    expect(txType, "only the Tier0-admissible comment transaction may reach apply")
      .toBe("CONTENT_COMMENT_CREATE");
    expect(outcome.id).toMatch(/^tx:[0-9a-f]{64}$/i);
    const deadline = Date.now() + 45_000;
    while (Date.now() < deadline) {
      const r = await request.get(`/v1/tx/status/${encodeURIComponent(outcome.id)}`);
      if (r.ok()) {
        const status = await r.json();
        const terminal = String(status?.status || "").toLowerCase();
        if (["rejected", "failed"].includes(terminal)) {
          expect(status.apply_ok, "ordinary Tier0 comment must not apply").toBe(false);
          return;
        }
        if (["confirmed", "committed", "finalized"].includes(terminal)
          && status?.apply_ok === true) {
          throw new Error("m4_tier0_ordinary_comment_illegally_applied");
        }
      }
      await new Promise((resolve) => setTimeout(resolve, 350));
    }
    throw new Error("m4_tier0_ordinary_comment_not_terminally_rejected");
  }

  // Admission denials are valid only when explicitly caused by eligibility.
  // A connectivity error, HTTP 500, nonce conflict or malformed payload
  // must never be mistaken for a successful negative security proof.
  expect([400, 403], txType + " must be rejected by the real backend").toContain(outcome.status);
  // Production mempool admission reports a canonical gate_denied code
  // (rather than putting the Tier2 expression in the top-level error code).
  // Reject generic network errors or unrelated schema/nonce failures.
  expect(outcome.reason, txType + " must fail at the canonical eligibility gate")
    .toMatch(/^(?:gate_denied|insufficient_poh_tier|poh_tier_required)$/i);
}

async function submitRealPublicLobbyComment(
  page: Page,
  account: string,
  threadId: string,
  body: string,
): Promise<{ txId: string; commentId: string; nonce: number }> {
  // Production signing / canonical nonce reservation / actual HTTP submission.
  // No test identity injection, direct state mutation, or bypassed authority.
  const result = await page.evaluate(async ({ account, threadId, body }) => {
    // @ts-ignore - Vite's development-only module URL
    const { submitSignedTxWithNonce } = await import("/src/auth/session.ts");
    const signed = await submitSignedTxWithNonce({
      account,
      tx_type: "CONTENT_COMMENT_CREATE",
      payloadFactory: (nonce: number) => ({
        comment_id: `comment:${account}:${nonce}`,
        post_id: threadId,
        surface: "public_lobby",
        body,
      }),
      parent: null,
    });
    return {
      txId: String(signed?.result?.tx_id || ""),
      commentId: `comment:${account}:${signed.env.nonce}`,
      nonce: Number(signed.env.nonce),
    };
  }, { account, threadId, body });
  expect(result.txId).toMatch(/^tx:[0-9a-f]{64}$/i);
  expect(result.commentId).toMatch(/^comment:@m4[a-b]_[0-9a-f]+:[1-9][0-9]*$/);
  expect(result.nonce).toBeGreaterThan(0);
  return result;
}

async function readPublicLobbyFromBrowser(page: Page, threadId: string): Promise<any> {
  return page.evaluate(async (thread) => {
    // Same-origin API through the Vite node proxy. No bearer is attached.
    // Independent browser contexts share a localhost/IP token bucket. Retry
    // ONLY the safe anonymous GET when the server explicitly returns its 429
    // rate_limited envelope; do not retry signed writes or weaken the limiter.
    const url = `/v1/public-lobby/comments?thread_id=${encodeURIComponent(thread)}&limit=20`;
    for (let attempt = 0; attempt < 8; attempt += 1) {
      const response = await fetch(url, { method: "GET", credentials: "omit" });
      const json = await response.json();
      if (response.status !== 429 || json?.error?.code !== "rate_limited" || attempt === 7) {
        return { status: response.status, json, rateLimitRetries: attempt };
      }
      await new Promise<void>((resolve) => window.setTimeout(resolve, 1_250));
    }
    throw new Error("public-lobby read exhausted a bounded retry without a response");
  }, threadId);
}

async function verifyRealTier0PublicLobbyConversation(args: {
  alpha: Page;
  beta: Page;
  observer: Page;
  request: APIRequestContext;
  alphaId: string;
  betaId: string;
  suffix: string;
}): Promise<void> {
  const { alpha, beta, observer, request, alphaId, betaId, suffix } = args;
  const threadId = `public-lobby:m4-${suffix}`;
  const alphaBody = `Welcome from independent Tier 0 account alpha ${suffix}`;
  const betaBody = `Reply from independent Tier 0 account beta ${suffix}`;

  const [a, b] = await Promise.all([
    submitRealPublicLobbyComment(alpha, alphaId, threadId, alphaBody),
    submitRealPublicLobbyComment(beta, betaId, threadId, betaBody),
  ]);
  expect(a.txId).not.toBe(b.txId);
  expect(a.commentId).not.toBe(b.commentId);

  const [aReceipt, bReceipt] = await Promise.all([
    confirmed(request, a.txId),
    confirmed(request, b.txId),
  ]);
  for (const receipt of [aReceipt, bReceipt]) {
    expect(receipt.status).toBe("confirmed");
    expect(receipt.apply_ok).toBe(true);
    expect(Number(receipt.height)).toBeGreaterThan(0);
    expect(String(receipt.block_id)).toBeTruthy();
  }

  // The public-lobby root is synthetic; no Tier-2 parent post was injected.
  const parent = await request.get(`/v1/content/${encodeURIComponent(threadId)}`);
  expect(parent.status()).toBe(404);

  const ids = [a.commentId, b.commentId].sort();
  for (const [id, author, expectedBody] of [
    [a.commentId, alphaId, alphaBody],
    [b.commentId, betaId, betaBody],
  ] as const) {
    const r = await request.get(`/v1/content/${encodeURIComponent(id)}`);
    expect(r.ok()).toBe(true);
    const json = await r.json();
    expect(json.type).toBe("comment");
    expect(json.content?.comment_id).toBe(id);
    expect(json.content?.author).toBe(author);
    expect(json.content?.body).toBe(expectedBody);
    expect(json.content?.surface).toBe("public_lobby");
    expect(json.content?.post_id).toBe(threadId);
  }

  // The list is bounded and deterministic, with no authenticated session.
  const list = await request.get("/v1/public-lobby/comments", {
    params: { thread_id: threadId, limit: 20 },
  });
  expect(list.ok()).toBe(true);
  const data = await list.json();
  expect(data.ok).toBe(true);
  expect(data.thread_id).toBe(threadId);
  expect(data.next_cursor).toBeNull();
  expect(data.items).toHaveLength(2);
  expect(data.items.map((x: any) => String(x.comment_id)).sort()).toEqual(ids);
  expect(data.items.map((x: any) => String(x.author)).sort()).toEqual([alphaId, betaId].sort());

  const first = await request.get("/v1/public-lobby/comments", {
    params: { thread_id: threadId, limit: 1 },
  });
  expect(first.ok()).toBe(true);
  const firstJson = await first.json();
  expect(firstJson.items).toHaveLength(1);
  expect(firstJson.next_cursor).toBeTruthy();
  const second = await request.get("/v1/public-lobby/comments", {
    params: { thread_id: threadId, limit: 1, cursor: firstJson.next_cursor },
  });
  expect(second.ok()).toBe(true);
  const secondJson = await second.json();
  expect(secondJson.items).toHaveLength(1);
  expect(secondJson.next_cursor).toBeNull();
  expect([firstJson.items[0].comment_id, secondJson.items[0].comment_id].sort()).toEqual(ids);

  for (const page of [alpha, beta, observer]) {
    await page.goto("/#/feed");
    await expect(page.getByTestId("public-social-boundary-callout")).toBeVisible();
    const publicRead = await readPublicLobbyFromBrowser(page, threadId);
    expect(publicRead.status).toBe(200);
    expect(publicRead.rateLimitRetries).toBeLessThanOrEqual(7);
    expect(publicRead.json.items.map((x: any) => String(x.comment_id)).sort()).toEqual(ids);
  }

  // Reject a malicious attempt to label an ordinary target as the Tier-0
  // lobby. A submitted transaction is not proof of apply; the canonical
  // terminal receipt must reject it, as the previous M4.2 negative test does.
  const invalid = await beta.evaluate(async ({ account }) => {
    // @ts-ignore - Vite development-only module URL
    const { submitSignedTxWithNonce } = await import("/src/auth/session.ts");
    const submitted = await submitSignedTxWithNonce({
      account,
      tx_type: "CONTENT_COMMENT_CREATE",
      payloadFactory: (nonce: number) => ({
        comment_id: `invalid-lobby:${account}:${nonce}`,
        post_id: "ordinary-post",
        surface: "public_lobby",
        body: "Must fail synthetic-target validation",
      }),
      parent: null,
    });
    return String(submitted?.result?.tx_id || "");
  }, { account: betaId });
  expect(invalid).toMatch(/^tx:[0-9a-f]{64}$/i);
  const invalidDeadline = Date.now() + 45_000;
  let rejected = false;
  while (Date.now() < invalidDeadline) {
    const r = await request.get(`/v1/tx/status/${encodeURIComponent(invalid)}`);
    if (r.ok()) {
      const status = await r.json();
      if (status?.status === "rejected" && status.apply_ok === false) {
        expect(String(status.reason || "")).toMatch(/invalid_public_lobby_target/);
        rejected = true;
        break;
      }
      if (status?.status === "confirmed" && status.apply_ok === true) {
        throw new Error("m4_invalid_lobby_target_illegally_applied");
      }
    }
    await new Promise((resolve) => setTimeout(resolve, 300));
  }
  expect(rejected, "wrong-target lobby bypass must terminate as an apply rejection").toBe(true);

  const after = await request.get("/v1/public-lobby/comments", {
    params: { thread_id: threadId, limit: 20 },
  });
  expect(after.ok()).toBe(true);
  expect((await after.json()).items).toEqual(data.items);
}

test("two independent real users register, update public profiles and isolate keys on one node", async ({ browser, request }) => {
  test.setTimeout(420_000);
  await backendRequired(request);

  const suffix = randomBytes(5).toString("hex");
  const alphaId = `@m4a_${suffix}`;
  const betaId = `@m4b_${suffix}`;
  const alphaName = `M4 alpha ${suffix}`;
  const betaName = `M4 beta ${suffix}`;
  const contexts: BrowserContext[] = [];
  const makeContext = async () => {
    const context = await browser.newContext({ baseURL: BASE_URL, acceptDownloads: true });
    contexts.push(context);
    return context;
  };
  try {
    const alpha = await (await makeContext()).newPage();
    const beta = await (await makeContext()).newPage();

    // Real ML-DSA signing seeds are independently generated in separate
    // browser contexts, never injected via dev/bootstrap state.
    const [alphaRecovery, betaRecovery] = await Promise.all([
      newAccount(alpha, alphaId),
      newAccount(beta, betaId),
    ]);
    expect(alphaRecovery.publicKeyB64).not.toBe(betaRecovery.publicKeyB64);
    expect(alphaRecovery.secretKeyB64 !== betaRecovery.secretKeyB64).toBe(true);

    const [alphaBefore, betaBefore] = await Promise.all([
      storedKeys(alpha, alphaId, betaId),
      storedKeys(beta, betaId, alphaId),
    ]);
    for (const [own, recovery, identity] of [
      [alphaBefore, alphaRecovery, alphaId],
      [betaBefore, betaRecovery, betaId],
    ] as const) {
      expect(own.selfSession).toContain(identity);
      expect(own.selfSecret === recovery.secretKeyB64).toBe(true);
      expect(own.otherSecret).toBeNull();
      expect(own.otherMetadata).toBeNull();
      expect(own.selfSecretPersisted).toBeNull();
    }

    // Independent nonces/keys, same backend ledger, genuine signed requests.
    const [alphaTx, betaTx] = await Promise.all([
      submitAndCapture(alpha, () => alpha.getByTestId("submit-basic-registration").click()),
      submitAndCapture(beta, () => beta.getByTestId("submit-basic-registration").click()),
    ]);
    expect(alphaTx).not.toBe(betaTx);
    const [alphaReceipt, betaReceipt] = await Promise.all([
      confirmed(request, alphaTx), confirmed(request, betaTx),
    ]);
    for (const receipt of [alphaReceipt, betaReceipt]) {
      expect(receipt.apply_ok).toBe(true);
      expect(String(receipt.block_id)).toBeTruthy();
    }

    const [alphaState, betaState] = await Promise.all([
      accountState(request, alphaId), accountState(request, betaId),
    ]);
    const expectedKey = (r: Recovery) => Buffer.from(r.publicKeyB64, "base64").toString("hex");
    expect(alphaState.state.active_keys).toEqual([expectedKey(alphaRecovery)]);
    expect(betaState.state.active_keys).toEqual([expectedKey(betaRecovery)]);
    expect(alphaState.state.active_keys).not.toEqual(betaState.state.active_keys);
    expect(alphaState.state.recovery.offline_key.pubkey).toBe(
      Buffer.from(alphaRecovery.recoveryAuthorityPublicKeyB64, "base64").toString("hex"),
    );
    expect(betaState.state.recovery.offline_key.pubkey).toBe(
      Buffer.from(betaRecovery.recoveryAuthorityPublicKeyB64, "base64").toString("hex"),
    );

    // The post-registration local session has no canonical backend bearer.
    // Activate each device through the real signed, receipt-checked session
    // issuance flow before protected profile actions (not a test-only login).
    for (const page of [alpha, beta]) {
      await page.getByRole("button", { name: "Check registration status" }).click();
      await expect(page.getByTestId("registration-complete")).toContainText(
        "Your basic account is ready.", { timeout: 30_000 },
      );
      const activate = page.getByTestId("activate-registered-account-session");
      await expect(activate).toBeEnabled();
      await activate.click();
      await expect(page.getByTestId("registered-account-session-ready")).toBeVisible({
        timeout: 90_000,
      });
      await expect(page.getByRole("button", { name: "Continue to human verification" })).toBeEnabled();
    }
    if (process.env.WEALL_M4_LOBBY_POSITIVE === "1") {
      const [a, b] = await Promise.all([
        accountState(request, alphaId), accountState(request, betaId),
      ]);
      expect(Number(a.state.poh_tier)).toBe(0);
      expect(Number(b.state.poh_tier)).toBe(0);
      const observer = await (await makeContext()).newPage();
      await verifyRealTier0PublicLobbyConversation({
        alpha, beta, observer, request, alphaId, betaId, suffix,
      });
      return;
    }
    if (process.env.WEALL_M4_SOCIAL_PROBES === "1") {
      // M4.2 uses the proven M4.1 two-user identity and session setup, with
      // neither fake PoH elevation nor an independently verified BFT quorum.
      // Tier0 users MUST NOT submit post, ordinary comment, reaction, or flag.
      const [freshAlpha, freshBeta] = await Promise.all([
        accountState(request, alphaId),
        accountState(request, betaId),
      ]);
      expect(Number(freshAlpha.state.poh_tier)).toBe(0);
      expect(Number(freshBeta.state.poh_tier)).toBe(0);

      const feedBeforeResponse = await request.get("/v1/feed?limit=20");
      expect(feedBeforeResponse.ok()).toBe(true);
      const feedBefore = await feedBeforeResponse.json();
      expect(Array.isArray(feedBefore.items)).toBe(true);

      await verifyCanonicalTier0SocialDenial(
        beta, request, betaId, "CONTENT_POST_CREATE",
        { post_id: `m4:denied:${suffix}`, body: "Tier0 must not publish ordinary posts." },
      );
      await verifyCanonicalTier0SocialDenial(
        alpha, request, alphaId, "CONTENT_REACTION_SET",
        { target_id: `m4:nonexistent:${suffix}`, reaction: "like" },
      );
      await verifyCanonicalTier0SocialDenial(
        beta, request, betaId, "CONTENT_COMMENT_CREATE",
        { post_id: `m4:nonexistent:${suffix}`, body: "Tier0 must not reply to ordinary posts." },
      );
      await verifyCanonicalTier0SocialDenial(
        alpha, request, alphaId, "CONTENT_FLAG",
        { target_id: `m4:nonexistent:${suffix}`, reason: "Tier0 cannot report content." },
      );

      const feedAfterResponse = await request.get("/v1/feed?limit=20");
      expect(feedAfterResponse.ok()).toBe(true);
      const feedAfter = await feedAfterResponse.json();
      expect(feedAfter.items).toEqual(feedBefore.items);

      // Both user browsers can still view the same public social surface.
      await Promise.all([alpha.goto("/#/feed"), beta.goto("/#/feed")]);
      await Promise.all([
        expect(alpha.getByTestId("public-social-boundary-callout")).toBeVisible(),
        expect(beta.getByTestId("public-social-boundary-callout")).toBeVisible(),
      ]);
      // A completely anonymous third browser is allowed the same public read.
      const observer = await (await makeContext()).newPage();
      await observer.goto("/#/feed");
      await expect(observer.getByTestId("public-social-boundary-callout")).toBeVisible();
      return; // Focused M4.2: M4.1 profile/recovery stays in its own green workflow.
    }

    const [alphaProfileTx, betaProfileTx] = await Promise.all([
      profileUpdate(alpha, alphaId, alphaName),
      profileUpdate(beta, betaId, betaName),
    ]);
    await Promise.all([confirmed(request, alphaProfileTx), confirmed(request, betaProfileTx)]);
    const [alphaProfile, betaProfile] = await Promise.all([
      profileState(request, alphaId, alphaName),
      profileState(request, betaId, betaName),
    ]);
    expect(alphaProfile.profile.display_name).toBe(alphaName);
    expect(betaProfile.profile.display_name).toBe(betaName);

    // A new independent browser sees both canonical public read-models, but
    // has neither account's local signer, bearer nor recovery authority.
    const observer = await (await makeContext()).newPage();
    await observer.goto("/#/login");
    for (const id of [alphaId, betaId]) {
      const isolated = await storedKeys(observer, id, id === alphaId ? betaId : alphaId);
      expect(isolated.selfSession).toBeNull();
      expect(isolated.selfSecret).toBeNull();
      expect(isolated.otherSecret).toBeNull();
      expect(isolated.otherMetadata).toBeNull();
    }
    expect((await profileState(observer.request, alphaId, alphaName)).profile.display_name).toBe(alphaName);
    expect((await profileState(observer.request, betaId, betaName)).profile.display_name).toBe(betaName);

    // Recover only alpha in a freshly isolated browser. Beta's keys cannot
    // appear there, while beta's original page remains signed in as beta.
    const restored = await (await makeContext()).newPage();
    await restored.goto("/#/login");
    await restored.getByRole("button", { name: "Sign in", exact: true }).first().click();
    const form = restored.getByTestId("restore-account-form");
    await expect(form).toBeVisible();
    await form.getByLabel("Handle").fill(alphaId);
    await restored.getByTestId("restore-recovery-file").setInputFiles({
      name: "m4-alpha-recovery.json",
      mimeType: "application/json",
      buffer: Buffer.from(JSON.stringify(alphaRecovery)),
    });
    await form.getByRole("button", { name: "Sign in", exact: true }).click();
    await restored.waitForURL(/#\/home$/, { timeout: 120_000 });
    const restoredKeys = await storedKeys(restored, alphaId, betaId);
    expect(restoredKeys.selfSession).toContain(alphaId);
    expect(restoredKeys.selfSecret === alphaRecovery.secretKeyB64).toBe(true);
    expect(restoredKeys.otherSecret).toBeNull();
    expect(restoredKeys.otherMetadata).toBeNull();

    const betaAfter = await storedKeys(beta, betaId, alphaId);
    expect(betaAfter.selfSession).toContain(betaId);
    expect(betaAfter.selfSecret === betaRecovery.secretKeyB64).toBe(true);
    expect(betaAfter.otherSecret).toBeNull();
    expect(betaAfter.otherMetadata).toBeNull();

  } finally {
    await Promise.all(contexts.map((context) => context.close().catch(() => undefined)));
  }
});
