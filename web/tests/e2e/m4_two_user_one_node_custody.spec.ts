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
  expect(txId).toMatch(/^[0-9a-f]{64}$/i);
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
  return submitAndCapture(page, () =>
    page.getByRole("button", { name: "Submit public profile update" }).click());
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
    expect(alphaRecovery.secretKeyB64).not.toBe(betaRecovery.secretKeyB64);

    const [alphaBefore, betaBefore] = await Promise.all([
      storedKeys(alpha, alphaId, betaId),
      storedKeys(beta, betaId, alphaId),
    ]);
    for (const [own, recovery, identity] of [
      [alphaBefore, alphaRecovery, alphaId],
      [betaBefore, betaRecovery, betaId],
    ] as const) {
      expect(own.selfSession).toContain(identity);
      expect(own.selfSecret).toBe(recovery.secretKeyB64);
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

    // Reconcile both UI registration states before signed profile changes.
    for (const page of [alpha, beta]) {
      await page.getByRole("button", { name: "Check registration status" }).click();
      await expect(page.getByTestId("registration-complete")).toContainText("Your basic account is ready.", { timeout: 30_000 });
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
    expect(restoredKeys.selfSecret).toBe(alphaRecovery.secretKeyB64);
    expect(restoredKeys.otherSecret).toBeNull();
    expect(restoredKeys.otherMetadata).toBeNull();

    const betaAfter = await storedKeys(beta, betaId, alphaId);
    expect(betaAfter.selfSession).toContain(betaId);
    expect(betaAfter.selfSecret).toBe(betaRecovery.secretKeyB64);
    expect(betaAfter.otherSecret).toBeNull();
    expect(betaAfter.otherMetadata).toBeNull();
  } finally {
    await Promise.all(contexts.map((context) => context.close()));
  }
});
