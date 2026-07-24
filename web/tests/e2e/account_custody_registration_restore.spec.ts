import { expect, test, type APIRequestContext, type BrowserContext, type Page, type Response } from "@playwright/test";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const REQUIRE_REAL_STACK = process.env.WEALL_REQUIRE_REAL_ACCOUNT_CUSTODY_E2E === "1";
const BASE_URL = process.env.PLAYWRIGHT_BASE_URL ?? "http://127.0.0.1:5173";
const TERMINAL_SUCCESS = new Set(["confirmed", "committed", "finalized"]);
const TERMINAL_FAILURE = new Set(["rejected", "failed"]);

type RecoveryFileV2 = {
  type: "weall_recovery_key";
  version: 2;
  sigProfile: "pq-mldsa-v1";
  algorithm: "ML-DSA";
  parameterSet: "ML-DSA-65";
  secretKeyFormat: "mldsa65-seed-b64";
  account: string;
  publicKeyB64: string;
  secretKeyB64: string;
  recoveryAuthorityPublicKeyB64: string;
  recoveryAuthoritySecretKeyB64: string;
  evidenceKemPublicKeyB64: string;
  evidenceKemSecretKeyB64: string;
};

function extractTxId(value: unknown, depth = 0): string {
  if (depth > 5 || value == null) return "";
  if (typeof value === "string") return value.trim();
  if (Array.isArray(value)) {
    for (const item of value) {
      const found = extractTxId(item, depth + 1);
      if (found) return found;
    }
    return "";
  }
  if (typeof value !== "object") return "";
  const record = value as Record<string, unknown>;
  for (const key of ["tx_id", "txId", "existing_tx_id", "existingTxId"]) {
    const found = extractTxId(record[key], depth + 1);
    if (found) return found;
  }
  for (const key of ["result", "submit", "data", "payload", "body", "response"]) {
    const found = extractTxId(record[key], depth + 1);
    if (found) return found;
  }
  return "";
}

function mutateB64(value: string): string {
  const text = String(value || "");
  if (!text) return text;
  const first = text[0] === "A" ? "B" : "A";
  return `${first}${text.slice(1)}`;
}

function assertSingleCanonicalAccountKey(body: any, publicKeyB64: string): void {
  const state = body?.state || {};
  expect(state?.pubkey).toBe(publicKeyB64);
  expect(state?.pubkeys).toEqual([publicKeyB64]);
  expect(state?.active_keys).toEqual([publicKeyB64]);
  const byId = state?.keys?.by_id || {};
  expect(Object.keys(byId)).toHaveLength(1);
  expect(JSON.stringify(byId)).toContain(publicKeyB64);
}

async function requireBackend(request: APIRequestContext): Promise<void> {
  let detail = "";
  try {
    const response = await request.get("/v1/status", { timeout: 10_000 });
    if (response.ok()) return;
    detail = `real backend returned HTTP ${response.status()} at /v1/status`;
  } catch (error) {
    detail = `real WeAll backend is unavailable: ${String((error as Error)?.message || error)}`;
  }

  if (REQUIRE_REAL_STACK) throw new Error(detail);
  test.skip(true, detail);
}

async function captureSubmittedTx(page: Page, click: () => Promise<void>): Promise<string> {
  const responsePromise = page.waitForResponse(
    (response: Response) =>
      response.request().method() === "POST"
      && new URL(response.url()).pathname.endsWith("/v1/tx/submit"),
    { timeout: 60_000 },
  );
  await click();
  const response = await responsePromise;
  expect(response.ok(), `transaction submission failed with HTTP ${response.status()}`).toBeTruthy();
  const body = await response.json();
  const txId = extractTxId(body);
  expect(txId, `transaction response did not contain a tx id: ${JSON.stringify(body)}`).not.toBe("");
  return txId;
}

async function waitForConfirmedTx(request: APIRequestContext, txId: string, timeoutMs = 120_000): Promise<any> {
  const started = Date.now();
  let last: any = null;
  while (Date.now() - started < timeoutMs) {
    const response = await request.get(`/v1/tx/status/${encodeURIComponent(txId)}`, { timeout: 10_000 });
    if (response.ok()) {
      last = await response.json();
      const status = String(last?.status || last?.phase || "").trim().toLowerCase();
      if (TERMINAL_FAILURE.has(status)) {
        throw new Error(`transaction ${txId} reached terminal failure: ${JSON.stringify(last)}`);
      }
      if (TERMINAL_SUCCESS.has(status) && last?.local_state_synced !== false) return last;
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  throw new Error(`transaction ${txId} did not reach confirmed local state: ${JSON.stringify(last)}`);
}

async function getJson(request: APIRequestContext, path: string): Promise<any> {
  const response = await request.get(path, { timeout: 10_000 });
  expect(response.ok(), `${path} returned HTTP ${response.status()}`).toBeTruthy();
  return response.json();
}

async function pollJson(
  request: APIRequestContext,
  path: string,
  predicate: (body: any) => boolean,
  timeoutMs = 60_000,
): Promise<any> {
  const started = Date.now();
  let last: any = null;
  while (Date.now() - started < timeoutMs) {
    try {
      last = await getJson(request, path);
      if (predicate(last)) return last;
    } catch {
      // Read models can briefly trail committed transaction status on an observer.
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  throw new Error(`read model did not reconcile at ${path}: ${JSON.stringify(last)}`);
}

test.describe("real browser account custody", () => {
  test.describe.configure({ mode: "serial" });

  test("browser ML-DSA-65 custody primitives execute with protocol sizes and context", async ({ page }) => {
    await page.goto("/#/login");
    const result = await page.evaluate(async () => {
      const keysModulePath = "/src/auth/keys.ts";
      const keys = await import(/* @vite-ignore */ keysModulePath);
      const kp = keys.generateKeypair();
      const derived = keys.derivePublicKeyFromSecretKey(kp.secretKeyB64);
      const validation = keys.validateKeypair(kp.pubkeyB64, kp.secretKeyB64);
      const message = new TextEncoder().encode("weall-m2-browser-custody-smoke");
      const signatureB64 = keys.signDetachedB64(kp.secretKeyB64, message);
      const signatureValid = keys.verifyDetachedB64(kp.pubkeyB64, message, signatureB64);
      const decodedLength = (value: string) => atob(value).length;
      return {
        derivedMatches: derived === kp.pubkeyB64,
        validation,
        seedBytes: decodedLength(kp.secretKeyB64),
        publicKeyBytes: decodedLength(kp.pubkeyB64),
        signatureBytes: decodedLength(signatureB64),
        signatureValid,
        notice: keys.browserPqSigningNotice(),
      };
    });

    expect(result.derivedMatches).toBeTruthy();
    expect(result.validation).toEqual({ ok: true });
    expect(result.seedBytes).toBe(32);
    expect(result.publicKeyBytes).toBe(1952);
    expect(result.signatureBytes).toBe(3309);
    expect(result.signatureValid).toBeTruthy();
    expect(result.notice).toContain("ML-DSA-65");
  });

  test("create, verify, register, restart, restore, and submit a protected signed action", async ({ browser, request }) => {
    test.setTimeout(300_000);
    await requireBackend(request);

    const tempDir = await mkdtemp(join(tmpdir(), "weall-m2-custody-"));
    const recoveryPath = join(tempDir, "recovery.json");
    const suffix = Date.now().toString(36).slice(-9);
    const account = `@m2e2e_${suffix}`;
    const displayName = `M2 restored ${suffix}`;

    let firstContext: BrowserContext | null = await browser.newContext({ baseURL: BASE_URL, acceptDownloads: true });
    try {
      const firstPage = await firstContext.newPage();
      await firstPage.goto("/#/login");
      await expect(firstPage.getByTestId("create-account-key-form")).toBeVisible();

      await firstPage.getByLabel("Choose a handle").fill(account);
      const createAccountButton = firstPage.getByRole("button", { name: "Create account key" });
      await expect(createAccountButton).toBeEnabled({ timeout: 30_000 });
      await createAccountButton.click();
      await expect(firstPage.getByTestId("recovery-save-step")).toBeVisible({ timeout: 30_000 });

      const continueButton = firstPage.getByRole("button", { name: "Continue to account verification" });
      await expect(continueButton).toBeDisabled();

      const downloadPromise = firstPage.waitForEvent("download");
      await firstPage.getByRole("button", { name: /Download recovery file/ }).click();
      const download = await downloadPromise;
      await download.saveAs(recoveryPath);

      const recovery = JSON.parse(await readFile(recoveryPath, "utf8")) as RecoveryFileV2;
      expect(recovery).toMatchObject({
        type: "weall_recovery_key",
        version: 2,
        sigProfile: "pq-mldsa-v1",
        algorithm: "ML-DSA",
        parameterSet: "ML-DSA-65",
        secretKeyFormat: "mldsa65-seed-b64",
        account,
      });
      expect(Buffer.from(recovery.secretKeyB64, "base64")).toHaveLength(32);
      expect(Buffer.from(recovery.publicKeyB64, "base64")).toHaveLength(1952);
      expect(Buffer.from(recovery.recoveryAuthoritySecretKeyB64, "base64")).toHaveLength(32);
      expect(Buffer.from(recovery.recoveryAuthorityPublicKeyB64, "base64")).toHaveLength(1952);
      expect(Buffer.from(recovery.evidenceKemPublicKeyB64, "base64")).toHaveLength(1184);
      expect(Buffer.from(recovery.evidenceKemSecretKeyB64, "base64").length).toBeGreaterThan(0);
      expect(recovery.recoveryAuthorityPublicKeyB64).not.toBe(recovery.publicKeyB64);

      const recoveryText = firstPage.getByTestId("verify-created-recovery-json");
      await recoveryText.fill('{"type":');
      await expect(firstPage.locator(".error-text")).toBeVisible();
      await expect(continueButton).toBeDisabled();

      await recoveryText.fill(JSON.stringify({ ...recovery, account: `@wrong_${suffix}` }));
      await expect(firstPage.locator(".error-text")).toContainText("recovery_account_mismatch");
      await expect(continueButton).toBeDisabled();

      await recoveryText.fill(JSON.stringify({ ...recovery, publicKeyB64: mutateB64(recovery.publicKeyB64) }));
      await expect(firstPage.locator(".error-text")).toContainText(/invalid_recovery_key|public.key/i);
      await expect(continueButton).toBeDisabled();

      await recoveryText.fill(JSON.stringify({ ...recovery, secretKeyB64: mutateB64(recovery.secretKeyB64) }));
      await expect(firstPage.locator(".error-text")).toContainText(/invalid_recovery_key|secret.key/i);
      await expect(continueButton).toBeDisabled();

      await firstPage.getByTestId("verify-created-recovery-file").setInputFiles(recoveryPath);
      await expect(firstPage.getByTestId("recovery-verification-status")).toContainText("Recovery verified", { timeout: 30_000 });
      await expect(continueButton).toBeEnabled();

      const storageBeforeRegistration = await firstPage.evaluate((acct: string) => ({
        publicMetadata: localStorage.getItem(`weall_keypair::${acct}`),
        sessionSecret: sessionStorage.getItem(`weall_secret::${acct}`),
        recoveryPublic: localStorage.getItem(`weall_recovery_authority_public::${acct}`),
        recoverySecretInLocal: localStorage.getItem(`weall_recovery_authority_secret::${acct}`),
        recoverySecretInSession: sessionStorage.getItem(`weall_recovery_authority_secret::${acct}`),
        evidencePublic: localStorage.getItem(`weall_evidence_kem_public::${acct}`),
        evidenceSecretInLocal: localStorage.getItem(`weall_evidence_kem_secret::${acct}`),
        evidenceSecretInSession: sessionStorage.getItem(`weall_evidence_kem_secret::${acct}`),
      }), account);
      expect(storageBeforeRegistration.publicMetadata).toContain(recovery.publicKeyB64);
      expect(storageBeforeRegistration.publicMetadata).not.toContain(recovery.secretKeyB64);
      expect(storageBeforeRegistration.sessionSecret).toBe(recovery.secretKeyB64);
      expect(storageBeforeRegistration.recoveryPublic).toBe(recovery.recoveryAuthorityPublicKeyB64);
      expect(storageBeforeRegistration.recoverySecretInLocal).toBeNull();
      expect(storageBeforeRegistration.recoverySecretInSession).toBe(recovery.recoveryAuthoritySecretKeyB64);
      expect(storageBeforeRegistration.evidencePublic).toBe(recovery.evidenceKemPublicKeyB64);
      expect(storageBeforeRegistration.evidenceSecretInLocal).toBeNull();
      expect(storageBeforeRegistration.evidenceSecretInSession).toBe(recovery.evidenceKemSecretKeyB64);

      await continueButton.click();
      await firstPage.waitForURL(/#\/verification$/);
      const registerButton = firstPage.getByRole("button", { name: "Register basic account" });
      await expect(registerButton).toBeEnabled({ timeout: 30_000 });

      const registerTxId = await captureSubmittedTx(firstPage, () => registerButton.click());
      const registerStatus = await waitForConfirmedTx(firstPage.request, registerTxId);
      expect(TERMINAL_SUCCESS.has(String(registerStatus?.status || registerStatus?.phase || "").toLowerCase())).toBeTruthy();
      const accountPath = `/v1/accounts/${encodeURIComponent(account)}`;
      const accountBeforeRestart = await pollJson(
        firstPage.request,
        accountPath,
        (body) => Array.isArray(body?.state?.active_keys) && body.state.active_keys.length === 1,
      );
      expect(accountBeforeRestart?.account).toBe(account);
      assertSingleCanonicalAccountKey(accountBeforeRestart, recovery.publicKeyB64);
      expect(accountBeforeRestart?.state?.recovery?.offline_key?.pubkey).toBe(recovery.recoveryAuthorityPublicKeyB64);
      expect(accountBeforeRestart?.state?.evidence_encryption?.public_key).toBe(recovery.evidenceKemPublicKeyB64);

      const refreshStatusButton = firstPage.getByRole("button", { name: "Refresh status" });
      await expect(refreshStatusButton).toBeEnabled({ timeout: 30_000 });
      await refreshStatusButton.click();
      await expect(
        firstPage.locator("span.statusPill.ok").filter({ hasText: /^Basic account ready$/ }),
      ).toBeVisible({ timeout: 30_000 });

      await firstContext.close();
      firstContext = null;

      const restoredContext = await browser.newContext({ baseURL: BASE_URL, acceptDownloads: true });
      try {
        const restoredPage = await restoredContext.newPage();
        await restoredPage.goto("/#/login");

        const initiallyClean = await restoredPage.evaluate((acct: string) => ({
          session: localStorage.getItem("weall_session_v1"),
          publicMetadata: localStorage.getItem(`weall_keypair::${acct}`),
          sessionSecret: sessionStorage.getItem(`weall_secret::${acct}`),
          recoveryPublic: localStorage.getItem(`weall_recovery_authority_public::${acct}`),
          recoverySecret: sessionStorage.getItem(`weall_recovery_authority_secret::${acct}`),
          evidencePublic: localStorage.getItem(`weall_evidence_kem_public::${acct}`),
          evidenceSecret: sessionStorage.getItem(`weall_evidence_kem_secret::${acct}`),
        }), account);
        expect(initiallyClean).toEqual({
          session: null,
          publicMetadata: null,
          sessionSecret: null,
          recoveryPublic: null,
          recoverySecret: null,
          evidencePublic: null,
          evidenceSecret: null,
        });

        await restoredPage.getByRole("button", { name: "Sign in", exact: true }).first().click();
        const restoreForm = restoredPage.getByTestId("restore-account-form");
        await expect(restoreForm).toBeVisible();

        await restoreForm.getByLabel("Handle").fill(account);
        await restoreForm.getByRole("button", { name: "Sign in", exact: true }).click();
        await expect(restoredPage.locator(".error-text")).toContainText(
          "Upload your recovery file or paste your recovery key.",
        );

        await restoredPage.getByTestId("restore-recovery-file").setInputFiles(recoveryPath);
        await expect(restoreForm.getByLabel("Handle")).toHaveValue(account);
        await expect(restoreForm.getByLabel("Recovery key")).toHaveValue(recovery.secretKeyB64);

        await restoreForm.getByRole("button", { name: "Sign in", exact: true }).click();
        await restoredPage.waitForURL(/#\/home$/, { timeout: 120_000 });

        const restoredStorage = await restoredPage.evaluate((acct: string) => ({
          session: localStorage.getItem("weall_session_v1"),
          publicMetadata: localStorage.getItem(`weall_keypair::${acct}`),
          sessionSecret: sessionStorage.getItem(`weall_secret::${acct}`),
          recoveryPublic: localStorage.getItem(`weall_recovery_authority_public::${acct}`),
          recoverySecretInLocal: localStorage.getItem(`weall_recovery_authority_secret::${acct}`),
          recoverySecretInSession: sessionStorage.getItem(`weall_recovery_authority_secret::${acct}`),
          evidencePublic: localStorage.getItem(`weall_evidence_kem_public::${acct}`),
          evidenceSecretInLocal: localStorage.getItem(`weall_evidence_kem_secret::${acct}`),
          evidenceSecretInSession: sessionStorage.getItem(`weall_evidence_kem_secret::${acct}`),
        }), account);
        expect(restoredStorage.session).toContain(account);
        expect(restoredStorage.publicMetadata).toContain(recovery.publicKeyB64);
        expect(restoredStorage.publicMetadata).not.toContain(recovery.secretKeyB64);
        expect(restoredStorage.sessionSecret).toBe(recovery.secretKeyB64);
        expect(restoredStorage.recoveryPublic).toBe(recovery.recoveryAuthorityPublicKeyB64);
        expect(restoredStorage.recoverySecretInLocal).toBeNull();
        expect(restoredStorage.recoverySecretInSession).toBe(recovery.recoveryAuthoritySecretKeyB64);
        expect(restoredStorage.evidencePublic).toBe(recovery.evidenceKemPublicKeyB64);
        expect(restoredStorage.evidenceSecretInLocal).toBeNull();
        expect(restoredStorage.evidenceSecretInSession).toBe(recovery.evidenceKemSecretKeyB64);

        const accountAfterRestore = await getJson(restoredPage.request, accountPath);
        expect(accountAfterRestore?.account).toBe(account);
        assertSingleCanonicalAccountKey(accountAfterRestore, recovery.publicKeyB64);
        expect(accountAfterRestore?.state?.recovery?.offline_key?.pubkey).toBe(recovery.recoveryAuthorityPublicKeyB64);
        expect(accountAfterRestore?.state?.evidence_encryption?.public_key).toBe(recovery.evidenceKemPublicKeyB64);

        await restoredPage.goto("/#/profile");
        await expect(restoredPage.getByText(account).first()).toBeVisible({ timeout: 30_000 });
        const editProfile = restoredPage.getByText("Edit public profile", { exact: true });
        await editProfile.click();
        await restoredPage.getByLabel("Display name").fill(displayName);

        const profileTxId = await captureSubmittedTx(
          restoredPage,
          () => restoredPage.getByRole("button", { name: "Submit public profile update" }).click(),
        );
        await waitForConfirmedTx(restoredPage.request, profileTxId);
        const profilePath = `/v1/accounts/${encodeURIComponent(account)}/profile`;
        const profile = await pollJson(
          restoredPage.request,
          profilePath,
          (body) => JSON.stringify(body).includes(displayName),
        );
        expect(JSON.stringify(profile)).toContain(displayName);
        await expect(restoredPage.getByTestId("profile-tx-status-callout")).toContainText(profileTxId);
      } finally {
        await restoredContext.close();
      }
    } finally {
      if (firstContext) await firstContext.close();
      await rm(tempDir, { recursive: true, force: true });
    }
  });
});
