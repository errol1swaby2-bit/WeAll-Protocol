import { expect, test, type APIRequestContext, type BrowserContext, type Page, type Request, type Response } from "@playwright/test";
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
  // Consensus stores normalized ML-DSA-65 public key bytes as lowercase hex.
  // The downloaded recovery file stores the same 1952 bytes as base64.
  const canonicalHex = Buffer.from(publicKeyB64, "base64").toString("hex");
  expect(canonicalHex).toHaveLength(3904);
  const state = body?.state || {};
  expect(state?.pubkey).toBe(canonicalHex);
  expect(state?.pubkeys).toEqual([canonicalHex]);
  expect(state?.active_keys).toEqual([canonicalHex]);
  const byId = state?.keys?.by_id || {};
  expect(Object.keys(byId)).toHaveLength(1);
  expect(JSON.stringify(byId)).toContain(canonicalHex);
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
  // Never retry a signed action merely because its acknowledgement is missing.
  // Record only HTTP methods, endpoint paths and status codes: no signing
  // envelopes, recovery material, session headers or raw responses in logs.
  const events: string[] = [];
  const interested = (request: Request): boolean => {
    const pathname = new URL(request.url()).pathname;
    return request.method() === "POST"
      && (pathname.endsWith("/v1/tx/submit")
        || pathname.endsWith("/v1/accounts/tx/profile-update"));
  };
  const onRequest = (request: Request) => {
    if (interested(request)) events.push(`request ${request.method()} ${new URL(request.url()).pathname}`);
  };
  const onResponse = (response: Response) => {
    if (interested(response.request())) events.push(`response ${response.status()} ${new URL(response.url()).pathname}`);
  };
  const onRequestFailed = (request: Request) => {
    if (interested(request)) events.push(`request-failed ${new URL(request.url()).pathname}`);
  };
  page.on("request", onRequest);
  page.on("response", onResponse);
  page.on("requestfailed", onRequestFailed);
  try {
    const [response] = await Promise.all([
      page.waitForResponse(
        (candidate: Response) =>
          candidate.request().method() === "POST"
          && new URL(candidate.url()).pathname.endsWith("/v1/tx/submit"),
        { timeout: 60_000 },
      ),
      click(),
    ]);
    expect(response.ok(), `transaction submission failed with HTTP ${response.status()}`).toBeTruthy();
    const body = await response.json();
    const txId = extractTxId(body);
    expect(txId, "transaction response did not contain a transaction ID").not.toBe("");
    return txId;
  } catch (error) {
    const posture = await page.evaluate(() => ({
      hash: location.hash,
      errorCategories: Array.from(document.querySelectorAll('[role="alert"]'))
        .map((node) => node.getAttribute("data-feedback-category") || "error"),
      // Enumerate only known app error codes, never arbitrary backend payloads.
      knownErrorCodes: Array.from(document.querySelectorAll('[role="alert"]'))
        .flatMap((node) => ["signer_submission_busy", "register_the_account_first", "missing_account_signer", "profile_update_skeleton_missing_tx_type"]
          .filter((code) => node.textContent?.includes(code))),
      profileSubmitButtons: Array.from(document.querySelectorAll("button"))
        .filter((node) => node.textContent?.includes("Submit public profile update"))
        .map((node) => ({ disabled: node.disabled })),
      profileReceiptVisible: Boolean(document.querySelector('[data-testid="profile-tx-status-callout"]')),
    })).catch(() => ({ browserClosed: true }));
    throw new Error(`Signed transaction did not yield an acknowledged receipt: ${String(error)}. Network events: ${JSON.stringify(events.slice(-16))}. UI posture: ${JSON.stringify(posture)}`);
  } finally {
    page.off("request", onRequest);
    page.off("response", onResponse);
    page.off("requestfailed", onRequestFailed);
  }
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

  test("expired bearer and cancelled or unavailable passkeys never authenticate locally", async ({ page }) => {
    await page.goto("/#/login");
    const result = await page.evaluate(async () => {
      const sessionPath = "/src/auth/session.ts";
      const passkeyPath = "/src/auth/passkeys.ts";
      const sessions = await import(/* @vite-ignore */ sessionPath);
      const passkeys = await import(/* @vite-ignore */ passkeyPath);
      const acct = "@m2guard_" + Date.now().toString(36);

      // Only a local, deliberately expired fixture; never claim that this
      // synthetic token was issued or authorized by the network.
      sessions.setSession({
        version: 1,
        account: acct,
        sessionKey: "expired-bearer-not-authoritative",
        expiresAtMs: Date.now() - 1000,
      });
      const expiredHealth = sessions.getSessionHealth();
      const expiredWriteReady = sessions.isWriteSessionReady(acct);
      const expiredSession = sessions.getSession();

      const originalNavigator = Object.getOwnPropertyDescriptor(navigator, "credentials");
      const originalPublicKeyCredential = Object.getOwnPropertyDescriptor(window, "PublicKeyCredential");
      let cancelledRegistration = "";
      let cancelledSignIn = "";
      let unavailableRegistration = "";
      let unavailableSignIn = "";
      let afterCancelledCreate = -1;
      let afterUnavailability = -1;
      const fixtureId = "AQIDBA";
      try {
        Object.defineProperty(window, "PublicKeyCredential", {
          configurable: true,
          value: class MockPublicKeyCredential {},
        });
        Object.defineProperty(navigator, "credentials", {
          configurable: true,
          value: { create: async () => null, get: async () => null },
        });
        try {
          await passkeys.registerEasySignIn({ account: acct });
        } catch (e) {
          cancelledRegistration = e instanceof Error ? e.message : String(e);
        }
        afterCancelledCreate = passkeys.listEasySignInRecords().length;

        // Fixture is local metadata only. A cancelled assertion must not
        // validate it as an authenticated account or mint any bearer.
        localStorage.setItem("weall_easy_signin::" + fixtureId, JSON.stringify({
          version: 1,
          account: acct,
          credentialId: fixtureId,
          label: "Synthetic cancellation fixture",
          createdAt: "2026-01-01T00:00:00.000Z",
        }));
        localStorage.setItem("weall_easy_signin_index_v1", JSON.stringify([fixtureId]));
        try {
          await passkeys.confirmEasySignIn();
        } catch (e) {
          cancelledSignIn = e instanceof Error ? e.message : String(e);
        }

        Object.defineProperty(window, "PublicKeyCredential", {
          configurable: true,
          value: undefined,
        });
        try {
          await passkeys.registerEasySignIn({ account: acct });
        } catch (e) {
          unavailableRegistration = e instanceof Error ? e.message : String(e);
        }
        try {
          await passkeys.confirmEasySignIn();
        } catch (e) {
          unavailableSignIn = e instanceof Error ? e.message : String(e);
        }
        localStorage.removeItem("weall_easy_signin::" + fixtureId);
        localStorage.removeItem("weall_easy_signin_index_v1");
        afterUnavailability = passkeys.listEasySignInRecords().length;
      } finally {
        localStorage.removeItem("weall_easy_signin::" + fixtureId);
        localStorage.removeItem("weall_easy_signin_index_v1");
        if (originalNavigator) Object.defineProperty(navigator, "credentials", originalNavigator);
        else delete (navigator as Navigator & { credentials?: CredentialsContainer }).credentials;
        if (originalPublicKeyCredential) Object.defineProperty(window, "PublicKeyCredential", originalPublicKeyCredential);
        else delete (window as Window & { PublicKeyCredential?: typeof PublicKeyCredential }).PublicKeyCredential;
      }

      return {
        expiredState: expiredHealth.state,
        expiredWriteReady,
        expiredSession: expiredSession === null,
        persistentSessionCleared: localStorage.getItem("weall_session_v1") === null,
        tabBearerCleared: sessionStorage.getItem("weall_session_bearer_v1") === null,
        cancelledRegistration,
        cancelledSignIn,
        unavailableRegistration,
        unavailableSignIn,
        afterCancelledCreate,
        afterUnavailability,
      };
    });

    expect(result.expiredState).toBe("expired");
    expect(result.expiredWriteReady).toBe(false);
    expect(result.expiredSession).toBe(true);
    expect(result.persistentSessionCleared).toBe(true);
    expect(result.tabBearerCleared).toBe(true);
    expect(result.cancelledRegistration).toBe("passkey_registration_cancelled");
    expect(result.cancelledSignIn).toBe("passkey_signin_cancelled");
    expect(result.unavailableRegistration).toBe("passkeys_not_available");
    expect(result.unavailableSignIn).toBe("passkeys_not_available");
    expect(result.afterCancelledCreate).toBe(0);
    expect(result.afterUnavailability).toBe(0);
  });

  test("lost tab secrets with retained public metadata require recovery, never silent key rotation", async ({ browser, request }) => {
    test.setTimeout(120_000);
    await requireBackend(request);

    const account = "@m2lost_" + Date.now().toString(36);
    const context = await browser.newContext({ baseURL: BASE_URL });
    try {
      const page = await context.newPage();
      let submitted = 0;
      page.on("request", (req) => {
        if (req.method() === "POST" && new URL(req.url()).pathname.endsWith("/v1/tx/submit")) submitted += 1;
      });
      await page.goto("/#/login");
      await page.getByLabel("Choose a handle").fill(account);
      await page.getByRole("button", { name: "Create account key" }).click();
      await expect(page.getByTestId("recovery-save-step")).toBeVisible({ timeout: 30_000 });

      // Public metadata persists across tabs; signing seeds intentionally do not.
      const before = await page.evaluate((acct: string) => ({
        signerMeta: localStorage.getItem("weall_keypair::" + acct),
        recoveryMeta: localStorage.getItem("weall_recovery_authority_public::" + acct),
        evidenceMeta: localStorage.getItem("weall_evidence_kem_public::" + acct),
        signerSecretExists: !!sessionStorage.getItem("weall_secret::" + acct),
        recoverySecretExists: !!sessionStorage.getItem("weall_recovery_authority_secret::" + acct),
        evidenceSecretExists: !!sessionStorage.getItem("weall_evidence_kem_secret::" + acct),
      }), account);
      expect(before.signerMeta).toBeTruthy();
      expect(before.recoveryMeta).toBeTruthy();
      expect(before.evidenceMeta).toBeTruthy();
      expect(before.signerSecretExists).toBe(true);
      expect(before.recoverySecretExists).toBe(true);
      expect(before.evidenceSecretExists).toBe(true);

      // Simulate the exact same-origin browser state after tab-scoped key loss.
      await page.evaluate((acct: string) => {
        sessionStorage.removeItem("weall_secret::" + acct);
        sessionStorage.removeItem("weall_recovery_authority_secret::" + acct);
        sessionStorage.removeItem("weall_evidence_kem_secret::" + acct);
      }, account);
      await page.reload();
      await page.getByLabel("Choose a handle").fill(account);
      await page.getByRole("button", { name: "Create account key" }).click();

      await expect(page.getByTestId("restore-account-form")).toBeVisible();
      await expect(page.locator(".error-text")).toContainText("No replacement keys have been generated.");
      const after = await page.evaluate((acct: string) => ({
        signerMeta: localStorage.getItem("weall_keypair::" + acct),
        recoveryMeta: localStorage.getItem("weall_recovery_authority_public::" + acct),
        evidenceMeta: localStorage.getItem("weall_evidence_kem_public::" + acct),
        signerSecretExists: !!sessionStorage.getItem("weall_secret::" + acct),
        recoverySecretExists: !!sessionStorage.getItem("weall_recovery_authority_secret::" + acct),
        evidenceSecretExists: !!sessionStorage.getItem("weall_evidence_kem_secret::" + acct),
      }), account);
      expect(after.signerMeta).toBe(before.signerMeta);
      expect(after.recoveryMeta).toBe(before.recoveryMeta);
      expect(after.evidenceMeta).toBe(before.evidenceMeta);
      expect(after.signerSecretExists).toBe(false);
      expect(after.recoverySecretExists).toBe(false);
      expect(after.evidenceSecretExists).toBe(false);
      expect(submitted).toBe(0);
    } finally {
      await context.close();
    }
  });

  test("registration aborted before backend admission remains a durable unknown with no automatic resubmission", async ({ browser, request }) => {
    test.setTimeout(180_000);
    await requireBackend(request);

    const account = "@m2unknown_" + Date.now().toString(36);
    const tempDir = await mkdtemp(join(tmpdir(), "weall-m2-unknown-"));
    const recoveryPath = join(tempDir, "recovery.json");
    const context = await browser.newContext({ baseURL: BASE_URL, acceptDownloads: true });
    try {
      const page = await context.newPage();
      await page.goto("/#/login");
      await page.getByLabel("Choose a handle").fill(account);
      await page.getByRole("button", { name: "Create account key" }).click();
      await expect(page.getByTestId("recovery-save-step")).toBeVisible({ timeout: 30_000 });

      const downloadPromise = page.waitForEvent("download");
      await page.getByRole("button", { name: /Download recovery file/ }).click();
      const download = await downloadPromise;
      await download.saveAs(recoveryPath);
      await page.getByTestId("verify-created-recovery-file").setInputFiles(recoveryPath);
      await expect(page.getByTestId("recovery-verification-status")).toContainText("Recovery verified");
      await page.getByRole("button", { name: "Continue to network registration" }).click();
      await page.waitForURL(/#\/onboarding\/register$/);

      const registerButton = page.getByTestId("submit-basic-registration");
      await expect(registerButton).toBeEnabled({ timeout: 30_000 });
      let browserDispatches = 0;
      let savedBeforeDispatch = "";
      let originalSignedRegistration: Record<string, unknown> | null = null;
      let finishInterception!: () => void;
      const interceptionFinished = new Promise<void>((resolve) => {
        finishInterception = resolve;
      });
      await page.route("**/v1/tx/submit", async (route) => {
        if ((route.request().postDataJSON() as Record<string, unknown>)?.tx_type !== "ACCOUNT_REGISTER") {
          await route.continue();
          return;
        }
        browserDispatches += 1;
        try {
          // The signed envelope stays in Node test memory only; no private
          // recovery keys or raw signatures are emitted to CI logs.
          originalSignedRegistration = route.request().postDataJSON() as Record<string, unknown>;
          savedBeforeDispatch = await page.evaluate(
            (acct: string) => localStorage.getItem("weall.account_registration_pending::" + acct) || "",
            account,
          );
          // Abort before backend admission: this is unknown from the browser's
          // perspective, not an authoritative rejection or permission to retry.
          await route.abort("failed");
        } finally {
          // Request-observed fires before this asynchronous route handler has
          // read browser storage and completed the abort. A visible pending UI
          // is not a completion barrier for Playwright's interception callback.
          finishInterception();
        }
      });
      await registerButton.click();
      await expect.poll(() => browserDispatches).toBe(1);
      await interceptionFinished;
      expect(savedBeforeDispatch).toMatch(/^tx:[0-9a-f]{64}$/);
      await expect(page.getByTestId("registration-pending")).toBeVisible({ timeout: 30_000 });
      await page.unroute("**/v1/tx/submit");

      await page.reload();
      await expect(page.getByTestId("registration-pending")).toBeVisible({ timeout: 30_000 });
      await expect(page.getByTestId("submit-basic-registration")).toBeDisabled();
      await page.getByRole("button", { name: "Check registration status" }).click();
      await expect(page.getByTestId("submit-basic-registration")).toBeDisabled();
      const recorded = await page.evaluate(
        (acct: string) => localStorage.getItem("weall.account_registration_pending::" + acct),
        account,
      );
      expect(recorded).toBe(savedBeforeDispatch);
      expect(browserDispatches).toBe(1);
      const state = await getJson(page.request, "/v1/accounts/" + encodeURIComponent(account));
      expect(String(state?.state?.pubkey || "")).toBe("");

      // Send a DIFFERENT signature over the same canonical registration body
      // directly to the live backend. Public HTTP admission must reject this
      // cryptographically invalid envelope; unlike the simulated terminal
      // receipt below, this is a genuine production-equivalent ingress probe.
      // The original correctly signed envelope must never be sent by this test.
      expect(originalSignedRegistration).not.toBeNull();
      const originalEnvelope = originalSignedRegistration as unknown as Record<string, any>;
      const originalSignature = String(originalEnvelope.sig || "");
      expect(originalSignature.length).toBeGreaterThan(100);
      const corruptSignature = mutateB64(originalSignature);
      expect(corruptSignature).not.toBe(originalSignature);
      const forged = {
        ...originalEnvelope,
        sig: corruptSignature,
        signature: {
          ...(originalEnvelope.signature || {}),
          sig: corruptSignature,
        },
      };
      const actualRejection = await page.request.post("/v1/tx/submit", {
        data: forged,
        timeout: 15_000,
      });
      expect(actualRejection.ok()).toBe(false);
      expect(actualRejection.status()).toBeGreaterThanOrEqual(400);
      expect(actualRejection.status()).toBeLessThan(500);
      const rejectedBody = await actualRejection.json();
      expect(JSON.stringify(rejectedBody)).toContain("bad_sig");
      const afterRealIngressRejection = await getJson(
        page.request,
        "/v1/accounts/" + encodeURIComponent(account),
      );
      expect(String(afterRealIngressRejection?.state?.pubkey || "")).toBe("");
      expect(Number(afterRealIngressRejection?.state?.nonce || 0)).toBe(0);
      expect(browserDispatches).toBe(1);

      // This is a controlled terminal-status RESPONSE fixture, not a claim
      // that the real backend rejected the transaction aborted above.
      // It proves the browser treats a canonical "rejected" report as
      // terminal and demands an explicit, guarded request reset.
      const statusPath = "/v1/tx/status/" + encodeURIComponent(savedBeforeDispatch);
      let terminalStatusReads = 0;
      await page.route("**/v1/tx/status/**", async (route) => {
        if (new URL(route.request().url()).pathname !== statusPath) {
          await route.continue();
          return;
        }
        terminalStatusReads += 1;
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({ ok: true, status: "rejected", local_state_synced: false }),
        });
      });
      await page.getByRole("button", { name: "Check registration status" }).click();
      await expect(page.getByTestId("registration-rejected")).toBeVisible({ timeout: 30_000 });
      await expect(page.getByTestId("submit-basic-registration")).toBeDisabled();
      expect(browserDispatches).toBe(1);
      expect(terminalStatusReads).toBeGreaterThan(0);

      await page.unroute("**/v1/tx/status/**");
      await page.getByRole("button", { name: "Prepare a new request" }).click();
      await expect(page.getByTestId("submit-basic-registration")).toBeEnabled({ timeout: 30_000 });
      const afterDeliberateReset = await page.evaluate(
        (acct: string) => localStorage.getItem("weall.account_registration_pending::" + acct),
        account,
      );
      expect(afterDeliberateReset).toBeNull();
      // No second signed request may occur until the human actually clicks
      // "Register my account" again.
      expect(browserDispatches).toBe(1);
    } finally {
      await context.close();
      await rm(tempDir, { recursive: true, force: true });
    }
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
      // Locally generated keys are not an authenticated account. Signing in
      // before checking the saved recovery material would bypass custody.
      expect(await firstPage.evaluate(() => localStorage.getItem("weall_session_v1"))).toBeNull();

      const continueButton = firstPage.getByRole("button", { name: "Continue to network registration" });
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
      expect(await firstPage.evaluate(() => localStorage.getItem("weall_session_v1"))).toBeNull();

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
      await firstPage.waitForURL(/#\/onboarding\/register$/);
      await expect(firstPage.getByTestId("guided-account-registration")).toBeVisible();
      const issuedSession = await firstPage.evaluate(() => localStorage.getItem("weall_session_v1"));
      expect(issuedSession).toContain(account);
      const registerButton = firstPage.getByTestId("submit-basic-registration");
      await expect(registerButton).toBeEnabled({ timeout: 30_000 });

      // Adversarial receipt-loss drill: the backend accepts ACCOUNT_REGISTER,
      // but the browser never receives the acknowledgement. The signed,
      // canonical ID must already be durable. No automatic re-submission.
      let registerTxId = "";
      let savedBeforeLostAcknowledgement = "";
      let registrationDispatches = 0;
      await firstPage.route("**/v1/tx/submit", async (route) => {
        const payload = route.request().postDataJSON() as Record<string, unknown>;
        if (payload?.tx_type !== "ACCOUNT_REGISTER") {
          await route.continue();
          return;
        }
        registrationDispatches += 1;
        // The browser must have durably recorded the canonical transaction
        // ID before attempting network dispatch. An intercepted, unacknowledged
        // request cannot authorize an automatic retry.
        const signedBody = route.request().postData();
        expect(signedBody).toBeTruthy();
        savedBeforeLostAcknowledgement = await firstPage.evaluate(
          (acct) => localStorage.getItem(`weall.account_registration_pending::${acct}`) || "",
          account,
        );
        expect(savedBeforeLostAcknowledgement).toMatch(/^tx:[0-9a-f]{64}$/);
        // Abort the browser request FIRST. Otherwise the browser may destroy
        // the intercepted route during a slow independent API submission.
        await route.abort("failed");
        // Deliver the *same* signed bytes independently to the real backend.
        // The client has no acknowledgement even though the ledger receives
        // and commits the exact transaction it pre-recorded.
        const actual = await firstPage.request.post("/v1/tx/submit", {
          data: signedBody || "",
          headers: { "content-type": "application/json" },
        });
        expect(actual.ok(), `ACCOUNT_REGISTER backend returned HTTP ${actual.status()}`).toBeTruthy();
        registerTxId = extractTxId(await actual.json());
        expect(registerTxId).toMatch(/^tx:[0-9a-f]{64}$/);
      });
      await registerButton.click();
      await expect.poll(() => registerTxId, { timeout: 60_000 }).toMatch(/^tx:[0-9a-f]{64}$/);
      await firstPage.unroute("**/v1/tx/submit");
      expect(savedBeforeLostAcknowledgement).toBe(registerTxId);
      expect(registrationDispatches).toBe(1);
      // A page reload preserves the write-ahead transaction ID and cannot
      // legitimately trigger another ACCOUNT_REGISTER submission.
      await firstPage.reload();
      await expect(firstPage.getByTestId("guided-account-registration")).toBeVisible();
      const registerStatus = await waitForConfirmedTx(firstPage.request, registerTxId);
      expect(registrationDispatches).toBe(1);
      expect(TERMINAL_SUCCESS.has(String(registerStatus?.status || registerStatus?.phase || "").toLowerCase())).toBeTruthy();
      const accountPath = `/v1/accounts/${encodeURIComponent(account)}`;
      const accountBeforeRestart = await pollJson(
        firstPage.request,
        accountPath,
        (body) => Array.isArray(body?.state?.active_keys) && body.state.active_keys.length === 1,
      );
      expect(accountBeforeRestart?.account).toBe(account);
      assertSingleCanonicalAccountKey(accountBeforeRestart, recovery.publicKeyB64);
      expect(accountBeforeRestart?.state?.recovery?.offline_key?.pubkey).toBe(Buffer.from(recovery.recoveryAuthorityPublicKeyB64, "base64").toString("hex"));
      expect(accountBeforeRestart?.state?.evidence_encryption?.public_key).toBe(recovery.evidenceKemPublicKeyB64);

      // Competing browser profile: the handle is already bound on-chain to
      // the first signer's public key. A second valid but different signer
      // must be blocked before signed ACCOUNT_REGISTER dispatch.
      const competingContext = await browser.newContext({ baseURL: BASE_URL, acceptDownloads: true });
      try {
        const competitor = await competingContext.newPage();
        let competingRegistrations = 0;
        competitor.on("request", (req) => {
          if (req.method() !== "POST" || !new URL(req.url()).pathname.endsWith("/v1/tx/submit")) return;
          try {
            if ((req.postDataJSON() as Record<string, unknown>)?.tx_type === "ACCOUNT_REGISTER") {
              competingRegistrations += 1;
            }
          } catch {
            // Do not log the signed transaction's contents.
          }
        });
        await competitor.goto("/#/login");
        await competitor.getByLabel("Choose a handle").fill(account);
        await competitor.getByRole("button", { name: "Create account key" }).click();
        await expect(competitor.getByTestId("recovery-save-step")).toBeVisible({ timeout: 30_000 });

        const collisionRecoveryPath = join(tempDir, "collision-recovery.json");
        const collisionDownload = competitor.waitForEvent("download");
        await competitor.getByRole("button", { name: /Download recovery file/ }).click();
        await (await collisionDownload).saveAs(collisionRecoveryPath);
        const rival = JSON.parse(await readFile(collisionRecoveryPath, "utf8")) as RecoveryFileV2;
        expect(rival.account).toBe(account);
        expect(rival.publicKeyB64).not.toBe(recovery.publicKeyB64);
        await competitor.getByTestId("verify-created-recovery-file").setInputFiles(collisionRecoveryPath);
        await expect(competitor.getByTestId("recovery-verification-status")).toContainText("Recovery verified");
        await competitor.getByRole("button", { name: "Continue to network registration" }).click();
        await competitor.waitForURL(/#\/onboarding\/register$/);
        await expect(competitor.getByTestId("registration-key-mismatch")).toBeVisible({ timeout: 30_000 });
        await expect(competitor.getByTestId("submit-basic-registration")).toBeDisabled();
        expect(competingRegistrations).toBe(0);

        const afterCollision = await getJson(competitor.request, accountPath);
        assertSingleCanonicalAccountKey(afterCollision, recovery.publicKeyB64);
        expect(afterCollision?.state?.recovery?.offline_key?.pubkey)
          .toBe(Buffer.from(recovery.recoveryAuthorityPublicKeyB64, "base64").toString("hex"));
      } finally {
        await competingContext.close();
      }

      const refreshStatusButton = firstPage.getByRole("button", { name: "Check registration status" });
      await expect(refreshStatusButton).toBeEnabled({ timeout: 30_000 });
      await refreshStatusButton.click();
      await expect(firstPage.getByTestId("registration-complete")).toContainText(
        "Your basic account is ready.",
        { timeout: 30_000 },
      );
      await expect(
        firstPage.locator("span.statusPill.ok").filter({ hasText: "3. Network registration" }),
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

        // A correct file for a different entered handle must not poison
        // canonical signer or auxiliary key custody in a fresh browser.
        await restoredPage.getByTestId("restore-recovery-file").setInputFiles(recoveryPath);
        await restoreForm.getByLabel("Handle").fill("@foreign_" + suffix);
        await restoreForm.getByRole("button", { name: "Sign in", exact: true }).click();
        await expect(restoredPage.locator(".error-text")).toContainText("does not match this handle");
        const afterForeignAttempt = await restoredPage.evaluate((acct: string) => ({
          publicMetadata: localStorage.getItem("weall_keypair::" + acct),
          signerSecret: sessionStorage.getItem("weall_secret::" + acct),
          recoveryPublic: localStorage.getItem("weall_recovery_authority_public::" + acct),
          evidencePublic: localStorage.getItem("weall_evidence_kem_public::" + acct),
        }), account);
        expect(afterForeignAttempt).toEqual({
          publicMetadata: null,
          signerSecret: null,
          recoveryPublic: null,
          evidencePublic: null,
        });

        await restoreForm.getByLabel("Handle").fill(account);
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

        // Two tabs share durable *public* metadata, not sessionStorage bearer
        // or signing seeds. Opening a new tab must not silently inherit the
        // authenticated browser session from the restored tab.
        const siblingPage = await restoredContext.newPage();
        try {
          await siblingPage.goto("/#/login");
          const sibling = await siblingPage.evaluate(async (acct: string) => {
            const sessionPath = "/src/auth/session.ts";
            const sessions = await import(/* @vite-ignore */ sessionPath);
            const current = sessions.getSession();
            return {
              durableAccount: JSON.parse(localStorage.getItem("weall_session_v1") || "null")?.account,
              bearer: sessionStorage.getItem("weall_session_bearer_v1"),
              signer: sessionStorage.getItem("weall_secret::" + acct),
              currentKey: current?.sessionKey ?? null,
              writeReady: sessions.isWriteSessionReady(acct),
            };
          }, account);
          expect(sibling.durableAccount).toBe(account);
          expect(sibling.bearer).toBeNull();
          expect(sibling.signer).toBeNull();
          expect(sibling.currentKey).toBeNull();
          expect(sibling.writeReady).toBe(false);

          // Explicitly import the test recovery signer's seed into this tab.
          // This is a deliberate simulated recovery, NEVER a silent copy from
          // another tab. Two independently executing JS realms now own the
          // same valid account signing key, as may happen on two user devices.
          const imported = await siblingPage.evaluate(async (input: { account: string; seed: string }) => {
            const keysPath = "/src/auth/keys.ts";
            const keys = await import(/* @vite-ignore */ keysPath);
            const key = keys.saveKeypair(input.account, { secretKeyB64: input.seed });
            return { matchingAccount: key.pubkeyB64.length > 0, signerStored: !!sessionStorage.getItem("weall_secret::" + input.account) };
          }, { account, seed: recovery.secretKeyB64 });
          expect(imported).toEqual({ matchingAccount: true, signerStored: true });

          const issueFrom = (target: Page) => target.evaluate(async (acct: string) => {
            const modulePath = "/src/auth/session.ts";
            const sessions = await import(/* @vite-ignore */ modulePath);
            const raw = new Uint8Array(32);
            crypto.getRandomValues(raw);
            const binary = Array.from(raw, (byte) => String.fromCharCode(byte)).join("");
            const candidate = btoa(binary);
            const outcome = await sessions.submitSignedTxWithNonce({
              account: acct,
              tx_type: "ACCOUNT_SESSION_KEY_ISSUE",
              payloadFactory: () => ({ session_key: candidate, ttl_s: 3600 }),
              parent: null,
            });
            // No bearer or signature bytes leave the browser; expose only
            // canonical tx IDs and numeric nonce values for assertions.
            return {
              nonce: outcome.env.nonce,
              txId: String(outcome.result?.tx_id || outcome.result?.result?.tx_id || ""),
            };
          }, account);

          // Both tabs submit at the same time. The shared signer lease and
          // nonce reservation must avoid two accepted txs with one nonce.
          const [firstIssue, secondIssue] = await Promise.all([
            issueFrom(restoredPage),
            issueFrom(siblingPage),
          ]);
          expect(firstIssue.txId).toMatch(/^tx:[0-9a-f]{64}$/);
          expect(secondIssue.txId).toMatch(/^tx:[0-9a-f]{64}$/);
          expect(firstIssue.txId).not.toBe(secondIssue.txId);
          expect(firstIssue.nonce).toBeGreaterThan(0);
          expect(secondIssue.nonce).toBeGreaterThan(0);
          expect(firstIssue.nonce).not.toBe(secondIssue.nonce);
          await Promise.all([
            waitForConfirmedTx(restoredPage.request, firstIssue.txId),
            waitForConfirmedTx(siblingPage.request, secondIssue.txId),
          ]);
          const afterConcurrentIssues = await pollJson(
            restoredPage.request,
            accountPath,
            (body) => Number(body?.state?.nonce || 0) >= Math.max(firstIssue.nonce, secondIssue.nonce),
          );
          assertSingleCanonicalAccountKey(afterConcurrentIssues, recovery.publicKeyB64);
        } finally {
          await siblingPage.close();
        }

        // Authoritative session expiry must be decided by the live backend's
        // ledger clock, NOT by the browser's local expiresAtMs value. Issue a
        // separate one-second session bearer as a signed canonical transaction
        // but never activate it as this tab's current browser session.
        const shortSession = await restoredPage.evaluate(async (acct: string) => {
          const sessionPath = "/src/auth/session.ts";
          const sessions = await import(/* @vite-ignore */ sessionPath);
          const raw = crypto.getRandomValues(new Uint8Array(32));
          const bearer = btoa(Array.from(raw, (b) => String.fromCharCode(b)).join(""));
          const issued = await sessions.submitSignedTxWithNonce({
            account: acct,
            tx_type: "ACCOUNT_SESSION_KEY_ISSUE",
            payloadFactory: () => ({ session_key: bearer, ttl_s: 1 }),
            parent: null,
          });
          return {
            // This bearer is test-only and stays in runner memory; it must
            // never be printed in errors, snapshots, or workflow logs.
            bearer,
            txId: String(issued.result?.tx_id || issued.result?.result?.tx_id || ""),
            nonce: issued.env.nonce,
          };
        }, account);
        expect(shortSession.txId).toMatch(/^tx:[0-9a-f]{64}$/);
        await waitForConfirmedTx(restoredPage.request, shortSession.txId);
        const shortHeaders = {
          "x-weall-account": account,
          "x-weall-session-key": shortSession.bearer,
        };
        // Constitutional chain time does not advance merely because 30 wall
        // seconds pass. Advance finalized state using distinct, deliberately
        // signed one-shot transactions, each committed in a separate block,
        // and verify expiry only after the authoritative height/time advances.
        const readShortSession = async (): Promise<any> => {
          const response = await restoredPage.request.get("/v1/session/me", {
            headers: shortHeaders,
            timeout: 10_000,
          });
          expect(response.ok()).toBe(true);
          return response.json();
        };
        let shortSessionState = await readShortSession();
        expect(Number(shortSessionState?.session?.ttl_s || 0)).toBe(1);
        // Canonical genesis time can legitimately be zero; absence is not
        // equivalent to a zero consensus timestamp.
        expect(Number.isInteger(shortSessionState?.session?.issued_at_ts)).toBe(true);
        expect(shortSessionState.session.issued_at_ts).toBeGreaterThanOrEqual(0);
        let clockAdvanceBlocks = 0;
        while (shortSessionState?.session?.expired !== true && clockAdvanceBlocks < 4) {
          const witness = await restoredPage.evaluate(async (acct: string) => {
            const sessionPath = "/src/auth/session.ts";
            const sessions = await import(/* @vite-ignore */ sessionPath);
            const random = crypto.getRandomValues(new Uint8Array(32));
            const key = btoa(Array.from(random, (b) => String.fromCharCode(b)).join(""));
            const outcome = await sessions.submitSignedTxWithNonce({
              account: acct,
              tx_type: "ACCOUNT_SESSION_KEY_ISSUE",
              payloadFactory: () => ({ session_key: key, ttl_s: 3600 }),
              parent: null,
            });
            // Never export the bearer or signed envelope into the test report.
            return {
              txId: String(outcome.result?.tx_id || outcome.result?.result?.tx_id || ""),
              nonce: outcome.env.nonce,
            };
          }, account);
          expect(witness.txId).toMatch(/^tx:[0-9a-f]{64}$/);
          await waitForConfirmedTx(restoredPage.request, witness.txId);
          clockAdvanceBlocks += 1;
          shortSessionState = await readShortSession();
        }
        expect(
          shortSessionState?.session?.expired,
          "A confirmed session remained unexpired despite subsequent finalized blocks; " +
            "canonical TTL=" + String(shortSessionState?.session?.ttl_s) +
            " and issued_at_ts=" + String(shortSessionState?.session?.issued_at_ts) +
            " after " + clockAdvanceBlocks + " distinct confirmed advance blocks.",
        ).toBe(true);
        expect(shortSessionState?.authenticated).toBe(false);
        const expiredProtectedRead = await restoredPage.request.get("/v1/social/me", {
          headers: shortHeaders,
        });
        expect(expiredProtectedRead.status()).toBe(403);
        const expiredError = await expiredProtectedRead.json();
        expect(JSON.stringify(expiredError)).toContain("session_expired");
        // The original independently authorized device session remains
        // intact and is the one used below for profile and revocation proof.
        expect(await restoredPage.evaluate(() => !!sessionStorage.getItem("weall_session_bearer_v1"))).toBe(true);

        const accountAfterRestore = await getJson(restoredPage.request, accountPath);
        expect(accountAfterRestore?.account).toBe(account);
        assertSingleCanonicalAccountKey(accountAfterRestore, recovery.publicKeyB64);
        expect(accountAfterRestore?.state?.recovery?.offline_key?.pubkey).toBe(Buffer.from(recovery.recoveryAuthorityPublicKeyB64, "base64").toString("hex"));
        expect(accountAfterRestore?.state?.evidence_encryption?.public_key).toBe(recovery.evidenceKemPublicKeyB64);

        // Inject two transient canonical account-view failures on the restored
        // profile screen. The UI may reconcile with bounded GETs, but must
        // never manufacture an account or submit a signed mutation.
        let canonicalAccountReads = 0;
        let transientObserverFailures = 0;
        let protectedProfileSubmissions = 0;
        restoredPage.on("request", (req) => {
          if (req.method() !== "POST" || !new URL(req.url()).pathname.endsWith("/v1/tx/submit")) return;
          try {
            if ((req.postDataJSON() as Record<string, unknown>)?.tx_type === "PROFILE_UPDATE") {
              protectedProfileSubmissions += 1;
            }
          } catch {
            // Never persist or emit signing material.
          }
        });
        await restoredPage.route("**/v1/accounts/**", async (route) => {
          if (route.request().method() !== "GET" ||
              new URL(route.request().url()).pathname !== accountPath) {
            await route.continue();
            return;
          }
          canonicalAccountReads += 1;
          if (transientObserverFailures < 2) {
            transientObserverFailures += 1;
            await route.fulfill({
              status: 503,
              contentType: "application/json",
              body: JSON.stringify({ ok: false, code: "observer_temporarily_unavailable" }),
            });
            return;
          }
          await route.continue();
        });

        await restoredPage.goto("/#/profile");
        await expect(restoredPage.getByText(account).first()).toBeVisible({ timeout: 30_000 });
        const editProfile = restoredPage.getByText("Edit public profile", { exact: true });
        await editProfile.click();
        await restoredPage.getByLabel("Display name").fill(displayName);

        const submitProfileButton = restoredPage.getByTestId("submit-public-profile-update");
        // Only the canonical account read is reconciled; never the signed TX.
        await expect(submitProfileButton).toBeEnabled({ timeout: 30_000 });
        expect(transientObserverFailures).toBe(2);
        expect(canonicalAccountReads).toBeGreaterThanOrEqual(3);
        expect(protectedProfileSubmissions).toBe(0);
        await restoredPage.unroute("**/v1/accounts/**");
        try {
          await expect(submitProfileButton).toBeEnabled({ timeout: 30_000 });
        } catch {
          const blockers = await submitProfileButton.getAttribute("data-submit-blockers");
          throw new Error(`Profile submission remained disabled; non-secret blockers: ${blockers || "none-reported"}`);
        }
        const profileTxId = await captureSubmittedTx(
          restoredPage,
          () => submitProfileButton.click(),
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

        // Revocation is a separate authoritative boundary: the old bearer must
        // authenticate before revocation and explicitly fail authentication
        // afterward. Local logout alone is not proof of remote revocation.
        const priorSession = JSON.parse(String(restoredStorage.session || "{}")) as { sessionKey?: string };
        expect(priorSession.sessionKey).toBeUndefined();
        const priorBearer = await restoredPage.evaluate(() => {
          const raw = sessionStorage.getItem("weall_session_bearer_v1");
          const stored = raw ? JSON.parse(raw) : null;
          return String(stored?.sessionKey || "");
        });
        expect(priorBearer.length).toBeGreaterThan(20);
        const oldBearerHeaders = {
          "x-weall-account": account,
          "x-weall-session-key": priorBearer,
        };
        const beforeRevocation = await restoredPage.request.get("/v1/session/me", {
          headers: oldBearerHeaders,
        });
        expect(beforeRevocation.ok()).toBeTruthy();
        expect((await beforeRevocation.json()).authenticated).toBe(true);

        // Offline logout is a LOCAL deletion, not cryptographic proof that the
        // network revoked the bearer. The real session endpoint must still
        // accept it after a deliberately unreachable revocation transport.
        const offlineLogout = await restoredPage.evaluate(async (input: {
          account: string;
          bearer: string;
        }) => {
          const sessionPath = "/src/auth/session.ts";
          const sessions = await import(/* @vite-ignore */ sessionPath);
          let error = "";
          try {
            await sessions.logoutCurrentDevice({ base: "http://127.0.0.1:1", forgetSigner: false });
          } catch (e) {
            error = e instanceof Error ? e.message : String(e);
          }
          const result = {
            error,
            sessionGone: sessions.getSession() === null,
            persistentGone: localStorage.getItem("weall_session_v1") === null,
            bearerGone: sessionStorage.getItem("weall_session_bearer_v1") === null,
            signerRetained: !!sessionStorage.getItem("weall_secret::" + input.account),
          };
          // Reconstitute only the *already network-authorized* same bearer
          // to exercise the separate positive canonical revocation below.
          // This does not mint a new bearer, issue a tx, or imply revocation.
          sessions.setSession({
            version: 1,
            account: input.account,
            sessionKey: input.bearer,
            expiresAtMs: Date.now() + 10 * 60 * 1000,
          });
          return result;
        }, { account, bearer: priorBearer });
        expect(offlineLogout.error.length).toBeGreaterThan(0);
        expect(offlineLogout.sessionGone).toBe(true);
        expect(offlineLogout.persistentGone).toBe(true);
        expect(offlineLogout.bearerGone).toBe(true);
        expect(offlineLogout.signerRetained).toBe(true);
        const stillAuthorizedAfterOffline = await restoredPage.request.get("/v1/session/me", {
          headers: oldBearerHeaders,
        });
        expect(stillAuthorizedAfterOffline.ok()).toBe(true);
        expect((await stillAuthorizedAfterOffline.json()).authenticated).toBe(true);

        await restoredPage.goto("/#/session");
        const revokeButton = restoredPage.getByRole("button", { name: "Log out of this device" });
        await expect(revokeButton).toBeEnabled({ timeout: 30_000 });
        // Cancel the "forget signer" option, but still revoke the session.
        restoredPage.once("dialog", (dialog) => { void dialog.dismiss(); });
        const revokeTxId = await captureSubmittedTx(restoredPage, () => revokeButton.click());
        await waitForConfirmedTx(restoredPage.request, revokeTxId);
        await expect.poll(async () => {
          const result = await restoredPage.request.get("/v1/session/me", {
            headers: oldBearerHeaders,
          });
          if (!result.ok()) return "unavailable";
          return (await result.json()).authenticated;
        }, { timeout: 45_000 }).toBe(false);
        await expect.poll(() => restoredPage.evaluate(() =>
          localStorage.getItem("weall_session_v1"),
        ), { timeout: 45_000 }).toBeNull();
        expect((await restoredPage.evaluate((acct: string) =>
          sessionStorage.getItem(`weall_secret::${acct}`),
        account))).toBe(recovery.secretKeyB64);
      } finally {
        await restoredContext.close();
      }
    } finally {
      if (firstContext) await firstContext.close();
      await rm(tempDir, { recursive: true, force: true });
    }
  });
});
