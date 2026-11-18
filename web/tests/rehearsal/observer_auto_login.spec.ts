import { expect, test, type Request } from "@playwright/test";

function txType(request: Request): string {
  if (request.method() !== "POST" || new URL(request.url()).pathname !== "/v1/tx/submit") return "";
  try { return String(request.postDataJSON()?.tx_type || ""); } catch { return ""; }
}

// Local controlled-devnet only. The actual README launcher must provision
// both accounts and the two separate frontend origins. No state injection.
for (const actor of [
  { port: 5173, route: "/verification", account: "@errol", interrupt: true },
  { port: 5174, route: "/reviews", account: "@devnet-genesis", interrupt: false },
]) {
  test("F-001 real automatic login on port " + actor.port, async ({ browser, request }) => {
    const origin = "http://127.0.0.1:" + actor.port;
    const context = await browser.newContext();
    const page = await context.newPage();
    let suppressReceiptReads = false;
    const counts = { device: 0, issue: 0, registration: 0 };
    try {
      for (const port of [8001, 8002, 5173, 5174]) {
        const status = await request.get("http://127.0.0.1:" + port + "/v1/status");
        expect(status.ok(), "README launcher backend/proxy health").toBe(true);
      }
      page.on("request", req => {
        const type = txType(req);
        if (type === "ACCOUNT_DEVICE_REGISTER") counts.device++;
        if (type === "ACCOUNT_REGISTER") counts.registration++;
        if (type === "ACCOUNT_SESSION_KEY_ISSUE") {
          counts.issue++;
          if (actor.interrupt && counts.issue === 1) suppressReceiptReads = true;
        }
      });
      // Drop only browser receipt reads during the deliberate interruption.
      // Never fabricate a result or modify an actual transaction.
      await page.route(/\/v1\/tx\/status\//, async route => {
        if (suppressReceiptReads) await route.abort("failed");
        else await route.continue();
      });
      const direct = page.waitForResponse(r => r.request().method() === "POST"
        && new URL(r.url()).pathname === "/v1/session/login", { timeout: 90_000 });
      const device = page.waitForResponse(r => r.ok() && txType(r.request()) === "ACCOUNT_DEVICE_REGISTER", { timeout: 120_000 });
      const issue = page.waitForResponse(r => r.ok() && txType(r.request()) === "ACCOUNT_SESSION_KEY_ISSUE", { timeout: 240_000 });
      const authenticated = page.waitForResponse(async r => {
        if (!r.ok() || new URL(r.url()).pathname !== "/v1/session/me") return false;
        const body = await r.json();
        return body?.ok === true && body?.authenticated === true && body?.account === actor.account;
      }, { timeout: 330_000 });

      await page.goto(origin + "/#" + actor.route);
      const denied = await direct;
      expect(denied.status()).toBe(403);
      expect((await denied.json())?.error?.code).toBe("direct_session_mutation_forbidden_in_controlled_devnet");
      const deviceId = String((await (await device).json())?.tx_id || "");
      const issueId = String((await (await issue).json())?.tx_id || "");
      expect(deviceId).toMatch(/^tx:[0-9a-f]{64}$/);
      expect(issueId).toMatch(/^tx:[0-9a-f]{64}$/);

      if (actor.interrupt) {
        // Deliberately exceed the original 30s confirmation budget, then
        // reload the same tab while the exact issued transaction is tracked.
        await page.waitForTimeout(35_000);
        await page.reload({ waitUntil: "domcontentloaded" });
        suppressReceiptReads = false;
      }
      await authenticated;
      await expect.poll(() => page.evaluate(acct => {
        const meta = JSON.parse(localStorage.getItem("weall_session_v1") || "null");
        const bearer = JSON.parse(sessionStorage.getItem("weall_session_bearer_v1") || "null");
        return meta?.account === acct && !meta?.sessionKey && bearer?.account === acct
          && Boolean(bearer?.sessionKey)
          && !Object.keys(sessionStorage).some(k => k.startsWith("weall_pending_canonical_login_v1::"))
          && !Object.values(localStorage).some(value => String(value).includes(String(bearer.sessionKey)));
      }, actor.account), { timeout: 60_000 }).toBe(true);

      await expect(page.getByRole("heading", { name: "Create or access your WeAll account" })).toHaveCount(0);
      // Verify committed apply receipts without retrieving any raw bearer.
      for (const [txId, type] of [[deviceId, "ACCOUNT_DEVICE_REGISTER"], [issueId, "ACCOUNT_SESSION_KEY_ISSUE"]]) {
        const receipt = async (port: number) => {
          const result = await request.get("http://127.0.0.1:" + port + "/v1/tx/status/" + encodeURIComponent(txId));
          if (!result.ok()) return "";
          const body = await result.json();
          return body?.status === "confirmed" && body?.apply_ok === true && body?.local_state_synced === true
            && body?.tx_type === type && body?.signer === actor.account && typeof body?.block_id === "string"
            ? body.block_id : "";
        };
        await expect.poll(async () => {
          const genesis = await receipt(8001);
          if (!genesis) return false;
          if (!actor.interrupt) return true;
          return genesis === await receipt(8002);
        }, { timeout: 120_000 }).toBe(true);
      }
      // Navigation/focus after success must not mint further credentials.
      // Await actual node recognition after reload rather than a transient
      // zero-heading count during initial React hydration.
      const recognizedAgain = page.waitForResponse(async response => {
        if (!response.ok() || new URL(response.url()).pathname !== "/v1/session/me") return false;
        const body = await response.json();
        return body?.authenticated === true && body?.account === actor.account;
      }, { timeout: 60_000 });
      await page.reload({ waitUntil: "domcontentloaded" });
      await recognizedAgain;
      await expect(page.getByRole("heading", { name: "Create or access your WeAll account" })).toHaveCount(0);
      expect(counts).toEqual({ device: 1, issue: 1, registration: 0 });
    } finally {
      await context.close();
    }
  });
}
