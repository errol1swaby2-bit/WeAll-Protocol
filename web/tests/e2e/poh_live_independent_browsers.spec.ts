import { test, expect } from "@playwright/test";
import {
  createActorContext,
  loadM2ActorManifest,
  m2BrowserJourneyTimeoutMs,
  submitDirect,
  waitForConfirmed,
  waitForTier,
  waitForLiveLocalMedia,
} from "./m2_actor_helpers";

const REQUIRE_REAL = String(process.env.WEALL_REQUIRE_M2_REAL_STACK || "") === "1";

test.describe("M2 independent-browser live Tier 2", () => {
  test("independent applicant and reviewers establish live media, record attendance, vote, and unlock Tier 2", async ({ browser, request, baseURL }) => {
    test.setTimeout(m2BrowserJourneyTimeoutMs());
    if (!REQUIRE_REAL) test.skip(true, "set WEALL_REQUIRE_M2_REAL_STACK=1 for the mandatory external journey");
    const manifest = loadM2ActorManifest("live");
    const opened: Array<{ context: any; page: any }> = [];
    try {
      const applicant = await test.step("Restore applicant browser custody and canonical session", () =>
        createActorContext(browser, baseURL || "http://127.0.0.1:5173", manifest.applicant, manifest.api_base),
      );
      opened.push(applicant);
      await applicant.page.goto(`/#/verification/live/${encodeURIComponent(manifest.case_id)}`);
      await expect(applicant.page.getByTestId("live-verification-room")).toBeVisible();
      await applicant.page.getByTestId("live-room-join").click();
      await waitForLiveLocalMedia(applicant.page, "applicant");

      const reviewerActors: Array<{ actor: any; reviewer: any }> = [];
      for (const reviewer of manifest.reviewers) {
        const actor = await test.step(`Restore reviewer browser custody and canonical session: ${reviewer.account}`, () =>
          createActorContext(browser, baseURL || "http://127.0.0.1:5173", reviewer, manifest.api_base),
        );
        opened.push(actor);
        reviewerActors.push({ actor, reviewer });
        await actor.page.goto(`/#/verification/live/${encodeURIComponent(manifest.case_id)}`);
        await expect(actor.page.getByTestId("live-verification-room")).toBeVisible();
        await actor.page.getByTestId("live-room-join").click();
        await waitForLiveLocalMedia(actor.page, `reviewer ${reviewer.account}`);
        if (String(reviewer.role || "").toLowerCase() !== "observing") {
          const approve = actor.page.getByTestId("live-review-approve");
          await expect(approve).toBeVisible({ timeout: 60_000 });
          await approve.click();
        }
      }

      await expect.poll(async () => {
        const values = await Promise.all(opened.map(({ page }) => page.getByTestId("live-p2p-status").textContent().catch(() => "")));
        return values.some((value) => /connected|media|running|offer|answer/i.test(String(value || "")));
      }, { timeout: 45_000 }).toBe(true);

      const state = await test.step("Wait for canonical Tier 2 finalization", () =>
        waitForTier(request, manifest.api_base, manifest.applicant.account, 2),
      );
      expect(Number(state.poh_tier || 0)).toBe(2);
      const gatedTx = await submitDirect(applicant.page, manifest.api_base, manifest.applicant.account, "CONTENT_POST_CREATE", {
        post_id: `post:m2-live-browser:${Date.now()}`,
        body: "M2 live browser gated-action confirmation",
        visibility: "public",
      });
      await waitForConfirmed(request, manifest.api_base, gatedTx);
      const caseResponse = await request.get(`${manifest.api_base}/v1/poh/live/case/${encodeURIComponent(manifest.case_id)}`);
      const caseBody = await caseResponse.json();
      expect(String(caseBody?.case?.status || caseBody?.case?.outcome || "").toLowerCase()).toMatch(/awarded|approved|finalized/);
      const jurors = Array.isArray(caseBody?.case?.jurors) ? caseBody.case.jurors : [];
      expect(jurors.filter((record: any) => record?.accepted === true && record?.attended === true).length).toBeGreaterThanOrEqual(1);
      const storedAccounts = await Promise.all(opened.map(({ page }) => page.evaluate(() => JSON.parse(localStorage.getItem("weall_session_v1") || "{}").account)));
      expect(new Set(storedAccounts).size).toBe(opened.length);
    } finally {
      await Promise.all(opened.map(({ context }) => context.close()));
    }
  });
});
