import { test, expect } from "@playwright/test";
import {
  createActorContext,
  loadM2ActorManifest,
  m2BrowserJourneyTimeoutMs,
  submitEncryptedAsyncFollowup,
  submitSkeleton,
  waitForAsyncCase,
  waitForConfirmed,
  waitForTier,
} from "./m2_actor_helpers";

const REQUIRE_REAL = String(process.env.WEALL_REQUIRE_M2_REAL_STACK || "") === "1";

test.describe("M2 independent-browser async Tier 1", () => {
  test("applicant and independently restored reviewers finalize canonical Tier 1", async ({ browser, request, baseURL }) => {
    test.setTimeout(m2BrowserJourneyTimeoutMs());
    if (!REQUIRE_REAL) test.skip(true, "set WEALL_REQUIRE_M2_REAL_STACK=1 for the mandatory external journey");
    const manifest = loadM2ActorManifest("async");
    const opened: Array<{ context: any; page: any }> = [];
    try {
      const applicant = await test.step("Restore applicant browser custody and canonical session", () =>
        createActorContext(browser, baseURL || "http://127.0.0.1:5173", manifest.applicant, manifest.api_base),
      );
      opened.push(applicant);
      const reviewerActors: Array<{ actor: any; reviewer: any }> = [];
      for (const reviewer of manifest.reviewers) {
        const actor = await test.step(`Restore reviewer browser custody and canonical session: ${reviewer.account}`, () =>
          createActorContext(browser, baseURL || "http://127.0.0.1:5173", reviewer, manifest.api_base),
        );
        opened.push(actor);
        reviewerActors.push({ actor, reviewer });
        await test.step(`Reviewer accepts async assignment: ${reviewer.account}`, async () => {
          const acceptId = await submitSkeleton(actor.page, manifest.api_base, reviewer.account, "pohAsyncTxJurorAccept", { case_id: manifest.case_id });
          await waitForConfirmed(request, manifest.api_base, acceptId);
        });
      }

      const lead = reviewerActors[0];
      await test.step("Lead reviewer requests encrypted follow-up evidence", async () => {
        const followupId = await submitSkeleton(lead.actor.page, manifest.api_base, lead.reviewer.account, "pohAsyncTxReview", {
          case_id: manifest.case_id,
          verdict: "needs_followup",
          reason_code: "m2_require_real_encrypted_browser_evidence",
          followup_round: 0,
        });
        await waitForConfirmed(request, manifest.api_base, followupId);
        await waitForAsyncCase(request, manifest.api_base, manifest.case_id, (record) =>
          String(record.status || "").toLowerCase() === "needs_followup" && Number(record.followup_round || 0) === 1,
        );
      });

      const encrypted = await test.step("Applicant encrypts, declares, and binds follow-up evidence", async () => {
        const result = await submitEncryptedAsyncFollowup({
          page: applicant.page,
          apiBase: manifest.api_base,
          caseId: manifest.case_id,
          applicant: manifest.applicant.account,
          recipients: manifest.reviewers.map((reviewer) => reviewer.account),
        });
        await waitForConfirmed(request, manifest.api_base, result.declareTxId);
        await waitForConfirmed(request, manifest.api_base, result.bindTxId);
        await waitForAsyncCase(request, manifest.api_base, manifest.case_id, (record) =>
          String(record.status || "").toLowerCase() === "under_review" && Number(record.followup_round || 0) === 1,
        );
        return result;
      });

      await test.step("Lead reviewer decrypts the reviewer-scoped evidence", async () => {
        await lead.actor.page.goto("/#/reviews?lane=poh_async_review");
        await lead.actor.page.getByRole("button", { name: "Load details" }).first().click();
        const decryptButton = lead.actor.page.getByTestId(`decrypt-evidence-${encrypted.evidenceId}`);
        await expect(decryptButton).toBeVisible();
        await decryptButton.click();
        await expect(lead.actor.page.getByTestId(`decrypted-evidence-${encrypted.evidenceId}`)).toHaveAttribute("src", /^blob:/);
      });

      for (const { actor, reviewer } of reviewerActors) {
        await test.step(`Reviewer approves encrypted follow-up: ${reviewer.account}`, async () => {
          const reviewId = await submitSkeleton(actor.page, manifest.api_base, reviewer.account, "pohAsyncTxReview", {
            case_id: manifest.case_id,
            verdict: "approve",
            reason_code: "m2_independent_browser_encrypted_review",
            followup_round: 1,
          });
          await waitForConfirmed(request, manifest.api_base, reviewId);
        });
      }
      const state = await test.step("Wait for canonical Tier 1 finalization", () =>
        waitForTier(request, manifest.api_base, manifest.applicant.account, 1),
      );
      expect(Number(state.poh_tier || 0)).toBeGreaterThanOrEqual(1);
      const caseResponse = await request.get(`${manifest.api_base}/v1/poh/async/case/${encodeURIComponent(manifest.case_id)}`);
      const caseBody = await caseResponse.json();
      const caseRecord = caseBody?.case || {};
      expect(String(caseRecord.outcome || caseRecord.status || "").toLowerCase()).toMatch(/approved|finalized/);
      expect(caseRecord.receipt || caseRecord.receipt_id).toBeTruthy();
      const storedAccounts = await Promise.all(opened.map(({ page }) => page.evaluate(() => JSON.parse(localStorage.getItem("weall_session_v1") || "{}").account)));
      expect(new Set(storedAccounts).size).toBe(opened.length);
    } finally {
      await Promise.all(opened.map(({ context }) => context.close()));
    }
  });
});
