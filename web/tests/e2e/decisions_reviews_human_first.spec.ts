import { expect, test } from "@playwright/test";

const HUMAN_FIRST_ROUTES = [
  {
    path: "/decisions",
    include: [/Decisions/i, /Current decisions/i],
    avoid: [/Governance/i, /Proposals/i, /route contract/i, /Hub surface/i, /nonce/i, /mempool/i, /quorum certificate/i],
  },
  {
    path: "/decisions/create",
    include: [/Create a community decision/i, /New community decision/i],
    avoid: [/Governance/i, /Proposal/i, /Action route only/i, /local signer/i, /Tier 3/i],
  },
  {
    path: "/reports",
    include: [/Reports/i, /visible reports/i],
    avoid: [/Disputes/i, /Juror/i, /adjudicate/i, /route contract/i, /Hub surface/i, /nonce/i],
  },
  {
    path: "/reviews",
    include: [/Review Queue/i, /Community Reviewer/i],
    avoid: [/Juror work/i, /Tier 3/i, /mempool/i, /nonce/i],
  },
];

test.describe("decisions and reviews use human-first language", () => {
  for (const route of HUMAN_FIRST_ROUTES) {
    test(`${route.path} avoids protocol-console wording`, async ({ page }) => {
      await page.goto(route.path);
      const body = page.locator("body");
      for (const pattern of route.include) await expect(body).toContainText(pattern);
      for (const pattern of route.avoid) await expect(body).not.toContainText(pattern);
    });
  }
});
