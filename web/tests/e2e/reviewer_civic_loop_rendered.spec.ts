import { expect, test } from "@playwright/test";

const REVIEWER_CIVIC_LOOP = [
  { path: "/profile", include: [/Account/i, /Profile/i] },
  { path: "/verification", include: [/Know what your account can do/i, /Your Account Status/i] },
  { path: "/feed", include: [/Latest protocol activity/i, /Read visible public activity/i, /My posts/i] },
  { path: "/groups", include: [/Find your communities/i, /Groups/i] },
  { path: "/decisions", include: [/Decisions/i, /Current decisions/i] },
  { path: "/reports", include: [/Reports/i, /visible reports/i] },
  { path: "/reviews", include: [/Review Center/i, /Community Reviewer/i] },
  { path: "/activity", include: [/Activity notices/i, /Visibility cannot/i] },
  { path: "/node", include: [/Local node control surface/i, /public beta/i] },
  { path: "/economics", include: [/Economics & Treasury/i, /never unlocks economics by itself/i, /locked/i] },
] as const;

async function loadSeededReviewerSession(page: import("@playwright/test").Page): Promise<boolean> {
  await page.goto("/#/login");
  await expect(page.getByRole("heading", { name: /sign in to weall/i })).toBeVisible();

  const bootstrap = page.getByTestId("load-demo-tester-session").first();
  if ((await bootstrap.count()) === 0) return false;

  await bootstrap.click();
  await page.waitForURL(/#\/home$/);
  return true;
}

test("reviewer civic loop renders in order against the configured backend", async ({ page }) => {
  const loaded = await loadSeededReviewerSession(page);
  if (!loaded) test.skip(true, "seeded dev/reviewer session is not available; run with a configured backend and dev-bootstrap manifest");

  const consoleErrors: string[] = [];
  const pageErrors: string[] = [];
  page.on("console", (msg) => {
    if (msg.type() === "error") consoleErrors.push(msg.text());
  });
  page.on("pageerror", (err) => pageErrors.push(String(err)));

  for (const step of REVIEWER_CIVIC_LOOP) {
    await page.goto(`/#${step.path}`);
    await expect(page).toHaveURL(new RegExp(`#${step.path.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}$`));
    for (const pattern of step.include) {
      await expect(page.locator("body"), `${step.path} should expose ${pattern}`).toContainText(pattern);
    }
  }

  await expect(page.locator("body")).not.toContainText(/public mainnet ready|mainnet-scale|globally ready for 2350 TPS/i);
  expect(pageErrors, "Rendered civic-loop pages must not throw page errors").toEqual([]);
  expect(consoleErrors, "Rendered civic-loop pages must not emit console errors").toEqual([]);
});
