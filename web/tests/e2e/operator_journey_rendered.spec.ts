import { expect, test } from "@playwright/test";

async function loadDemoIfAvailable(page: import("@playwright/test").Page): Promise<boolean> {
  await page.goto("/#/login");
  const bootstrap = page.getByTestId("load-demo-tester-session").first();
  if ((await bootstrap.count()) === 0) return false;
  await bootstrap.click();
  await page.waitForURL(/#\/home$/);
  return true;
}

test("settings accent tone changes actual CSS variables", async ({ page }) => {
  await page.goto("/#/settings");
  await expect(page.getByRole("heading", { name: /personalize this browser client/i })).toBeVisible();

  const before = await page.evaluate(() => getComputedStyle(document.documentElement).getPropertyValue("--accent").trim());
  await page.getByLabel(/accent tone/i).selectOption("gold");
  await expect.poll(async () => page.evaluate(() => getComputedStyle(document.documentElement).getPropertyValue("--accent").trim())).toBe("#f4c95d");
  await expect.poll(async () => page.evaluate(() => getComputedStyle(document.documentElement).getPropertyValue("--accent-rgb").trim())).toBe("244, 201, 93");
  expect(before).not.toBe("#f4c95d");
});

test("operator dashboard exposes blocker wizard and public-beta boundaries", async ({ page }) => {
  const loaded = await loadDemoIfAvailable(page);
  if (!loaded) test.skip(true, "demo account is not available in this build");

  await page.goto("/#/node");
  await expect(page.getByRole("heading", { name: /fix readiness blockers in order/i })).toBeVisible();
  await expect(page.getByText(/Safe switch command preview/i)).toBeVisible();
  await expect(page.getByText(/Public beta remains blocked/i)).toBeVisible();
  await expect(page.getByText(/Helper production/i)).toBeVisible();
});

test("transactions page renders peer propagation lifecycle", async ({ page }) => {
  const loaded = await loadDemoIfAvailable(page);
  if (!loaded) test.skip(true, "demo account is not available in this build");

  await page.evaluate(() => localStorage.setItem("weall_client_settings_v3", JSON.stringify({ showGenesisBootstrap: false, showAdvancedMode: true, themeMode: "dark", accentTone: "mint", fontScale: "md", density: "comfortable", motionMode: "full" })));
  await page.goto("/#/transactions");
  await expect(page.getByText(/Transaction activity/i)).toBeVisible();
  await expect(page.getByText(/Gossiped to peers|Peer propagation lifecycle|No catalog entries matched/i).first()).toBeVisible();
});
