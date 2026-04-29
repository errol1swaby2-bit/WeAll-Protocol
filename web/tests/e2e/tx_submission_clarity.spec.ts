import { test, expect } from "@playwright/test";

test("conference path keeps duplicate mutation clicks from creating a second in-flight action", async ({ page }) => {
  await page.goto("/login");
  await page.waitForLoadState("networkidle");

  const bootstrap = page.getByRole("button", { name: /use seeded conference identity/i });
  if (await bootstrap.count()) {
    await bootstrap.click();
  }

  await page.goto("/groups");
  await page.waitForLoadState("networkidle");

  const joinButtons = page.getByRole("button", { name: /join group|membership request/i });
  if (await joinButtons.count()) {
    const first = joinButtons.first();
    await first.click();
    await first.click({ force: true });
    await expect(page.getByText(/already being submitted|waiting for the current attempt/i)).toBeVisible();
  }
});
