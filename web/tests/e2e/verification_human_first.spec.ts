import { expect, test } from "@playwright/test";

test("account verification page uses human-first account language", async ({ page }) => {
  await page.goto("/#/login");

  const bootstrap = page.getByTestId("load-demo-tester-session").first();
  if ((await bootstrap.count()) === 0) {
    test.skip(true, "dev bootstrap session control is not available in this environment");
  }

  await bootstrap.click();
  await page.waitForURL(/#\/home$/);
  await page.goto("/#/verification");

  await expect(page.getByRole("heading", { name: /know what your account can do/i })).toBeVisible();
  await expect(page.getByText("Your Account Status").first()).toBeVisible();
  await expect(page.getByText("Basic Account").first()).toBeVisible();
  await expect(page.getByText("Verified Person").first()).toBeVisible();
  await expect(page.getByText("Trusted Verified Person").first()).toBeVisible();
  await expect(page.getByText("Trusted Responsibilities").first()).toBeVisible();
  await expect(page.getByText("Verification History").first()).toBeVisible();

  await expect(page.getByText(/Level 3|Tier 3|Proof-of-Humanity/i)).toHaveCount(0);
});
