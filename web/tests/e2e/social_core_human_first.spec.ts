import { expect, test } from "@playwright/test";

test("core social surfaces use human-first labels", async ({ page }) => {
  await page.goto("/#/login");

  const bootstrap = page.getByTestId("load-demo-tester-session").first();
  if ((await bootstrap.count()) === 0) {
    test.skip(true, "dev bootstrap session control is not available in this environment");
  }

  await bootstrap.click();
  await page.waitForURL(/#\/home$/);

  await expect(page.getByRole("heading", { name: /welcome back to weall/i })).toBeVisible();
  await expect(page.getByRole("button", { name: /create post/i })).toBeVisible();

  await page.goto("/#/feed");
  await expect(page.getByRole("heading", { name: /see what people are sharing/i })).toBeVisible();
  await expect(page.getByRole("button", { name: /all posts/i })).toBeVisible();

  await page.goto("/#/groups");
  await expect(page.getByRole("heading", { name: /find your communities/i })).toBeVisible();

  await expect(page.getByText(/route contract|transaction-backed|nonce|mempool|tier 3/i)).toHaveCount(0);
});
