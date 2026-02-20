import { test, expect } from "@playwright/test";

test("smoke: home renders and navigation works", async ({ page }) => {
  await page.goto("/");

  // Home
  await expect(page.getByRole("heading")).toContainText("WeAll", { timeout: 15000 });

  // Connection pill should exist (env label + base shown)
  await expect(page.getByText("h:", { exact: false })).toBeVisible({ timeout: 15000 });

  // Navigate to PoH
  await page.getByRole("button", { name: "Open PoH" }).click();
  await expect(page.getByRole("heading", { name: "Proof of Humanity (Tier 1)" })).toBeVisible({ timeout: 15000 });

  // Navigate to Feed
  await page.goto("/feed");
  await expect(page.getByRole("heading", { name: "Feed" })).toBeVisible({ timeout: 15000 });

  // Feed should either show items or "(no items)" — but must not crash.
  await expect(page.locator("body")).not.toContainText("Something went wrong");
});
