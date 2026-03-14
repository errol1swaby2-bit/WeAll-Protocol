import { test, expect } from "@playwright/test";

test("app loads and navigates core pages", async ({ page }) => {
  const consoleErrors: string[] = [];
  const pageErrors: string[] = [];

  page.on("console", (msg) => {
    if (msg.type() === "error") consoleErrors.push(msg.text());
  });

  page.on("pageerror", (err) => {
    pageErrors.push(String(err));
  });

  await page.goto("/");

  // Wait for React to actually render something (at least one element under #root)
  // If this fails, we dump console/page errors to make it obvious what's wrong.
  try {
    await page.waitForFunction(() => {
      const root = document.getElementById("root");
      if (!root) return false;
      // must have at least one rendered element
      return root.querySelectorAll("*").length > 0;
    }, null, { timeout: 15_000 });
  } catch {
    const dbg = [
      "App failed to render any elements under #root.",
      "",
      "Page errors:",
      ...(pageErrors.length ? pageErrors : ["(none)"]),
      "",
      "Console errors:",
      ...(consoleErrors.length ? consoleErrors : ["(none)"])
    ].join("\n");
    throw new Error(dbg);
  }

  // If there are startup errors, fail with them immediately.
  if (pageErrors.length || consoleErrors.length) {
    const dbg = [
      "App rendered but emitted errors.",
      "",
      "Page errors:",
      ...(pageErrors.length ? pageErrors : ["(none)"]),
      "",
      "Console errors:",
      ...(consoleErrors.length ? consoleErrors : ["(none)"])
    ].join("\n");
    throw new Error(dbg);
  }

  // Basic navigation (hash router). We verify the app still renders content.
  await page.goto("/#/feed");
  await expect(page.locator("#root")).toBeVisible();

  await page.goto("/#/poh");
  await expect(page.locator("#root")).toBeVisible();

  await page.goto("/#/proposals");
  await expect(page.locator("#root")).toBeVisible();
});
