import { defineConfig, devices } from "@playwright/test";

const chromiumArgs = (process.env.PLAYWRIGHT_CHROMIUM_ARGS ?? "")
  .split(",")
  .map((value) => value.trim())
  .filter(Boolean);

export default defineConfig({
  testDir: "./tests/e2e",
  outputDir: process.env.PLAYWRIGHT_OUTPUT_DIR ?? "test-results-production",
  timeout: 30_000,
  expect: { timeout: 10_000 },
  fullyParallel: false,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [["github"]] : [["list"]],
  use: {
    baseURL: process.env.PLAYWRIGHT_BASE_URL ?? "http://127.0.0.1:8088",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
  },
  projects: [
    {
      name: "chromium",
      use: {
        ...devices["Desktop Chrome"],
        launchOptions: chromiumArgs.length > 0 ? { args: chromiumArgs } : undefined,
      },
    },
  ],
});
