import { defineConfig, devices } from "@playwright/test";

const chromiumArgs = (process.env.PLAYWRIGHT_CHROMIUM_ARGS ?? "")
  .split(",")
  .map((value) => value.trim())
  .filter(Boolean);

const htmlOutputFolder = process.env.PLAYWRIGHT_HTML_OUTPUT_DIR ?? "playwright-report";
const testOutputDir = process.env.PLAYWRIGHT_OUTPUT_DIR ?? "test-results";
const retainFailureTrace = String(process.env.WEALL_M2_TRACE || "") === "1";

export default defineConfig({
  testDir: "./tests/e2e",
  outputDir: testOutputDir,
  timeout: 30_000,
  expect: { timeout: 10_000 },
  fullyParallel: true,
  retries: process.env.CI ? 2 : 0,
  reporter: process.env.CI
    ? [["github"], ["html", { open: "never", outputFolder: htmlOutputFolder }]]
    : [["list"], ["html", { open: "never", outputFolder: htmlOutputFolder }]],
  use: {
    baseURL: process.env.PLAYWRIGHT_BASE_URL ?? "http://127.0.0.1:5173",
    trace: retainFailureTrace ? "retain-on-failure" : "on-first-retry",
    screenshot: "only-on-failure",
    video: "retain-on-failure"
  },
  webServer: {
    command: "npm run dev -- --host 127.0.0.1 --port 5173",
    url: "http://127.0.0.1:5173",
    reuseExistingServer: !process.env.CI,
    timeout: 60_000
  },
  projects: [
    {
      name: "chromium",
      use: {
        ...devices["Desktop Chrome"],
        launchOptions: chromiumArgs.length > 0 ? { args: chromiumArgs } : undefined
      }
    }
  ]
});
