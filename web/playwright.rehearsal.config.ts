import { defineConfig, devices } from "@playwright/test";

// The exact README launcher must already be running. No fixture server,
// skipped tests, traces, screenshots, videos or recovery material artifacts.
export default defineConfig({
  testDir: "./tests/rehearsal",
  timeout: 360_000,
  retries: 0,
  workers: 1,
  reporter: [["line"]],
  use: { ...devices["Desktop Chrome"], trace: "off", screenshot: "off", video: "off" },
});
