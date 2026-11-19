import { defineConfig } from "@playwright/test";
import base from "./playwright.config";

// M4 account custody handles REAL private recovery material inside local
// browser sessions. Never retain screenshots, video, traces, or HTML reports
// containing that material as CI evidence. Fail deterministically, no retries.
export default defineConfig(base, {
  retries: 0,
  workers: 1,
  reporter: [["line"]],
  use: {
    trace: "off",
    screenshot: "off",
    video: "off",
  },
});
