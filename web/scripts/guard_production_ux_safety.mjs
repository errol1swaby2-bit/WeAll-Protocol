#!/usr/bin/env node
/* global console, process */

/**
 * Static guardrail for production frontend posture.
 * This intentionally checks source-level invariants that do not require a browser:
 *   - production builds cannot expose demo/dev bootstrap or technical workbench routes
 *   - production builds default to same-origin API unless an explicit remote API is configured
 *   - API base overrides are validated before being stored
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function read(rel) {
  return fs.readFileSync(path.join(ROOT, rel), "utf8");
}

function requireContains(rel, needle, label) {
  const txt = read(rel);
  if (!txt.includes(needle)) {
    console.error(`ERROR: ${label} missing in ${rel}`);
    console.error(`Expected source to contain: ${needle}`);
    process.exitCode = 1;
  }
}

function requireRegex(rel, regex, label) {
  const txt = read(rel);
  if (!regex.test(txt)) {
    console.error(`ERROR: ${label} missing in ${rel}`);
    console.error(`Expected source to match: ${regex}`);
    process.exitCode = 1;
  }
}

function main() {
  requireContains(
    "src/lib/config.ts",
    "enableDevTools: !isProd &&",
    "production fail-closed dev-tools flag",
  );
  requireContains(
    "src/lib/config.ts",
    "enableDevBootstrap: !isProd &&",
    "production fail-closed dev-bootstrap flag",
  );
  requireContains(
    "src/lib/config.ts",
    "return isProd ? \"/\" : \"http://127.0.0.1:8000\";",
    "production same-origin API default",
  );
  requireContains("src/lib/config.ts", "isProduction: isProd", "production metadata export");

  requireContains(
    "src/App.tsx",
    "const showAdvancedMode = config.enableDevTools && settings.showAdvancedMode;",
    "advanced route rendering bound to build-time dev-tools flag",
  );
  requireContains(
    "src/App.tsx",
    "if (!config.enableDevBootstrap)",
    "dev bootstrap short-circuit when disabled",
  );

  requireContains(
    "src/pages/Settings.tsx",
    "{config.enableDevTools ? (",
    "settings page hides advanced toggles in production builds",
  );
  requireContains(
    "src/pages/Settings.tsx",
    "Advanced and tester surfaces are disabled in this production build.",
    "settings page explains production disabled advanced surfaces",
  );
  requireContains(
    "src/pages/Settings.tsx",
    "validateApiBaseInput(trimmed)",
    "settings validates API base before saving",
  );
  requireContains(
    "src/pages/Settings.tsx",
    "Remote genesis APIs are supported",
    "settings explains remote genesis API support",
  );

  requireContains("src/api/weall.ts", "export function validateApiBaseInput", "API base validator export");
  requireContains("src/api/weall.ts", "Only http:// and https:// backend URLs are supported.", "API base protocol validation");
  requireContains("src/api/weall.ts", "if (!validation.ok) throw new Error(validation.reason);", "API base setter rejects invalid targets");

  requireRegex(
    "src/lib/router.ts",
    /href: "\/advanced"[\s\S]*advancedOnly: true/,
    "advanced nav route remains hidden unless explicitly allowed",
  );

  if (process.exitCode) {
    console.error("Frontend production UX safety guard FAILED.");
    process.exit(process.exitCode);
  }
  console.log("OK: frontend production UX safety guard passed");
}

main();
