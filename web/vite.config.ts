import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { readFileSync } from "node:fs";
import { execSync } from "node:child_process";
import path from "node:path";

const DEV_CSP =
  "default-src 'self'; base-uri 'self'; frame-ancestors 'none'; object-src 'none'; " +
  "script-src 'self' 'unsafe-eval' https://challenges.cloudflare.com; " +
  "style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; " +
  "connect-src 'self' http: https: ws: wss:; frame-src https://challenges.cloudflare.com;";

const PREVIEW_CSP =
  "default-src 'self'; base-uri 'self'; frame-ancestors 'none'; object-src 'none'; " +
  "script-src 'self' https://challenges.cloudflare.com; " +
  "style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; " +
  "connect-src 'self' http: https: ws: wss:; frame-src https://challenges.cloudflare.com;";

function safeReadPackageVersion(): string {
  try {
    const p = path.resolve(process.cwd(), "package.json");
    const raw = readFileSync(p, "utf-8");
    const pkg = JSON.parse(raw);
    return String(pkg?.version || "0.0.0");
  } catch {
    return "0.0.0";
  }
}

function safeGitSha(): string {
  try {
    const out = execSync("git rev-parse --short HEAD", { stdio: ["ignore", "pipe", "ignore"] })
      .toString()
      .trim();
    return out || "nogit";
  } catch {
    return "nogit";
  }
}

const PKG_VERSION = safeReadPackageVersion();
const GIT_SHA = safeGitSha();

// Vite dev proxy: /v1 -> localhost:8000 to avoid CORS in dev.
// In production, you can either:
// - Serve UI and API behind the same origin (recommended), OR
// - Allow CORS and keep connect-src open as above.
export default defineConfig({
  plugins: [react()],
  define: {
    __WEALL_WEB_VERSION__: JSON.stringify(PKG_VERSION),
    __WEALL_WEB_GIT_SHA__: JSON.stringify(GIT_SHA),
  },
  server: {
    host: true,
    port: 5173,
    headers: {
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "no-referrer",
      "X-Frame-Options": "DENY",
      "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
      "Cross-Origin-Opener-Policy": "same-origin",
      "Cross-Origin-Resource-Policy": "same-origin",
      "Content-Security-Policy": DEV_CSP,
    },
    proxy: {
      "/v1": { target: "http://localhost:8000", changeOrigin: true },
    },
  },
  preview: {
    headers: {
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "no-referrer",
      "X-Frame-Options": "DENY",
      "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
      "Cross-Origin-Opener-Policy": "same-origin",
      "Cross-Origin-Resource-Policy": "same-origin",
      "Content-Security-Policy": PREVIEW_CSP,
    },
  },
});

