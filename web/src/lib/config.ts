// web/src/lib/config.ts
//
// Centralized build/runtime configuration.
// Keep this file tiny and boring: it should be safe to import anywhere.

import { webVersion } from "./version";

export type AppConfig = {
  appName: string;
  envLabel: string;
  // When false, dev-only pages and mutation helpers MUST NOT render.
  enableDevTools: boolean;

  // Client metadata attached to requests
  clientName: string;
  clientVersion: string;

  // Turnstile
  turnstileSiteKey: string;

  // Network
  defaultApiBase: string;
  // Where to fetch initial seed node list (JSON). If empty, node selection falls back to user list / configured base.
  seedsUrl: string;
};

function env(k: string): string {
  return ((import.meta as any).env?.[k] as string) || "";
}

function truthy(v: string): boolean {
  const s = (v || "").trim().toLowerCase();
  return s === "1" || s === "true" || s === "yes" || s === "on";
}

export const isProd = Boolean((import.meta as any).env?.PROD);
export const mode = String((import.meta as any).env?.MODE || "unknown");

// IMPORTANT: prod default must be safe.
const enableDevToolsDefault = !isProd;

const injectedVersion = webVersion();

export const config: AppConfig = {
  appName: env("VITE_WEALL_APP_NAME").trim() || "WeAll",
  envLabel: env("VITE_WEALL_ENV_LABEL").trim() || (isProd ? "prod" : "dev"),
  enableDevTools: truthy(env("VITE_WEALL_ENABLE_DEV_TOOLS")) || enableDevToolsDefault,

  clientName: env("VITE_WEALL_CLIENT_NAME").trim() || "weall-web",
  // Prefer Vite-injected version to avoid manual drift; env can override if desired.
  clientVersion: env("VITE_WEALL_CLIENT_VERSION").trim() || injectedVersion || "0.0.0",

  turnstileSiteKey: env("VITE_TURNSTILE_SITE_KEY").trim() || "",

  defaultApiBase: env("VITE_WEALL_API_BASE").trim() || "http://127.0.0.1:8000",

  // Default to same-origin /seeds.json so a Cloudflare-hosted webfront can ship its own seed list.
  seedsUrl: env("VITE_WEALL_SEEDS_URL").trim() || "/seeds.json",
};
