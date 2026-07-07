// web/src/lib/config.ts
//
// Centralized build/runtime configuration.
// Keep this file tiny and boring: it should be safe to import anywhere.

import { webVersion } from "./version";
import { useMemo } from "react";
import { loadSettings, type ClientSettings } from "./settings";

export type AppConfig = {
  appName: string;
  envLabel: string;
  // True when this is a Vite production build. Production builds must fail closed for demo/dev surfaces.
  isProduction: boolean;
  // When false, dev-only pages and mutation helpers MUST NOT render.
  enableDevTools: boolean;
  // When true, the client may hydrate a local dev tester profile from a manifest.
  enableDevBootstrap: boolean;

  // Client metadata attached to requests
  clientName: string;
  clientVersion: string;

  // Network
  publicTestnet: boolean;
  defaultApiBase: string;
  // Where to fetch initial seed node list (JSON). If empty, node selection falls back to user list / configured base.
  seedsUrl: string;
  // Optional build-pinned compatibility commitments. External/testnet builds should set these
  // from the public chain manifest so the first reachable/current node cannot define the
  // expected network identity for the user.
  expectedChainId: string;
  expectedGenesisHash: string;
  expectedTxIndexHash: string;
  expectedProtocolProfileHash: string;
  // Dev-only manifest used to preload a local tester account/signer/session.
  devBootstrapManifestUrl: string;
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

function defaultApiBase(): string {
  const configured = env("VITE_WEALL_API_BASE").trim();
  if (configured) return configured;
  // Production web builds should not default external users to their own localhost.
  // Same-origin keeps a hosted UI pointed at the deployment's API unless an explicit remote genesis API is configured.
  return isProd ? "/" : "http://127.0.0.1:8000";
}

const injectedVersion = webVersion();

export const config: AppConfig = {
  appName: env("VITE_WEALL_APP_NAME").trim() || "WeAll",
  envLabel: env("VITE_WEALL_ENV_LABEL").trim() || (isProd ? "prod" : "dev"),
  isProduction: isProd,
  enableDevTools: !isProd && (truthy(env("VITE_WEALL_ENABLE_DEV_TOOLS")) || enableDevToolsDefault),
  enableDevBootstrap: !isProd && truthy(env("VITE_WEALL_ENABLE_DEV_BOOTSTRAP")),

  clientName: env("VITE_WEALL_CLIENT_NAME").trim() || "weall-web",
  // Prefer Vite-injected version to avoid manual drift; env can override if desired.
  clientVersion: env("VITE_WEALL_CLIENT_VERSION").trim() || injectedVersion || "0.0.0",

  publicTestnet: truthy(env("VITE_WEALL_PUBLIC_TESTNET")),
  defaultApiBase: defaultApiBase(),

  // Default to same-origin /seeds.json so a static webfront can ship its own seed list.
  seedsUrl: env("VITE_WEALL_SEED_MANIFEST_URL").trim() || env("VITE_WEALL_SEEDS_URL").trim() || "/seeds.json",
  expectedChainId: env("VITE_WEALL_EXPECTED_CHAIN_ID").trim(),
  expectedGenesisHash: env("VITE_WEALL_EXPECTED_GENESIS_HASH").trim(),
  expectedTxIndexHash: env("VITE_WEALL_EXPECTED_TX_INDEX_HASH").trim(),
  expectedProtocolProfileHash: env("VITE_WEALL_EXPECTED_PROTOCOL_PROFILE_HASH").trim(),
  devBootstrapManifestUrl: env("VITE_WEALL_DEV_BOOTSTRAP_MANIFEST").trim() || "/dev-bootstrap.json",
};

// Tiny hook wrapper to keep pages stable if we later swap to context-driven config.
export function useAppConfig(): AppConfig {
  // config is static (from Vite env); memo keeps hook semantics clean.
  return useMemo(() => config, []);
}


export function canShowAdvancedMode(settings?: Pick<ClientSettings, "showAdvancedMode">): boolean {
  const clientSettings = settings ?? loadSettings();
  return config.enableDevTools && clientSettings.showAdvancedMode === true;
}
