import { apiGet } from "../api/weall";

type ChainStatus = {
  chain_id?: string;
};

let cachedChainId: string | null = null;
let cachedAtMs = 0;

const TTL_MS = 60_000;

export async function getChainId(): Promise<string> {
  const now = Date.now();
  if (cachedChainId && now - cachedAtMs < TTL_MS) return cachedChainId;

  // Prefer a stable status endpoint. If your backend uses a different one,
  // update this path to match.
  const status = (await apiGet("/v1/status")) as ChainStatus;

  const chainId = status?.chain_id;
  if (!chainId || typeof chainId !== "string") {
    throw new Error("Unable to determine chain_id from /v1/status");
  }

  cachedChainId = chainId;
  cachedAtMs = now;
  return chainId;
}

/** Allow overriding via env for locked-down deployments */
export function getEnvChainId(): string | null {
  // Vite exposes only VITE_* env vars
  const v = (import.meta as any).env?.VITE_WEALL_CHAIN_ID;
  if (typeof v === "string" && v.trim().length > 0) return v.trim();
  return null;
}
