import { config } from "./config";
import { getApiBaseUrl, setApiBaseUrl, validateApiBaseInput } from "../api/weall";

export const WEALL_API_BASE_CHANGED_EVENT = "weall-api-base-changed";

export type SeedNode = {
  url: string;
  name?: string;
  label?: string;
  description?: string;
  trusted?: boolean;
};

export type NodeProbePhase = "healthy" | "syncing" | "incompatible" | "offline";

export type NodeProbe = {
  baseUrl: string;
  label: string;
  description?: string;
  isCurrent: boolean;
  phase: NodeProbePhase;
  ok: boolean;
  reachable: boolean;
  ready: boolean;
  latencyMs: number | null;
  chainId?: string;
  height?: number;
  txIndexHash?: string;
  protocolProfileHash?: string;
  mode?: string;
  service?: string;
  errors: string[];
  score: number;
  status?: any;
  readyz?: any;
  consensus?: any;
};

function normalizeBase(value: string): string | null {
  const validation = validateApiBaseInput(String(value || "").trim());
  return validation.ok ? validation.normalized : null;
}

function displayBase(value: string): string {
  const normalized = normalizeBase(value) || "/";
  return normalized || "/";
}

function endpoint(base: string, path: string): string {
  const normalized = normalizeBase(base) || "/";
  if (!path.startsWith("/")) path = `/${path}`;
  if (normalized === "/") return path;
  return `${normalized}${path}`;
}

async function fetchJsonWithTimeout(url: string, timeoutMs: number): Promise<any> {
  const controller = new AbortController();
  const timer = window.setTimeout(() => controller.abort(), Math.max(500, timeoutMs));
  try {
    const res = await fetch(url, {
      method: "GET",
      headers: { Accept: "application/json" },
      signal: controller.signal,
    });
    const text = await res.text();
    let payload: any = null;
    try {
      payload = text ? JSON.parse(text) : null;
    } catch {
      payload = text;
    }
    if (!res.ok) {
      throw new Error(`HTTP ${res.status}`);
    }
    return payload;
  } finally {
    window.clearTimeout(timer);
  }
}

function seedFromUnknown(raw: unknown): SeedNode | null {
  if (!raw) return null;
  if (typeof raw === "string") {
    const url = normalizeBase(raw);
    return url ? { url } : null;
  }
  if (typeof raw !== "object" || Array.isArray(raw)) return null;
  const rec = raw as Record<string, unknown>;
  const url = normalizeBase(String(rec.url || rec.api_base || rec.apiBase || rec.base || ""));
  if (!url) return null;
  return {
    url,
    name: String(rec.name || rec.label || "").trim() || undefined,
    label: String(rec.label || rec.name || "").trim() || undefined,
    description: String(rec.description || rec.note || "").trim() || undefined,
    trusted: rec.trusted === true,
  };
}

function seedsFromPayload(payload: unknown): SeedNode[] {
  const candidates: unknown[] = [];
  if (Array.isArray(payload)) {
    candidates.push(...payload);
  } else if (payload && typeof payload === "object") {
    const rec = payload as Record<string, unknown>;
    if (Array.isArray(rec.nodes)) candidates.push(...rec.nodes);
    if (Array.isArray(rec.seeds)) candidates.push(...rec.seeds);
    if (Array.isArray(rec.items)) candidates.push(...rec.items);
  }
  return candidates.map(seedFromUnknown).filter((x): x is SeedNode => !!x);
}

function dedupeSeeds(seeds: SeedNode[]): SeedNode[] {
  const seen = new Set<string>();
  const out: SeedNode[] = [];
  for (const seed of seeds) {
    const url = normalizeBase(seed.url);
    if (!url || seen.has(url)) continue;
    seen.add(url);
    out.push({ ...seed, url });
  }
  return out;
}

export async function loadSeedNodes(seedsUrl = config.seedsUrl): Promise<SeedNode[]> {
  const configured = String(seedsUrl || "").trim();
  if (!configured) return [];
  try {
    const payload = await fetchJsonWithTimeout(configured, 2500);
    return dedupeSeeds(seedsFromPayload(payload));
  } catch {
    return [];
  }
}

export async function discoverCandidateNodes(): Promise<SeedNode[]> {
  const current = displayBase(getApiBaseUrl());
  const defaults = [
    seedFromUnknown({ url: current, label: "Current node", description: "The backend this browser is using now." }),
    seedFromUnknown({ url: config.defaultApiBase, label: "Build default", description: "The backend configured for this frontend build." }),
  ].filter((x): x is SeedNode => !!x);
  const seeds = await loadSeedNodes();
  return dedupeSeeds([...defaults, ...seeds]);
}

function safeStr(value: unknown): string | undefined {
  const out = String(value || "").trim();
  return out || undefined;
}

function safeNumber(value: unknown): number | undefined {
  const n = Number(value);
  return Number.isFinite(n) ? n : undefined;
}

function statusReady(raw: any): boolean {
  if (!raw || typeof raw !== "object") return false;
  if (raw.ok === true) return true;
  if (raw.ready === true) return true;
  if (raw.status === "ok" || raw.status === "ready") return true;
  return false;
}

function extractConsensusHash(consensus: any, status: any): { txIndexHash?: string; protocolProfileHash?: string } {
  const profile = consensus?.profile_compatibility || status?.profile_compatibility || {};
  const runtime = consensus?.runtime_profile || status?.runtime_profile || {};
  return {
    txIndexHash: safeStr(consensus?.tx_index_hash || profile?.tx_index_hash || status?.tx_index_hash),
    protocolProfileHash: safeStr(
      runtime?.protocol_profile_hash ||
      profile?.runtime_profile_hash ||
      profile?.protocol_profile_hash ||
      status?.protocol_profile_hash,
    ),
  };
}

function classifyProbe(args: {
  reachable: boolean;
  statusOk: boolean;
  ready: boolean;
  chainId?: string;
  txIndexHash?: string;
  protocolProfileHash?: string;
  errors: string[];
}): NodeProbePhase {
  if (!args.reachable) return "offline";
  if (!args.statusOk) return "syncing";
  if (args.errors.some((e) => e.includes("incompatible"))) return "incompatible";
  if (!args.ready) return "syncing";
  if (!args.chainId) return "syncing";
  return "healthy";
}

function scoreProbe(phase: NodeProbePhase, ready: boolean, height?: number, latencyMs?: number | null): number {
  let score = 0;
  if (phase === "healthy") score += 100;
  if (phase === "syncing") score += 55;
  if (phase === "incompatible") score += 20;
  if (ready) score += 10;
  if (typeof height === "number") score += Math.min(20, Math.max(0, height) / 1000);
  if (typeof latencyMs === "number") score += Math.max(0, 20 - Math.min(20, latencyMs / 50));
  return Math.round(score);
}

export async function probeNode(seed: SeedNode, opts?: { timeoutMs?: number; currentBase?: string }): Promise<NodeProbe> {
  const baseUrl = displayBase(seed.url);
  const currentBase = displayBase(opts?.currentBase || getApiBaseUrl());
  const timeoutMs = Math.max(500, opts?.timeoutMs ?? 3000);
  const started = performance.now();
  const errors: string[] = [];
  let status: any = null;
  let readyz: any = null;
  let consensus: any = null;

  try {
    status = await fetchJsonWithTimeout(endpoint(baseUrl, "/v1/status"), timeoutMs);
  } catch (e: any) {
    errors.push(`status:${String(e?.message || e || "failed")}`);
  }

  if (status) {
    try {
      readyz = await fetchJsonWithTimeout(endpoint(baseUrl, "/v1/readyz"), Math.min(timeoutMs, 2000));
    } catch (e: any) {
      errors.push(`readyz:${String(e?.message || e || "failed")}`);
    }

    try {
      consensus = await fetchJsonWithTimeout(endpoint(baseUrl, "/v1/status/consensus"), Math.min(timeoutMs, 2200));
    } catch {
      // Consensus diagnostics are helpful but not required for normal user access.
    }
  }

  const latencyMs = Math.max(1, Math.round(performance.now() - started));
  const reachable = !!status;
  const statusOk = statusReady(status);
  const ready = statusReady(readyz) || statusOk;
  const chainId = safeStr(status?.chain_id || consensus?.chain_id);
  const height = safeNumber(status?.height ?? consensus?.height);
  const { txIndexHash, protocolProfileHash } = extractConsensusHash(consensus, status);

  const phase = classifyProbe({ reachable, statusOk, ready, chainId, txIndexHash, protocolProfileHash, errors });
  return {
    baseUrl,
    label: seed.label || seed.name || (baseUrl === currentBase ? "Current node" : baseUrl),
    description: seed.description,
    isCurrent: baseUrl === currentBase,
    phase,
    ok: phase === "healthy",
    reachable,
    ready,
    latencyMs: reachable ? latencyMs : null,
    chainId,
    height,
    txIndexHash,
    protocolProfileHash,
    mode: safeStr(status?.mode || consensus?.mode),
    service: safeStr(status?.service),
    errors,
    score: scoreProbe(phase, ready, height, reachable ? latencyMs : null),
    status,
    readyz,
    consensus,
  };
}

export async function discoverNodeProbes(opts?: { timeoutMs?: number }): Promise<NodeProbe[]> {
  const currentBase = displayBase(getApiBaseUrl());
  const seeds = await discoverCandidateNodes();
  const probes = await Promise.all(seeds.map((seed) => probeNode(seed, { timeoutMs: opts?.timeoutMs, currentBase })));
  return probes.sort((a, b) => {
    if (a.isCurrent !== b.isCurrent) return a.isCurrent ? -1 : 1;
    return b.score - a.score || String(a.baseUrl).localeCompare(String(b.baseUrl));
  });
}

export function switchToNode(baseUrl: string): string {
  const runtimeBase = setApiBaseUrl(baseUrl);
  try {
    window.dispatchEvent(new CustomEvent(WEALL_API_BASE_CHANGED_EVENT, { detail: { baseUrl, runtimeBase } }));
  } catch {
    // Ignore event dispatch failures in non-browser test contexts.
  }
  return runtimeBase;
}

export function nodePhaseLabel(phase: NodeProbePhase): string {
  if (phase === "healthy") return "Healthy";
  if (phase === "syncing") return "Syncing";
  if (phase === "incompatible") return "Incompatible";
  return "Offline";
}

export function nodePhaseHint(probe: NodeProbe): string {
  if (probe.phase === "healthy") return "This node is reachable and ready for normal reads and submissions.";
  if (probe.phase === "syncing") return "This node is reachable but may still be catching up or missing readiness details.";
  if (probe.phase === "incompatible") return "This node responded, but its reported protocol identity does not look compatible.";
  return "This node could not be reached from this browser.";
}
