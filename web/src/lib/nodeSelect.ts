// web/src/lib/nodeSelect.ts
//
// Production-minded node selection for a "every node is an API node" topology.
//
// Goals:
//   - Load a seed list (default: /seeds.json on the webfront origin)
//   - Probe candidate nodes in parallel with short timeouts
//   - Select a primary write node + a small set of fallbacks
//   - Cache selection for a short TTL to avoid flapping
//   - Allow user overrides via localStorage (manual candidates + API base override)
//
// This file intentionally avoids React. It can be used from any UI layer.

import { getApiBaseUrl, httpJson, setApiBaseUrl, stripTrailingSlashes } from "../api/weall";
import { config } from "./config";

const LS_NODE_CANDIDATES = "weall.nodeCandidates"; // user-managed list
const LS_NODE_SELECTION = "weall.nodeSelection"; // cached pick

// Cache/selection tuning
const DEFAULT_PICK_TTL_MS = 15 * 60 * 1000; // 15 minutes
const DEFAULT_PROBE_TIMEOUT_MS = 2500;
const DEFAULT_MAX_FALLBACKS = 3;
const DEFAULT_PROBE_CONCURRENCY = 8;

export type NodeCandidate = {
  base_url: string;
  weight: number;
  name?: string;
  region?: string;
};

export type SeedDocument = {
  chain_id?: string;
  schema_version?: number;
  seeds?: string[];
};

export type ReadyResponse = {
  ok: boolean;
  service?: string;
  version?: string;
  ts_ms?: number;
  chain_id?: string | null;
  height?: number | null;
  tip?: string | null;
  tx_index_hash?: string | null;
};

export type NodeProbe = {
  base_url: string;
  ok: boolean;
  chain_id: string;
  height: number;
  tip: string;
  tx_index_hash: string;
  rtt_ms: number;
  weight: number;
};

export type NodeSelection = {
  primary: string;
  fallbacks: string[];
  picked_ts_ms: number;
  ttl_ms: number;
  chain_id: string;
  tx_index_hash: string;
};

function nowMs(): number {
  return Date.now();
}

function clampInt(n: any, fallback = 1): number {
  const x = Number(n);
  if (!Number.isFinite(x)) return fallback;
  return Math.max(1, Math.floor(x));
}

function normalizeUrl(raw: any): string {
  return stripTrailingSlashes(String(raw || "").trim());
}

function normalizeCandidate(raw: any): NodeCandidate | null {
  const url = normalizeUrl(raw?.base_url || raw?.url || raw);
  if (!url) return null;
  return {
    base_url: url,
    weight: clampInt(raw?.weight, 1),
    name: raw?.name ? String(raw.name) : undefined,
    region: raw?.region ? String(raw.region) : undefined,
  };
}

function uniqUrls(urls: string[]): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const u of urls) {
    const n = normalizeUrl(u);
    if (!n) continue;
    if (seen.has(n)) continue;
    seen.add(n);
    out.push(n);
  }
  return out;
}

export function getNodeCandidates(): NodeCandidate[] {
  if (typeof window === "undefined") return [];
  const raw = window.localStorage.getItem(LS_NODE_CANDIDATES);
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.map(normalizeCandidate).filter(Boolean) as NodeCandidate[];
  } catch {
    return [];
  }
}

export function setNodeCandidates(nodes: NodeCandidate[]): void {
  if (typeof window === "undefined") return;
  const cleaned = (nodes || []).map(normalizeCandidate).filter(Boolean) as NodeCandidate[];
  window.localStorage.setItem(LS_NODE_CANDIDATES, JSON.stringify(cleaned));
}

export function addNodeCandidate(baseUrl: string, opts?: { weight?: number; name?: string; region?: string }): void {
  const url = normalizeUrl(baseUrl);
  if (!url || typeof window === "undefined") return;
  const existing = getNodeCandidates();
  const without = existing.filter((n) => normalizeUrl(n.base_url) !== url);
  without.unshift({
    base_url: url,
    weight: clampInt(opts?.weight, 1),
    name: opts?.name,
    region: opts?.region,
  });
  setNodeCandidates(without);
}

function readCachedSelection(): NodeSelection | null {
  if (typeof window === "undefined") return null;
  const raw = window.localStorage.getItem(LS_NODE_SELECTION);
  if (!raw) return null;
  try {
    const v = JSON.parse(raw);
    if (!v || typeof v !== "object") return null;
    const primary = normalizeUrl(v.primary);
    const fallbacks = Array.isArray(v.fallbacks) ? v.fallbacks.map(normalizeUrl).filter(Boolean) : [];
    const picked_ts_ms = Number(v.picked_ts_ms);
    const ttl_ms = Number(v.ttl_ms);
    const chain_id = String(v.chain_id || "");
    const tx_index_hash = String(v.tx_index_hash || "");
    if (!primary) return null;
    if (!Number.isFinite(picked_ts_ms) || !Number.isFinite(ttl_ms)) return null;
    if (!chain_id || !tx_index_hash) return null;
    return {
      primary,
      fallbacks: uniqUrls(fallbacks),
      picked_ts_ms: Math.floor(picked_ts_ms),
      ttl_ms: Math.max(10_000, Math.floor(ttl_ms)),
      chain_id,
      tx_index_hash,
    };
  } catch {
    return null;
  }
}

function writeCachedSelection(sel: NodeSelection): void {
  if (typeof window === "undefined") return;
  window.localStorage.setItem(LS_NODE_SELECTION, JSON.stringify(sel));
}

function isSelectionFresh(sel: NodeSelection): boolean {
  const age = nowMs() - sel.picked_ts_ms;
  return age >= 0 && age <= sel.ttl_ms;
}

async function fetchSeeds(timeoutMs: number): Promise<SeedDocument | null> {
  // Seeds are fetched from the webfront origin by default.
  const url = String(config.seedsUrl || "").trim();
  if (!url) return null;

  const ac = timeoutMs ? new AbortController() : null;
  const timer = timeoutMs ? window.setTimeout(() => ac?.abort("timeout"), timeoutMs) : null;

  try {
    const r = await fetch(url, { method: "GET", signal: ac?.signal });
    if (!r.ok) return null;
    const txt = await r.text();
    const data = txt ? JSON.parse(txt) : null;
    if (!data || typeof data !== "object") return null;
    return data as SeedDocument;
  } catch {
    return null;
  } finally {
    if (timer != null) window.clearTimeout(timer);
  }
}

async function probeReady(base: string, timeoutMs: number): Promise<{ ready: ReadyResponse; rtt_ms: number } | null> {
  const url = normalizeUrl(base);
  if (!url) return null;

  const t0 = nowMs();
  try {
    const ready = await httpJson<ReadyResponse>("/v1/readyz", { base: url, timeoutMs });
    const rtt_ms = Math.max(0, nowMs() - t0);
    if (!ready || typeof ready !== "object") return null;
    return { ready, rtt_ms };
  } catch {
    return null;
  }
}

function toProbe(base: string, weight: number, ready: ReadyResponse, rtt_ms: number): NodeProbe | null {
  const chain_id = String(ready.chain_id || "").trim();
  const tx_index_hash = String(ready.tx_index_hash || "").trim();
  const height = Number(ready.height ?? 0);
  const tip = String(ready.tip || "").trim();

  if (!ready.ok) return null;
  if (!chain_id || !tx_index_hash) return null;

  return {
    base_url: normalizeUrl(base),
    ok: true,
    chain_id,
    height: Number.isFinite(height) ? Math.floor(height) : 0,
    tip,
    tx_index_hash,
    rtt_ms: Math.max(0, Math.floor(rtt_ms)),
    weight: clampInt(weight, 1),
  };
}

function scoreProbe(p: NodeProbe, target?: { chain_id?: string; tx_index_hash?: string }): number {
  // Hard filters: chain_id + tx_index_hash must match the target if provided.
  if (target?.chain_id && p.chain_id !== target.chain_id) return -Infinity;
  if (target?.tx_index_hash && p.tx_index_hash !== target.tx_index_hash) return -Infinity;

  // Score: prioritize height, then lower RTT, then weight.
  // Height dominates to avoid reading from stale nodes.
  const heightScore = p.height * 1_000_000;
  const rttPenalty = Math.min(2500, p.rtt_ms) * 100; // keep it smaller than a single block height step
  const weightScore = p.weight * 10;
  return heightScore - rttPenalty + weightScore;
}

async function mapConcurrent<T, R>(items: T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const out: R[] = [];
  let idx = 0;

  async function worker() {
    while (idx < items.length) {
      const my = idx++;
      const item = items[my];
      try {
        out[my] = await fn(item);
      } catch {
        // @ts-ignore
        out[my] = null;
      }
    }
  }

  const n = Math.max(1, Math.min(limit, items.length));
  await Promise.all(Array.from({ length: n }, () => worker()));
  return out;
}

function buildCandidateList(seeds: string[], user: NodeCandidate[], configuredBase: string): NodeCandidate[] {
  const map = new Map<string, NodeCandidate>();

  // Start with seeds at weight=1.
  for (const s of seeds) {
    const url = normalizeUrl(s);
    if (!url) continue;
    if (!map.has(url)) map.set(url, { base_url: url, weight: 1 });
  }

  // User candidates override weight/name.
  for (const u of user) {
    const c = normalizeCandidate(u);
    if (!c) continue;
    map.set(c.base_url, c);
  }

  // Always include configured base (API override / env default).
  const cfg = normalizeUrl(configuredBase);
  if (cfg) {
    const existing = map.get(cfg);
    map.set(cfg, existing ? { ...existing } : { base_url: cfg, weight: 1 });
  }

  return Array.from(map.values());
}

export async function pickNodes(opts?: {
  timeoutMs?: number;
  ttlMs?: number;
  maxFallbacks?: number;
  concurrency?: number;
}): Promise<NodeSelection> {
  const timeoutMs = opts?.timeoutMs ?? DEFAULT_PROBE_TIMEOUT_MS;
  const ttlMs = opts?.ttlMs ?? DEFAULT_PICK_TTL_MS;
  const maxFallbacks = opts?.maxFallbacks ?? DEFAULT_MAX_FALLBACKS;
  const concurrency = opts?.concurrency ?? DEFAULT_PROBE_CONCURRENCY;

  const seedDoc = await fetchSeeds(Math.min(timeoutMs, 2000));
  const seedUrls = Array.isArray(seedDoc?.seeds) ? seedDoc!.seeds!.map((s) => String(s)) : [];

  const candidates = buildCandidateList(seedUrls, getNodeCandidates(), getApiBaseUrl());
  const uniq = candidates.filter((c) => !!normalizeUrl(c.base_url));

  // Probe all candidates (bounded concurrency).
  const probes = await mapConcurrent(uniq, concurrency, async (c) => {
    const res = await probeReady(c.base_url, timeoutMs);
    if (!res) return null;
    return toProbe(c.base_url, c.weight, res.ready, res.rtt_ms);
  });

  const good = probes.filter(Boolean) as NodeProbe[];
  if (!good.length) {
    // Fail-safe: fallback to configured base without claiming readiness.
    const base = normalizeUrl(getApiBaseUrl());
    const sel: NodeSelection = {
      primary: base,
      fallbacks: [],
      picked_ts_ms: nowMs(),
      ttl_ms: Math.max(10_000, ttlMs),
      chain_id: "",
      tx_index_hash: "",
    };
    return sel;
  }

  // Choose a target chain_id/tx_index_hash.
  // Prefer the seedDoc chain_id if present; otherwise choose the modal chain_id among probes.
  let targetChain = String(seedDoc?.chain_id || "").trim();
  if (!targetChain) {
    const counts = new Map<string, number>();
    for (const p of good) counts.set(p.chain_id, (counts.get(p.chain_id) || 0) + 1);
    targetChain = Array.from(counts.entries()).sort((a, b) => b[1] - a[1])[0]?.[0] || good[0].chain_id;
  }

  // For tx_index_hash: choose the most common value within the target chain.
  let targetTxIndex = "";
  {
    const counts = new Map<string, number>();
    for (const p of good) {
      if (p.chain_id !== targetChain) continue;
      counts.set(p.tx_index_hash, (counts.get(p.tx_index_hash) || 0) + 1);
    }
    targetTxIndex = Array.from(counts.entries()).sort((a, b) => b[1] - a[1])[0]?.[0] || "";
  }

  const scored = good
    .map((p) => ({ p, score: scoreProbe(p, { chain_id: targetChain, tx_index_hash: targetTxIndex || undefined }) }))
    .filter((x) => Number.isFinite(x.score))
    .sort((a, b) => b.score - a.score);

  const primary = scored[0]?.p?.base_url || normalizeUrl(getApiBaseUrl());

  const fallbacks = uniqUrls(
    scored
      .slice(1)
      .map((x) => x.p.base_url)
      .filter((u) => u && u !== primary)
      .slice(0, Math.max(0, maxFallbacks))
  );

  const sel: NodeSelection = {
    primary,
    fallbacks,
    picked_ts_ms: nowMs(),
    ttl_ms: Math.max(10_000, ttlMs),
    chain_id: targetChain,
    tx_index_hash: targetTxIndex,
  };

  return sel;
}

export async function ensureNodeSelection(opts?: {
  force?: boolean;
  timeoutMs?: number;
  ttlMs?: number;
  maxFallbacks?: number;
  concurrency?: number;
}): Promise<NodeSelection> {
  const cached = readCachedSelection();
  if (!opts?.force && cached && isSelectionFresh(cached) && cached.primary) {
    // Keep the global API base aligned with primary.
    try {
      if (normalizeUrl(getApiBaseUrl()) !== cached.primary) setApiBaseUrl(cached.primary);
    } catch {
      // ignore
    }
    return cached;
  }

  const sel = await pickNodes(opts);
  writeCachedSelection(sel);

  // Align client base URL to primary for all existing API helpers.
  if (sel.primary) setApiBaseUrl(sel.primary);

  return sel;
}

export function getCurrentSelection(): NodeSelection | null {
  const cached = readCachedSelection();
  if (cached && isSelectionFresh(cached)) return cached;
  return null;
}

export function getPrimaryNode(): string {
  const sel = getCurrentSelection();
  return normalizeUrl(sel?.primary || getApiBaseUrl());
}

export function getFallbackNodes(): string[] {
  const sel = getCurrentSelection();
  return uniqUrls(sel?.fallbacks || []);
}

export function getReadNodes(): string[] {
  // For reads, rotate across fallbacks (primary first) if needed.
  const primary = getPrimaryNode();
  return uniqUrls([primary, ...getFallbackNodes()]);
}

export async function rotateToNextNode(): Promise<string> {
  // Simple manual failover: if the current primary is failing, rotate to the next fallback.
  const sel = getCurrentSelection();
  const primary = normalizeUrl(sel?.primary || getApiBaseUrl());
  const fallbacks = uniqUrls(sel?.fallbacks || []);
  if (!fallbacks.length) return primary;

  const next = fallbacks[0];
  const rest = fallbacks.slice(1);

  const newSel: NodeSelection = {
    primary: next,
    fallbacks: uniqUrls([primary, ...rest]),
    picked_ts_ms: nowMs(),
    ttl_ms: sel?.ttl_ms || DEFAULT_PICK_TTL_MS,
    chain_id: sel?.chain_id || "",
    tx_index_hash: sel?.tx_index_hash || "",
  };

  writeCachedSelection(newSel);
  setApiBaseUrl(next);
  return next;
}
