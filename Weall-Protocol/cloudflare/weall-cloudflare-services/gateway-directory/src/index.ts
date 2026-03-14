// File: projects/weall-email-oracle/src/index.ts
import * as ed from "@noble/ed25519";

export interface Env {
  NODE_DIRECTORY: DurableObjectNamespace;

  NODE_GATEWAY_HMAC_SECRET: string;
  // Optional: asymmetric gateway token signing (preferred).
  // If WEALL_GATEWAY_SIGNING_JWK is provided, tokens are JWS (EdDSA/Ed25519).
  // If not, tokens fall back to legacy HMAC compact format.
  WEALL_GATEWAY_SIGNING_JWK?: string; // private key JWK JSON
  WEALL_GATEWAY_PUBLIC_JWK?: string; // public key JWK JSON
  WEALL_GATEWAY_KID?: string; // key id
  WEALL_REGISTRY_URL: string;

  WEALL_CORS_ORIGINS?: string;
  WEALL_ALLOW_HTTP_UPSTREAM?: string;

  WEALL_HEARTBEAT_REPLAY_TTL_S?: string;

  // Registry cache TTLs
  WEALL_REGISTRY_CACHE_TTL_S?: string; // positive cache (default 60)
  WEALL_REGISTRY_NEG_CACHE_TTL_S?: string; // negative cache (default 10)
  WEALL_REGISTRY_CACHE_MAX?: string; // max entries (default 5000)

  // Gateway token expiry
  WEALL_GATEWAY_TOKEN_TTL_MS?: string; // default 15 minutes
  WEALL_GATEWAY_TOKEN_FUTURE_SKEW_MS?: string; // default 60 seconds

  // Optional: per-worker-instance cache TTL for /v1/gateway/pick (ms). Default 30_000.
  WEALL_PICK_CACHE_TTL_MS?: string;

  // Upstream proxy timeout
  WEALL_GATEWAY_UPSTREAM_TIMEOUT_MS?: string; // default 5000
}

type Json = Record<string, unknown>;

function json(body: unknown, status = 200, headers: Record<string, string> = {}) {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      ...headers,
    },
  });
}

function getCorsHeaders(req: Request, env: Env): Record<string, string> {
  const raw = (env.WEALL_CORS_ORIGINS || "").trim();
  if (!raw) return {};
  const origin = req.headers.get("origin") || "";
  const allow = raw
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  if (!origin || !allow.includes(origin)) return {};
  return {
    "access-control-allow-origin": origin,
    "access-control-allow-credentials": "true",
    "access-control-allow-methods": "GET,POST,OPTIONS",
    "access-control-allow-headers": "content-type,authorization",
    "access-control-max-age": "600",
    vary: "origin",
  };
}

function base64UrlEncode(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  const b64 = btoa(s);
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlDecode(s: string): Uint8Array {
  const pad = "=".repeat((4 - (s.length % 4)) % 4);
  const b64 = (s + pad).replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function base64DecodeFlexible(s: string): Uint8Array {
  const ss = (s || "").trim();
  if (!ss) return new Uint8Array();
  const isUrl = ss.includes("-") || ss.includes("_");
  if (isUrl) return base64UrlDecode(ss);

  const pad = "=".repeat((4 - (ss.length % 4)) % 4);
  const b64 = ss + pad;
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function nowMs(): number {
  return Date.now();
}

function normalizeNodeId(node_id: string): string {
  return (node_id || "").trim();
}

function parsePubKeyBytes(node_id: string): Uint8Array | null {
  const id = normalizeNodeId(node_id);
  try {
    const parts = id.split(":");
    const last = parts.length > 1 ? parts[parts.length - 1] : id;
    const pk = base64DecodeFlexible(last);
    if (pk.length !== 32) return null;
    return pk;
  } catch {
    return null;
  }
}

function joinUrl(base: string, path: string): string {
  const b = base.replace(/\/+$/g, "");
  const p = path.startsWith("/") ? path : `/${path}`;
  return `${b}${p}`;
}

async function hmacSha256(key: string, data: string): Promise<string> {
  const enc = new TextEncoder();
  const k = await crypto.subtle.importKey("raw", enc.encode(key), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", k, enc.encode(data));
  const bytes = new Uint8Array(sig);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function sha256Hex(data: Uint8Array): Promise<string> {
  const dig = await crypto.subtle.digest("SHA-256", data);
  const bytes = new Uint8Array(dig);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

type GatewayKeyCache = {
  kid: string;
  publicKey: CryptoKey | null;
  privateKey: CryptoKey | null;
};

let GATEWAY_KEYS: GatewayKeyCache | null = null;

async function loadGatewayKeys(env: Env): Promise<GatewayKeyCache> {
  if (GATEWAY_KEYS) return GATEWAY_KEYS;

  const kid = (env.WEALL_GATEWAY_KID || "weall-gateway-1").trim() || "weall-gateway-1";
  const pubRaw = (env.WEALL_GATEWAY_PUBLIC_JWK || "").trim();
  const privRaw = (env.WEALL_GATEWAY_SIGNING_JWK || "").trim();

  let publicKey: CryptoKey | null = null;
  let privateKey: CryptoKey | null = null;

  try {
    if (pubRaw) {
      const pubJwk = JSON.parse(pubRaw) as JsonWebKey;
      publicKey = await crypto.subtle.importKey("jwk", pubJwk, { name: "Ed25519" }, false, ["verify"]);
    }
  } catch {
    publicKey = null;
  }

  try {
    if (privRaw) {
      const privJwk = JSON.parse(privRaw) as JsonWebKey;
      privateKey = await crypto.subtle.importKey("jwk", privJwk, { name: "Ed25519" }, false, ["sign"]);
      if (!publicKey && typeof (privJwk as any)?.x === "string") {
        const derivedPub: JsonWebKey = { kty: "OKP", crv: "Ed25519", x: (privJwk as any).x, kid };
        publicKey = await crypto.subtle.importKey("jwk", derivedPub, { name: "Ed25519" }, false, ["verify"]);
      }
    }
  } catch {
    privateKey = null;
  }

  GATEWAY_KEYS = { kid, publicKey, privateKey };
  return GATEWAY_KEYS;
}

function b64urlBytes(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function b64urlToBytes(s: string): Uint8Array {
  const pad = "=".repeat((4 - (s.length % 4)) % 4);
  const b64 = (s + pad).replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function signGatewayToken(env: Env, payload: Json): Promise<string> {
  const keys = await loadGatewayKeys(env);
  if (keys.privateKey) {
    const header = { alg: "EdDSA", typ: "JWT", kid: keys.kid };
    const enc = new TextEncoder();
    const h = b64urlBytes(enc.encode(JSON.stringify(header)));
    const p = b64urlBytes(enc.encode(JSON.stringify(payload)));
    const input = `${h}.${p}`;
    const sig = await crypto.subtle.sign({ name: "Ed25519" }, keys.privateKey, enc.encode(input));
    return `${input}.${b64urlBytes(new Uint8Array(sig))}`;
  }

  // Legacy compact token: base64url(json).hex(hmac(body))
  const enc = new TextEncoder();
  const body = base64UrlEncode(enc.encode(JSON.stringify(payload)));
  const sig = await hmacSha256(env.NODE_GATEWAY_HMAC_SECRET, body);
  return `${body}.${sig}`;
}

function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let out = 0;
  for (let i = 0; i < a.length; i++) out |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return out === 0;
}

async function verifyGatewayToken(env: Env, token: string): Promise<Json | null> {
  const parts = token.split(".");

  // JWS EdDSA
  if (parts.length === 3) {
    const keys = await loadGatewayKeys(env);
    if (!keys.publicKey) return null;
    const [h, p, s] = parts;
    try {
      const hdr = JSON.parse(new TextDecoder().decode(b64urlToBytes(h))) as any;
      if (!hdr || hdr.alg !== "EdDSA") return null;
      const enc = new TextEncoder();
      const ok = await crypto.subtle.verify({ name: "Ed25519" }, keys.publicKey, b64urlToBytes(s), enc.encode(`${h}.${p}`));
      if (!ok) return null;
      const payload = JSON.parse(new TextDecoder().decode(b64urlToBytes(p)));
      if (!payload || typeof payload !== "object") return null;
      return payload as Json;
    } catch {
      return null;
    }
  }

  // Legacy HMAC compact
  if (parts.length !== 2) return null;
  const [body, sig] = parts;
  const expect = await hmacSha256(env.NODE_GATEWAY_HMAC_SECRET, body);
  if (!timingSafeEqual(sig, expect)) return null;
  try {
    const bytes = base64UrlDecode(body);
    const txt = new TextDecoder().decode(bytes);
    const obj = JSON.parse(txt);
    if (!obj || typeof obj !== "object") return null;
    return obj as Json;
  } catch {
    return null;
  }
}

type PickCacheEntry = {
  token: string;
  node: NodeRecord;
  exp_ms: number;
  cached_at_ms: number;
};

const PICK_CACHE: Map<string, PickCacheEntry> = new Map();

function clientKey(req: Request): string {
  const cf = (req.headers.get("cf-connecting-ip") || "").trim();
  if (cf) return `ip:${cf}`;
  const xff = (req.headers.get("x-forwarded-for") || "").split(",")[0]?.trim();
  if (xff) return `ip:${xff}`;
  return "ip:unknown";
}

function heartbeatMessage(node_id: string, upstream_base: string, ts_ms: number): string {
  return `WEALL_NODE_HEARTBEAT|${node_id}|${upstream_base}|${ts_ms}`;
}

async function verifyHeartbeatSignature(node_id: string, upstream_base: string, ts_ms: number, sig_b64: string): Promise<boolean> {
  const pk = parsePubKeyBytes(node_id);
  if (!pk) return false;

  let sig: Uint8Array;
  try {
    sig = base64DecodeFlexible(sig_b64);
  } catch {
    return false;
  }
  if (sig.length !== 64) return false;

  const msg = new TextEncoder().encode(heartbeatMessage(normalizeNodeId(node_id), upstream_base, ts_ms));
  return ed.verify(sig, msg, pk);
}

/**
 * Registry caching (in-memory, per worker isolate). Fail-closed:
 * - If registry is unreachable, only accept if we have an unexpired positive cache.
 */
type RegCacheEntry = { ok: boolean; exp_ms: number; last_ms: number };
const REG_CACHE: Map<string, RegCacheEntry> = new Map();

function envInt(envVal: string | undefined, def: number): number {
  if (!envVal) return def;
  const n = Number(envVal);
  return Number.isFinite(n) ? Math.trunc(n) : def;
}

function cacheGet(node_id: string, now: number): RegCacheEntry | null {
  const e = REG_CACHE.get(node_id);
  if (!e) return null;
  if (now >= e.exp_ms) {
    REG_CACHE.delete(node_id);
    return null;
  }
  e.last_ms = now;
  return e;
}

function cacheSet(node_id: string, ok: boolean, now: number, ttl_s: number): void {
  const ttl = Math.max(1, Math.min(3600, Math.trunc(ttl_s)));
  const exp_ms = now + ttl * 1000;
  REG_CACHE.set(node_id, { ok, exp_ms, last_ms: now });
}

function cachePrune(now: number, maxKeys: number): void {
  for (const [k, v] of REG_CACHE.entries()) {
    if (now >= v.exp_ms) REG_CACHE.delete(k);
  }
  if (REG_CACHE.size <= maxKeys) return;

  const items = Array.from(REG_CACHE.entries());
  items.sort((a, b) => a[1].last_ms - b[1].last_ms);
  const overflow = REG_CACHE.size - maxKeys;
  for (let i = 0; i < overflow; i++) REG_CACHE.delete(items[i][0]);
}

async function isRegistered(env: Env, node_id: string): Promise<boolean> {
  const regBase = (env.WEALL_REGISTRY_URL || "").trim();
  if (!regBase) return false;

  const now = nowMs();

  const posTtl = envInt(env.WEALL_REGISTRY_CACHE_TTL_S, 60);
  const negTtl = envInt(env.WEALL_REGISTRY_NEG_CACHE_TTL_S, 10);
  const maxKeys = envInt(env.WEALL_REGISTRY_CACHE_MAX, 5000);

  cachePrune(now, maxKeys);

  const cached = cacheGet(node_id, now);
  if (cached) return cached.ok;

  const account = encodeURIComponent(node_id.trim());
  const url = joinUrl(regBase, `/v1/accounts/${account}/registered`);

  try {
    const resp = await fetch(url, { method: "GET", headers: { accept: "application/json" } });
    if (!resp.ok) {
      cacheSet(node_id, false, now, negTtl);
      return false;
    }
    const out = (await resp.json().catch(() => null)) as any;
    const ok = !!(out && out.ok === true && out.registered === true);
    cacheSet(node_id, ok, now, ok ? posTtl : negTtl);
    return ok;
  } catch {
    // Unreachable registry + no valid cache -> fail closed
    return false;
  }
}

function tokenExpired(env: Env, payload: any): string | null {
  const now = nowMs();
  const ttlMs = envInt(env.WEALL_GATEWAY_TOKEN_TTL_MS, 15 * 60_000);
  const futSkew = envInt(env.WEALL_GATEWAY_TOKEN_FUTURE_SKEW_MS, 60_000);

  // Newer tokens may include an explicit exp_ms.
  const exp = Number(payload?.exp_ms ?? 0);
  if (Number.isFinite(exp) && exp > 0) {
    if (exp < now) return "token_expired";
    if (exp > now + ttlMs + futSkew) {
      // Guard: reject absurdly long tokens even if exp_ms is set.
      return "exp_too_far";
    }
    return null;
  }

  const issued = Number(payload?.issued_ms ?? 0);
  if (!Number.isFinite(issued) || issued <= 0) return "missing_issued_ms";

  if (issued > now + futSkew) return "issued_in_future";
  if (now - issued > ttlMs) return "token_expired";
  return null;
}

async function penalizeNode(env: Env, node_id: string): Promise<void> {
  try {
    const id = env.NODE_DIRECTORY.idFromName("global");
    const stub = env.NODE_DIRECTORY.get(id);
    await stub.fetch("https://do/fail", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ node_id }),
    });
  } catch {
    // Best-effort: never crash gateway on penalty failure.
  }
}

async function doFetchUpstreamWithPenalty(env: Env, node_id: string, upstreamBase: string, req: Request): Promise<Response> {
  const url = new URL(req.url);
  const upstreamUrl = joinUrl(upstreamBase, url.pathname + url.search);

  const headers = new Headers(req.headers);

  // Strip hop-by-hop/gateway-specific headers
  headers.delete("host");
  headers.delete("cf-connecting-ip");
  headers.delete("x-forwarded-for");
  headers.delete("x-forwarded-proto");
  headers.delete("x-real-ip");

  const timeoutMs = envInt(env.WEALL_GATEWAY_UPSTREAM_TIMEOUT_MS, 5_000);

  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), Math.max(250, timeoutMs));

  try {
    const resp = await fetch(upstreamUrl, {
      method: req.method,
      headers,
      body: req.method === "GET" || req.method === "HEAD" ? undefined : req.body,
      redirect: "manual",
      signal: ctrl.signal,
    });

    // Penalize on upstream/server failure class (tune as desired)
    if (resp.status >= 500 || resp.status === 429) {
      // 429 often indicates node is overloaded; downrank briefly
      await penalizeNode(env, node_id);
    }

    return resp;
  } catch {
    // Network error / timeout -> penalize node
    await penalizeNode(env, node_id);
    return json({ ok: false, error: "upstream_unreachable" }, 502);
  } finally {
    clearTimeout(t);
  }
}

function pickAliveNode(nodes: any[], now: number): any | null {
  const alive = nodes.filter((n) => n && typeof n === "object" && typeof n.seen_ms === "number" && now - n.seen_ms <= 30_000);
  if (!alive.length) return null;

  alive.sort((a, b) => {
    const la = Number(a.load ?? 0);
    const lb = Number(b.load ?? 0);
    const fa = Number(a.last_failed_ms ?? 0);
    const fb = Number(b.last_failed_ms ?? 0);
    const sa = Number(a.seen_ms ?? 0);
    const sb = Number(b.seen_ms ?? 0);

    let scoreA = 0;
    let scoreB = 0;

    if (Number.isFinite(la)) scoreA += Math.max(0, la) * 10;
    if (Number.isFinite(lb)) scoreB += Math.max(0, lb) * 10;

    if (fa && now - fa < 60_000) scoreA += 500;
    if (fb && now - fb < 60_000) scoreB += 500;

    if (sa) {
      const age = now - sa;
      scoreA += Math.min(1000, Math.max(0, age / 100));
    } else {
      scoreA += 10_000;
    }

    if (sb) {
      const age = now - sb;
      scoreB += Math.min(1000, Math.max(0, age / 100));
    } else {
      scoreB += 10_000;
    }

    return scoreA - scoreB;
  });

  return alive[0];
}

async function handleGateway(req: Request, env: Env): Promise<Response> {
  const cors = getCorsHeaders(req, env);

  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: cors });
  }

  const url = new URL(req.url);

  if (url.pathname === "/v1/status") {
    return json({ ok: true, service: "weall-email-oracle" }, 200, cors);
  }

  // Heartbeat ingest endpoint (nodes post signed heartbeat, gateway stores in DO)
  if (url.pathname === "/v1/node/heartbeat") {
    if (req.method !== "POST") return json({ ok: false, error: "method_not_allowed" }, 405, cors);

    const body = (await req.json().catch(() => null)) as any;
    if (!body || typeof body !== "object") return json({ ok: false, error: "bad_json" }, 400, cors);

    const node_id = String(body.node_id || "").trim();
    const upstream_base = String(body.upstream_base || "").trim();
    const ts_ms = Number(body.ts_ms ?? 0);
    const sig = String(body.sig || "").trim();

    if (!node_id || !upstream_base || !sig || !Number.isFinite(ts_ms) || ts_ms <= 0) {
      return json({ ok: false, error: "missing_fields" }, 400, cors);
    }

    // Enforce heartbeat freshness (60s skew)
    const skew = Math.abs(nowMs() - ts_ms);
    if (!Number.isFinite(skew) || skew > 60_000) {
      return json({ ok: false, error: "stale_heartbeat" }, 400, cors);
    }

    // Basic URL sanity (HTTPS only by default; allow HTTP only when explicitly enabled for dev)
    try {
      const u = new URL(upstream_base);
      const allowHttp = env.WEALL_ALLOW_HTTP_UPSTREAM ? String(env.WEALL_ALLOW_HTTP_UPSTREAM).trim().toLowerCase() : "";
      const httpOk = allowHttp === "1" || allowHttp === "true" || allowHttp === "yes" || allowHttp === "on";
      if (u.protocol !== "https:" && !(httpOk && u.protocol === "http:")) return json({ ok: false, error: "bad_upstream_protocol" }, 400, cors);
    } catch {
      return json({ ok: false, error: "bad_upstream_url" }, 400, cors);
    }

    // Verify signature (node proves control of node_id key)
    const sigOk = await verifyHeartbeatSignature(node_id, upstream_base, ts_ms, sig);
    if (!sigOk) return json({ ok: false, error: "bad_signature" }, 401, cors);

    // Verify registration (node_id must be registered on-chain)
    const regOk = await isRegistered(env, node_id);
    if (!regOk) return json({ ok: false, error: "not_registered" }, 403, cors);

    // Compute replay-dedup hash (hash of signature bytes)
    let sig_hash = "";
    try {
      const sigBytes = base64DecodeFlexible(sig);
      sig_hash = await sha256Hex(sigBytes);
    } catch {
      return json({ ok: false, error: "bad_sig_encoding" }, 400, cors);
    }

    // Persist to DO (DO enforces replay protection using node_id+ts_ms+sig_hash)
    const id = env.NODE_DIRECTORY.idFromName("global");
    const stub = env.NODE_DIRECTORY.get(id);

    const hbResp = await stub.fetch("https://do/heartbeat", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        node_id,
        upstream_base,
        load: Number(body.load ?? 0),
        region_hint: String(body.region_hint || "").trim(),
        seen_ms: nowMs(),

        ts_ms,
        sig_hash,
        replay_ttl_s: envInt(env.WEALL_HEARTBEAT_REPLAY_TTL_S, 180),
      }),
    });

    const hbOut = await hbResp.json().catch(() => null);
    if (!hbResp.ok) return json({ ok: false, error: "do_error", detail: hbOut }, 500, cors);

    return json({ ok: true }, 200, cors);
  }

  // Sticky routing: token indicates chosen node_id
  if (url.pathname.startsWith("/v1/gateway/")) {
    const auth = req.headers.get("authorization") || "";
    const token = auth.startsWith("Bearer ") ? auth.slice("Bearer ".length).trim() : "";
    if (!token) return json({ ok: false, error: "missing_token" }, 401, cors);

    const payload = await verifyGatewayToken(env, token);
    if (!payload) return json({ ok: false, error: "bad_token" }, 401, cors);

    const expiryErr = tokenExpired(env, payload);
    if (expiryErr) return json({ ok: false, error: "token_invalid", detail: expiryErr }, 401, cors);

    const node_id = String((payload as any).node_id || "").trim();
    if (!node_id) return json({ ok: false, error: "bad_token_payload" }, 401, cors);

    const id = env.NODE_DIRECTORY.idFromName("global");
    const stub = env.NODE_DIRECTORY.get(id);

    const getResp = await stub.fetch("https://do/get", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ node_id }),
    });

    const out = (await getResp.json().catch(() => null)) as any;
    if (!getResp.ok || !out || out.ok !== true || !out.node) return json({ ok: false, error: "node_unavailable" }, 503, cors);

    const upstream_base = String(out.node.upstream_base || "").trim();
    if (!upstream_base) return json({ ok: false, error: "node_bad_upstream" }, 502, cors);

    // Proxy request to node upstream; penalize node automatically on failures.
    return doFetchUpstreamWithPenalty(env, node_id, upstream_base, req);
  }

  // Node selection: pick a node and return a signed sticky token
  if (url.pathname === "/v1/gateway/pick") {
    if (req.method !== "POST") return json({ ok: false, error: "method_not_allowed" }, 405, cors);

    const id = env.NODE_DIRECTORY.idFromName("global");
    const stub = env.NODE_DIRECTORY.get(id);

    // Small per-worker-instance cache to reduce DO list calls under load.
    // Note: This is best-effort; DO remains the source of truth.
    const ttlMs = envInt(env.WEALL_PICK_CACHE_TTL_MS, 30_000);
    const key = clientKey(req);
    const cached = PICK_CACHE.get(key);
    const now = nowMs();
    if (cached && now - cached.cached_at_ms <= ttlMs && cached.exp_ms > now) {
      return json({ ok: true, token: cached.token, node: { node_id: cached.node.node_id, region_hint: cached.node.region_hint || "" }, cached: true }, 200, cors);
    }

    const listResp = await stub.fetch("https://do/list", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({}),
    });

    const out = (await listResp.json().catch(() => null)) as any;
    if (!listResp.ok || !out || out.ok !== true || !Array.isArray(out.nodes)) return json({ ok: false, error: "no_nodes" }, 503, cors);

    const picked = pickAliveNode(out.nodes, now);
    if (!picked) return json({ ok: false, error: "no_alive_nodes" }, 503, cors);

    const expMs = now + envInt(env.WEALL_GATEWAY_TOKEN_TTL_MS, 15 * 60 * 1000);
    const token = await signGatewayToken(env, {
      node_id: String(picked.node_id || ""),
      issued_ms: now,
      exp_ms: expMs,
      v: 1,
    });

    PICK_CACHE.set(key, { token, node: picked, exp_ms: expMs, cached_at_ms: now });

    return json({ ok: true, token, node: { node_id: picked.node_id, region_hint: picked.region_hint || "" } }, 200, cors);
  }

  return json({ ok: false, error: "not_found" }, 404, cors);
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    return handleGateway(req, env);
  },
};

export class NodeDirectoryDO implements DurableObject {
  state: DurableObjectState;
  nodes: Map<string, any>;

  constructor(state: DurableObjectState) {
    this.state = state;
    this.nodes = new Map();
  }

  async load(): Promise<void> {
    const stored = await this.state.storage.get<Record<string, any>>("nodes");
    if (stored) for (const [k, v] of Object.entries(stored)) this.nodes.set(k, v);
  }

  async persist(): Promise<void> {
    const obj: Record<string, any> = {};
    for (const [k, v] of this.nodes.entries()) obj[k] = v;
    await this.state.storage.put("nodes", obj);
  }

  isAlive(n: any, now: number): boolean {
    return typeof n?.seen_ms === "number" && now - n.seen_ms <= 30_000;
  }

  async fetch(req: Request): Promise<Response> {
    const url = new URL(req.url);
    const now = Date.now();
    if (this.nodes.size === 0) await this.load();

    if (url.pathname === "/heartbeat") {
      const body = (await req.json().catch(() => null)) as any;
      if (!body || typeof body !== "object") return json({ ok: false, error: "bad_json" }, 400);

      const node_id = String(body.node_id || "").trim();
      const upstream_base = String(body.upstream_base || "").trim();
      const load = Number(body.load ?? 0);
      const region_hint = String(body.region_hint || "").trim();
      const seen_ms = Number(body.seen_ms ?? now);

      // replay-protection
      const ts_ms = Number(body.ts_ms ?? 0);
      const sig_hash = String(body.sig_hash || "").trim();
      const replay_ttl_s = Number(body.replay_ttl_s ?? 180);

      if (!node_id || !upstream_base) return json({ ok: false, error: "missing_fields" }, 400);
      if (!Number.isFinite(ts_ms) || ts_ms <= 0) return json({ ok: false, error: "missing_ts_ms" }, 400);
      if (!sig_hash) return json({ ok: false, error: "missing_sig_hash" }, 400);

      // Dedup key: node_id + ts_ms + sig_hash
      const ttl = Number.isFinite(replay_ttl_s) ? Math.max(30, Math.min(600, Math.trunc(replay_ttl_s))) : 180;
      const replayKey = `hb:${node_id}:${ts_ms}:${sig_hash}`;

      try {
        const exists = await this.state.storage.get(replayKey);
        if (exists !== undefined) {
          return json({ ok: false, error: "replay_detected" }, 409);
        }
        await this.state.storage.put(replayKey, 1, { expirationTtl: ttl });
      } catch {
        // If DO storage is unhealthy, fail closed for heartbeat ingestion.
        return json({ ok: false, error: "storage_error" }, 503);
      }

      const prev = this.nodes.get(node_id) || {};
      const next = {
        node_id,
        upstream_base,
        load: Number.isFinite(load) ? load : 0,
        region_hint: region_hint || prev.region_hint || "",
        seen_ms: Number.isFinite(seen_ms) ? seen_ms : now,
        last_failed_ms: prev.last_failed_ms || 0,
      };

      this.nodes.set(node_id, next);
      await this.persist();
      return json({ ok: true, node_id });
    }

    if (url.pathname === "/fail") {
      const body = (await req.json().catch(() => null)) as any;
      const node_id = String(body?.node_id || "").trim();
      if (!node_id) return json({ ok: false, error: "missing_node_id" }, 400);

      const n = this.nodes.get(node_id);
      if (n) {
        n.last_failed_ms = now;
        this.nodes.set(node_id, n);
        await this.persist();
      }
      return json({ ok: true });
    }

    if (url.pathname === "/get") {
      const body = (await req.json().catch(() => null)) as any;
      const node_id = String(body?.node_id || "").trim();
      if (!node_id) return json({ ok: false, error: "missing_node_id" }, 400);

      const n = this.nodes.get(node_id);
      if (!n || !this.isAlive(n, now)) return json({ ok: false, error: "not_found" }, 404);

      return json({ ok: true, node: n });
    }

    if (url.pathname === "/list") {
      return json({ ok: true, nodes: Array.from(this.nodes.values()) });
    }

    return json({ ok: false, error: "not_found" }, 404);
  }
}
