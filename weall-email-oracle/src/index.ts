import * as ed from "@noble/ed25519";

export interface Env {
  NODE_DIRECTORY: DurableObjectNamespace;

  // Required secret used to sign sticky routing cookie tokens (user->node stickiness).
  NODE_GATEWAY_HMAC_SECRET: string;

  // Required: a read-only registry endpoint the gateway can query to verify registration.
  // Example: "https://seed.weallprotocol.xyz" (a public node URL)
  WEALL_REGISTRY_URL: string;

  // Optional: CORS allowlist for browser webfront.
  // Example: "https://weallprotocol.xyz,https://app.weallprotocol.xyz"
  WEALL_CORS_ORIGINS?: string;
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
    "access-control-allow-methods": "GET,POST,PUT,PATCH,DELETE,OPTIONS",
    "access-control-allow-headers": "authorization,content-type,x-weall-client",
    vary: "Origin",
  };
}

function isPreflight(req: Request) {
  return req.method === "OPTIONS" && !!req.headers.get("origin");
}

function parseCookie(header: string | null): Record<string, string> {
  const out: Record<string, string> = {};
  if (!header) return out;
  for (const part of header.split(";")) {
    const [k, ...rest] = part.trim().split("=");
    if (!k) continue;
    out[k] = rest.join("=");
  }
  return out;
}

function nowMs() {
  return Date.now();
}

function base64UrlEncode(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  const b64 = btoa(s);
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlDecode(s: string): Uint8Array {
  const padded = s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4);
  const bin = atob(padded);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

function base64DecodeFlexible(s: string): Uint8Array {
  const t = s.trim();
  // base64url -> base64
  const padded = t.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((t.length + 3) % 4);
  const bin = atob(padded);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

function hexToBytes(hex: string): Uint8Array | null {
  const h = hex.trim().toLowerCase();
  if (!/^[0-9a-f]+$/.test(h) || h.length % 2 !== 0) return null;
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function normalizeNodeId(nodeId: string): string {
  // Accept "pubkey:..." or raw.
  const s = nodeId.trim();
  if (s.startsWith("pubkey:")) return s.slice("pubkey:".length).trim();
  return s;
}

function parsePubKeyBytes(nodeId: string): Uint8Array | null {
  const s = normalizeNodeId(nodeId);

  // Hex (32 bytes = 64 hex chars)
  const maybeHex = s.replace(/^0x/i, "");
  const hexBytes = hexToBytes(maybeHex);
  if (hexBytes && hexBytes.length === 32) return hexBytes;

  // Base64/base64url (32 bytes)
  try {
    const b = base64DecodeFlexible(s);
    if (b.length === 32) return b;
  } catch {}

  return null;
}

function joinUrl(base: string, pathAndQuery: string): string {
  const b = base.endsWith("/") ? base.slice(0, -1) : base;
  const p = pathAndQuery.startsWith("/") ? pathAndQuery : `/${pathAndQuery}`;
  return `${b}${p}`;
}

async function sha256Hex(s: string): Promise<string> {
  const enc = new TextEncoder();
  const buf = await crypto.subtle.digest("SHA-256", enc.encode(s));
  const b = new Uint8Array(buf);
  return [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
}

async function clientKeyForSelection(req: Request): Promise<string> {
  const colo = req.headers.get("cf-ray") || "";
  const ua = req.headers.get("user-agent") || "";
  const ip = req.headers.get("cf-connecting-ip") || "";
  return sha256Hex(`${colo}|${ua}|${ip}`);
}

async function hmacSha256(key: string, data: string): Promise<string> {
  const enc = new TextEncoder();
  const k = await crypto.subtle.importKey("raw", enc.encode(key), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", k, enc.encode(data));
  return base64UrlEncode(sig);
}

async function signToken(secret: string, payload: Json): Promise<string> {
  const enc = new TextEncoder();
  const body = base64UrlEncode(enc.encode(JSON.stringify(payload)));
  const sig = await hmacSha256(secret, body);
  return `${body}.${sig}`;
}

async function verifyToken(secret: string, token: string): Promise<Json | null> {
  const parts = token.split(".");
  if (parts.length !== 2) return null;
  const [body, sig] = parts;
  const expect = await hmacSha256(secret, body);
  if (sig !== expect) return null;
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

function heartbeatMessage(node_id: string, upstream_base: string, ts_ms: number): string {
  // Canonical message string for Ed25519 signature verification.
  // Keep this stable forever once deployed.
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

async function isRegistered(env: Env, node_id: string): Promise<boolean> {
  const regBase = (env.WEALL_REGISTRY_URL || "").trim();
  if (!regBase) return false;

  const account = encodeURIComponent(node_id.trim());
  const url = joinUrl(regBase, `/v1/accounts/${account}/registered`);

  try {
    const resp = await fetch(url, { method: "GET", headers: { accept: "application/json" } });
    if (!resp.ok) return false;
    const out = (await resp.json().catch(() => null)) as any;
    return !!(out && out.ok === true && out.registered === true);
  } catch {
    return false;
  }
}

async function doFetchUpstream(upstreamBase: string, req: Request): Promise<Response> {
  const url = new URL(req.url);
  const upstreamUrl = joinUrl(upstreamBase, url.pathname + url.search);

  const init: RequestInit = {
    method: req.method,
    headers: new Headers(req.headers),
    body: req.method === "GET" || req.method === "HEAD" ? undefined : req.body,
    redirect: "manual",
  };

  // Strip hop-by-hop/gateway-specific headers
  (init.headers as Headers).delete("host");
  (init.headers as Headers).delete("cf-connecting-ip");
  (init.headers as Headers).delete("cf-ray");
  (init.headers as Headers).delete("cf-visitor");
  (init.headers as Headers).delete("x-forwarded-proto");
  (init.headers as Headers).delete("x-forwarded-for");
  (init.headers as Headers).delete("x-real-ip");

  (init.headers as Headers).set("x-weall-gateway", "cloudflare-node-gateway");

  return fetch(upstreamUrl, init);
}

export default {
  async fetch(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const cors = getCorsHeaders(req, env);
    if (isPreflight(req)) return new Response(null, { status: 204, headers: cors });

    const url = new URL(req.url);
    const dirId = env.NODE_DIRECTORY.idFromName("global");
    const dir = env.NODE_DIRECTORY.get(dirId);

    // -----------------------
    // Node heartbeat endpoint
    // -----------------------
    // POST /__gateway/node/heartbeat
    //
    // Body:
    // {
    //   "node_id": "<pubkey>",
    //   "upstream_base": "https://node.example.com",
    //   "load": 0.1,
    //   "region_hint": "us-west",
    //   "ts_ms": 1739760000000,
    //   "sig": "<base64/base64url signature over canonical message>"
    // }
    if (url.pathname === "/__gateway/node/heartbeat") {
      if (req.method !== "POST") return json({ ok: false, error: "method_not_allowed" }, 405, cors);

      const body = (await req.json().catch(() => null)) as any;
      if (!body || typeof body !== "object") return json({ ok: false, error: "bad_json" }, 400, cors);

      const node_id = String(body.node_id || "").trim();
      const upstream_base = String(body.upstream_base || "").trim();
      const load = Number(body.load ?? 0);
      const region_hint = String(body.region_hint || "").trim();
      const ts_ms = Number(body.ts_ms ?? 0);
      const sig = String(body.sig || "").trim();

      if (!node_id || !upstream_base || !ts_ms || !sig) {
        return json(
          { ok: false, error: "missing_fields", need: ["node_id", "upstream_base", "ts_ms", "sig"] },
          400,
          cors
        );
      }

      // Reject stale heartbeats (replay protection)
      const skew = Math.abs(nowMs() - ts_ms);
      if (!Number.isFinite(skew) || skew > 60_000) {
        return json({ ok: false, error: "stale_heartbeat" }, 400, cors);
      }

      // Basic URL sanity
      try {
        const u = new URL(upstream_base);
        if (u.protocol !== "https:" && u.protocol !== "http:") return json({ ok: false, error: "bad_upstream_protocol" }, 400, cors);
      } catch {
        return json({ ok: false, error: "bad_upstream_url" }, 400, cors);
      }

      // Verify signature (node proves control of node_id key)
      const sigOk = await verifyHeartbeatSignature(node_id, upstream_base, ts_ms, sig);
      if (!sigOk) return json({ ok: false, error: "bad_signature" }, 401, cors);

      // Verify registration (node_id must be registered on-chain)
      const regOk = await isRegistered(env, node_id);
      if (!regOk) return json({ ok: false, error: "not_registered" }, 403, cors);

      const resp = await dir.fetch("https://do/heartbeat", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          node_id,
          upstream_base,
          load,
          region_hint,
          seen_ms: nowMs(),
        }),
      });

      const out = await resp.json().catch(() => ({}));
      return json(out, resp.status, cors);
    }

    // Debug: GET /__gateway/nodes
    if (url.pathname === "/__gateway/nodes") {
      const resp = await dir.fetch("https://do/nodes", { method: "GET" });
      const out = await resp.json().catch(() => ({}));
      return json(out, resp.status, cors);
    }

    // Debug: GET /__gateway/select
    if (url.pathname === "/__gateway/select") {
      const key = await clientKeyForSelection(req);
      const resp = await dir.fetch("https://do/select", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ client_key: key }),
      });
      const out = await resp.json().catch(() => ({}));
      return json(out, resp.status, cors);
    }

    // ----------------
    // Main reverse proxy
    // ----------------
    const cookies = parseCookie(req.headers.get("cookie"));
    const tokenName = "weall_node";
    const token = cookies[tokenName];

    let selectedNode: { node_id: string; upstream_base: string } | null = null;

    if (token) {
      const payload = await verifyToken(env.NODE_GATEWAY_HMAC_SECRET, token);
      if (payload) {
        const exp = Number(payload.exp_ms ?? 0);
        if (exp && exp > nowMs()) {
          const node_id = String(payload.node_id || "").trim();
          if (node_id) {
            const resp = await dir.fetch("https://do/get", {
              method: "POST",
              headers: { "content-type": "application/json" },
              body: JSON.stringify({ node_id }),
            });
            if (resp.ok) {
              const out = (await resp.json().catch(() => null)) as any;
              if (out && out.ok && out.node && out.node.upstream_base) {
                selectedNode = { node_id, upstream_base: String(out.node.upstream_base) };
              }
            }
          }
        }
      }
    }

    if (!selectedNode) {
      const key = await clientKeyForSelection(req);
      const resp = await dir.fetch("https://do/select", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ client_key: key }),
      });

      const out = (await resp.json().catch(() => null)) as any;
      if (!resp.ok || !out || !out.ok || !out.node_id || !out.upstream_base) {
        return json({ ok: false, error: "no_public_nodes_available" }, 503, cors);
      }

      selectedNode = { node_id: String(out.node_id), upstream_base: String(out.upstream_base) };

      // Set sticky cookie (1 hour)
      const exp = nowMs() + 60 * 60 * 1000;
      const tok = await signToken(env.NODE_GATEWAY_HMAC_SECRET, {
        node_id: selectedNode.node_id,
        exp_ms: exp,
        iat_ms: nowMs(),
      });

      const upstreamResp = await proxyWithFailover(req, dir, selectedNode);

      const headers = new Headers(upstreamResp.headers);
      headers.set("set-cookie", `${tokenName}=${tok}; Path=/; Max-Age=3600; Secure; HttpOnly; SameSite=Lax`);
      for (const [k, v] of Object.entries(cors)) headers.set(k, v);

      return new Response(upstreamResp.body, { status: upstreamResp.status, headers });
    }

    const upstreamResp = await proxyWithFailover(req, dir, selectedNode);
    const headers = new Headers(upstreamResp.headers);
    for (const [k, v] of Object.entries(cors)) headers.set(k, v);
    return new Response(upstreamResp.body, { status: upstreamResp.status, headers });
  },
};

async function proxyWithFailover(
  req: Request,
  dir: DurableObjectStub,
  selectedNode: { node_id: string; upstream_base: string }
): Promise<Response> {
  try {
    const resp = await doFetchUpstream(selectedNode.upstream_base, req);
    if (![502, 503, 504].includes(resp.status)) return resp;

    await dir.fetch("https://do/fail", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ node_id: selectedNode.node_id, failed_ms: Date.now() }),
    });

    const key = await clientKeyForSelection(req);
    const sel = await dir.fetch("https://do/select", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ client_key: key }),
    });
    const out = (await sel.json().catch(() => null)) as any;
    if (!sel.ok || !out || !out.ok || !out.upstream_base) return resp;

    return await doFetchUpstream(String(out.upstream_base), req);
  } catch {
    await dir.fetch("https://do/fail", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ node_id: selectedNode.node_id, failed_ms: Date.now() }),
    }).catch(() => {});

    const key = await clientKeyForSelection(req);
    const sel = await dir.fetch("https://do/select", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ client_key: key }),
    });
    const out = (await sel.json().catch(() => null)) as any;
    if (!sel.ok || !out || !out.ok || !out.upstream_base) {
      return new Response("Upstream unavailable", { status: 503 });
    }
    return await doFetchUpstream(String(out.upstream_base), req);
  }
}

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

  scoreNode(n: any, now: number): number {
    let score = 0;

    const load = Number(n?.load ?? 0);
    if (Number.isFinite(load)) score += Math.max(0, load) * 10;

    const lastFail = Number(n?.last_failed_ms ?? 0);
    if (lastFail && now - lastFail < 60_000) score += 500;

    const seen = Number(n?.seen_ms ?? 0);
    if (seen) {
      const age = now - seen;
      score += Math.min(1000, Math.max(0, age / 100));
    } else {
      score += 10_000;
    }
    return score;
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

      if (!node_id || !upstream_base) return json({ ok: false, error: "missing_fields" }, 400);

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
      if (!n) return json({ ok: false, error: "not_found" }, 404);
      if (!this.isAlive(n, now)) return json({ ok: false, error: "stale" }, 410);
      return json({ ok: true, node: n });
    }

    if (url.pathname === "/nodes") {
      const out: any[] = [];
      for (const n of this.nodes.values()) {
        out.push({
          node_id: n.node_id,
          upstream_base: n.upstream_base,
          load: n.load,
          region_hint: n.region_hint,
          seen_ms: n.seen_ms,
          alive: this.isAlive(n, now),
          last_failed_ms: n.last_failed_ms || 0,
        });
      }
      return json({ ok: true, nodes: out, count: out.length });
    }

    if (url.pathname === "/select") {
      const body = (await req.json().catch(() => null)) as any;
      const client_key = String(body?.client_key || "").trim();
      if (!client_key) return json({ ok: false, error: "missing_client_key" }, 400);

      const candidates: any[] = [];
      for (const n of this.nodes.values()) if (this.isAlive(n, now)) candidates.push(n);
      if (candidates.length === 0) return json({ ok: false, error: "no_alive_nodes" }, 503);

      let best = candidates[0];
      let bestScore = this.scoreNode(best, now);
      let bestTie = await sha256Hex(`${client_key}|${best.node_id}`);

      for (let i = 1; i < candidates.length; i++) {
        const n = candidates[i];
        const s = this.scoreNode(n, now);
        if (s < bestScore) {
          best = n;
          bestScore = s;
          bestTie = await sha256Hex(`${client_key}|${best.node_id}`);
          continue;
        }
        if (s === bestScore) {
          const tie = await sha256Hex(`${client_key}|${n.node_id}`);
          if (tie < bestTie) {
            best = n;
            bestTie = tie;
          }
        }
      }

      return json({ ok: true, node_id: best.node_id, upstream_base: best.upstream_base });
    }

    return json({ ok: false, error: "not_found" }, 404);
  }
}
