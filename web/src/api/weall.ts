// projects/web/src/api/weall.ts
// Minimal client for WeAll public API.

export type Json = Record<string, any>;

type HttpOpts = {
  base?: string;
  method?: string;
  body?: any;
  headers?: Record<string, string>;
  timeoutMs?: number;
  // If set, do NOT set content-type to application/json and do NOT JSON.stringify.
  rawBody?: BodyInit | null;
};

const API_BASE_LS_KEY = "weall_api_base";
let _apiBaseOverride: string | null = null;

export function stripTrailingSlashes(url: string): string {
  return String(url || "").replace(/\/+$/g, "");
}

/**
 * Set the API base URL for this session and persist it.
 * Used by ConnectionPill's "Edit" behavior.
 */
export function setApiBaseUrl(baseUrl: string): void {
  const v = stripTrailingSlashes(String(baseUrl || "").trim());
  _apiBaseOverride = v || null;
  try {
    if (!v) localStorage.removeItem(API_BASE_LS_KEY);
    else localStorage.setItem(API_BASE_LS_KEY, v);
  } catch {
    // ignore (storage disabled)
  }
}

export function getApiBaseUrl(): string {
  // Priority:
  //  1) explicit runtime override (setApiBaseUrl)
  //  2) persisted override (localStorage)
  //  3) build-time env
  //  4) default
  if (_apiBaseOverride && _apiBaseOverride.trim()) return stripTrailingSlashes(_apiBaseOverride.trim());
  try {
    const raw = localStorage.getItem(API_BASE_LS_KEY);
    if (raw && raw.trim()) return stripTrailingSlashes(raw.trim());
  } catch {
    // ignore
  }
  return stripTrailingSlashes((import.meta as any).env?.VITE_WEALL_API_BASE || "http://127.0.0.1:8000");
}

export async function httpJson<T>(path: string, opts: HttpOpts = {}): Promise<T> {
  const base = opts.base || getApiBaseUrl();
  const method = (opts.method || "GET").toUpperCase();
  const headers: Record<string, string> = {
    ...(opts.headers || {}),
  };

  let body: any = undefined;
  if (opts.rawBody !== undefined) {
    body = opts.rawBody;
  } else if (opts.body !== undefined) {
    headers["content-type"] = "application/json";
    body = JSON.stringify(opts.body);
  }

  const timeoutMs = typeof opts.timeoutMs === "number" && opts.timeoutMs > 0 ? Math.floor(opts.timeoutMs) : 0;
  const ac = timeoutMs ? new AbortController() : null;
  const timer = timeoutMs ? window.setTimeout(() => ac?.abort("timeout"), timeoutMs) : null;

  try {
    const r = await fetch(base + path, { method, headers, body, signal: ac?.signal });
    const txt = await r.text();
    let data: any = null;
    try {
      data = txt ? JSON.parse(txt) : null;
    } catch {
      data = { ok: false, error: "bad_json", raw: txt };
    }
    if (!r.ok) {
      const err: any = new Error(data?.message || data?.error || "http_error");
      err.status = r.status;
      err.data = data;
      throw err;
    }
    return data as T;
  } finally {
    if (timer != null) window.clearTimeout(timer);
  }
}

export type FeedResponse = {
  ok: true;
  items: Json[];
  next_cursor: string | null;
};

export const weall = {
  // Health / status
  health(base?: string) {
    return httpJson<Json>("/v1/health", { base });
  },

  readyz(base?: string) {
    return httpJson<Json>("/v1/readyz", { base });
  },

  status(base?: string) {
    return httpJson<Json>("/v1/status", { base });
  },

  chainHead(base?: string) {
    return httpJson<Json>("/v1/chain/head", { base });
  },

  snapshot(base?: string) {
    return httpJson<Json>("/v1/state/snapshot", { base });
  },

  // Accounts
  account(account: string, base?: string) {
    return httpJson<Json>(`/v1/account/${encodeURIComponent(account)}`, { base });
  },

  accountNonce(account: string, base?: string) {
    return httpJson<Json>(`/v1/account/${encodeURIComponent(account)}/nonce`, { base });
  },

  // PoH
  pohState(account: string, base?: string) {
    return httpJson<Json>(`/v1/poh/${encodeURIComponent(account)}`, { base });
  },

  pohEmailStart(body: any, base?: string) {
    return httpJson<Json>("/v1/poh/email/start", { base, method: "POST", body });
  },

  pohEmailConfirm(body: any, base?: string) {
    return httpJson<Json>("/v1/poh/email/confirm", { base, method: "POST", body });
  },

  // Mempool / tx
  submitTx(env: any, base?: string) {
    return httpJson<Json>("/v1/tx/submit", { base, method: "POST", body: env });
  },

  txStatus(txId: string, base?: string) {
    return httpJson<Json>(`/v1/tx/status/${encodeURIComponent(txId)}`, { base });
  },

  // Feed / content
  feed(params?: Record<string, any>, base?: string, headers?: Record<string, string>) {
    const q = params ? "?" + new URLSearchParams(params as any).toString() : "";
    return httpJson<FeedResponse>(`/v1/feed${q}`, { base, headers });
  },

  content(id: string, base?: string) {
    return httpJson<Json>(`/v1/content/${encodeURIComponent(id)}`, { base });
  },

  // Thread
  thread(id: string, base?: string) {
    return httpJson<Json>(`/v1/thread/${encodeURIComponent(id)}`, { base });
  },

  // Groups
  groups(base?: string) {
    return httpJson<Json>("/v1/groups", { base });
  },

  group(id: string, base?: string) {
    return httpJson<Json>(`/v1/groups/${encodeURIComponent(id)}`, { base });
  },

  // Governance
  proposals(params?: Record<string, any>, base?: string) {
    const q = params ? "?" + new URLSearchParams(params as any).toString() : "";
    return httpJson<Json>(`/v1/gov/proposals${q}`, { base });
  },

  proposal(id: string, base?: string) {
    return httpJson<Json>(`/v1/gov/proposals/${encodeURIComponent(id)}`, { base });
  },

  // Social
  socialFollowing(account: string, base?: string) {
    return httpJson<Json>(`/v1/social/${encodeURIComponent(account)}/following`, { base });
  },

  socialMe(base?: string, headers?: Record<string, string>) {
    return httpJson<Json>("/v1/social/me", { base, headers });
  },

  // Media (IPFS)
  mediaUpload(file: File, base?: string, headers?: Record<string, string>) {
    const form = new FormData();
    form.append("file", file);
    return httpJson<Json>("/v1/media/upload", { base, method: "POST", rawBody: form, headers });
  },

  mediaGateway(cid: string, base?: string) {
    return `${stripTrailingSlashes(base || getApiBaseUrl())}/v1/media/gateway/${encodeURIComponent(cid)}`;
  },
};
