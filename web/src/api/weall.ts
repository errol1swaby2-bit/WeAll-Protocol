const ENV_API_BASE = String(((import.meta as any).env?.VITE_WEALL_API_BASE as string) || "").trim();
const DEFAULT_API_BASE = ENV_API_BASE || "/";

export type HttpMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";

export type ApiBaseValidation = {
  ok: true;
  normalized: string;
  isRemote: boolean;
  isLoopback: boolean;
} | {
  ok: false;
  normalized: string;
  reason: string;
};


export type ApiErrorPayload = {
  ok?: false;
  error?: {
    code?: string;
    message?: string;
    details?: unknown;
  };
  detail?: unknown;
};

export class ApiError extends Error {
  status: number;
  payload: unknown;

  constructor(message: string, status: number, payload: unknown) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.payload = payload;
  }
}

function readStoredApiBase(): string | null {
  try {
    return localStorage.getItem("weall.api.base");
  } catch {
    return null;
  }
}

function trimTrailingSlash(value: string): string {
  const trimmed = value.trim();
  if (!trimmed || trimmed === "/") return "/";
  return trimmed.replace(/\/+$/, "");
}

function isSameOriginPath(value: string): boolean {
  const trimmed = String(value || "").trim();
  return trimmed === "/" || (trimmed.startsWith("/") && !trimmed.startsWith("//"));
}

function canUseWindowLocation(): boolean {
  return typeof window !== "undefined" && !!window.location;
}

function isLoopbackHostname(hostname: string): boolean {
  const host = String(hostname || "").trim().toLowerCase();
  return host === "127.0.0.1" || host === "localhost";
}

export function isLoopbackBackendUrl(value: string): boolean {
  try {
    const parsed = new URL(value);
    if (!isLoopbackHostname(parsed.hostname)) return false;
    return parsed.port === "8000" || parsed.port === "18000";
  } catch {
    return false;
  }
}

export function validateApiBaseInput(value: string): ApiBaseValidation {
  const raw = String(value || "").trim();
  if (!raw) {
    return { ok: false, normalized: "", reason: "Enter a backend URL or / for same-origin." };
  }

  if (isSameOriginPath(raw)) {
    return { ok: true, normalized: trimTrailingSlash(raw), isRemote: false, isLoopback: false };
  }

  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    return { ok: false, normalized: raw, reason: "Use an absolute http(s) URL, or / for same-origin." };
  }

  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return { ok: false, normalized: raw, reason: "Only http:// and https:// backend URLs are supported." };
  }

  if (!parsed.hostname) {
    return { ok: false, normalized: raw, reason: "Backend URL must include a host." };
  }

  parsed.hash = "";
  parsed.search = "";
  const normalized = trimTrailingSlash(parsed.toString());
  const isLoopback = isLoopbackHostname(parsed.hostname);
  return { ok: true, normalized, isRemote: !isLoopback, isLoopback };
}

function safeStoredOrDefaultApiBase(stored: string | null): string {
  const candidate = stored !== null ? stored : DEFAULT_API_BASE;
  const validation = validateApiBaseInput(candidate);
  return validation.ok ? validation.normalized : DEFAULT_API_BASE;
}

function shouldUseDevProxyForBase(value: string): boolean {
  const normalized = trimTrailingSlash(value);
  if (!normalized || normalized === "/") return true;
  if (!canUseWindowLocation()) return false;
  if (!isLoopbackBackendUrl(normalized)) return false;
  const current = window.location;
  return isLoopbackHostname(current.hostname) && (current.port === "5173" || current.port === "4173");
}

function normalizeApiBaseForRuntime(value: string): string {
  const validation = validateApiBaseInput(value);
  const normalized = validation.ok ? validation.normalized : "/";
  if (shouldUseDevProxyForBase(normalized)) return "";
  return normalized;
}

export function getApiBase(): string {
  const stored = readStoredApiBase();
  return normalizeApiBaseForRuntime(safeStoredOrDefaultApiBase(stored));
}

export function setApiBase(next: string): string {
  const validation = validateApiBaseInput(next);
  if (!validation.ok) throw new Error(validation.reason);
  const runtimeValue = normalizeApiBaseForRuntime(validation.normalized);
  localStorage.setItem("weall.api.base", validation.normalized);
  return runtimeValue;
}

export function getApiBaseUrl(): string {
  return getApiBase();
}

export function setApiBaseUrl(next: string): string {
  return setApiBase(next);
}

export function getAccount(): string | null {
  try {
    const v = localStorage.getItem("weall.account");
    return v && v.trim() ? v.trim() : null;
  } catch {
    return null;
  }
}

export function setAccount(account: string | null): void {
  try {
    if (account && account.trim()) {
      localStorage.setItem("weall.account", account.trim());
    } else {
      localStorage.removeItem("weall.account");
    }
  } catch {
    // ignore storage failures
  }
}

function extractErrorMessage(payload: unknown, fallback: string): string {
  if (!payload || typeof payload !== "object") {
    return fallback;
  }

  const maybe = payload as ApiErrorPayload;

  if (maybe.error?.message && typeof maybe.error.message === "string") {
    return maybe.error.message;
  }

  if (typeof maybe.detail === "string") {
    return maybe.detail;
  }

  if (Array.isArray(maybe.detail) && maybe.detail.length > 0) {
    const first = maybe.detail[0];
    if (first && typeof first === "object" && "msg" in first) {
      const msg = (first as { msg?: unknown }).msg;
      if (typeof msg === "string" && msg.trim()) {
        return msg;
      }
    }
    return fallback;
  }

  return fallback;
}

function safeJsonParse(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

function resolveBase(base?: string): string {
  return normalizeApiBaseForRuntime(base || getApiBase());
}

async function request<T = any>(
  path: string,
  init: RequestInit & { method?: HttpMethod } = {},
  base?: string,
): Promise<T> {
  const res = await fetch(`${resolveBase(base)}${path}`, {
    ...init,
    headers: {
      Accept: "application/json",
      ...(init.body && !(init.body instanceof FormData) ? { "Content-Type": "application/json" } : {}),
      ...(init.headers || {}),
    },
  });

  const text = await res.text();
  const payload = text ? safeJsonParse(text) : null;

  if (!res.ok) {
    throw new ApiError(
      extractErrorMessage(payload, `Request failed with status ${res.status}`),
      res.status,
      payload,
    );
  }

  return payload as T;
}

export async function apiGet<T = any>(path: string, base?: string, headers?: HeadersInit): Promise<T> {
  return request<T>(path, { method: "GET", headers }, base);
}

export async function apiPost<T = any>(
  path: string,
  body?: unknown,
  base?: string,
  headers?: HeadersInit,
): Promise<T> {
  return request<T>(
    path,
    {
      method: "POST",
      headers,
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    },
    base,
  );
}

export type StatusResponse = {
  ok: boolean;
  service: string;
  version: string;
  chain_id?: string;
  height?: number;
  tip?: string;
};

export type FeedItem = {
  cid?: string;
  tx_id?: string;
  author?: string;
  account?: string;
  text?: string;
  body?: string;
  created_at_ms?: number;
  ts_ms?: number;
  visibility?: string;
  attachments?: Array<{
    cid?: string;
    mime?: string;
    kind?: string;
    name?: string;
    size_bytes?: number;
  }>;
};

export type FeedParams = {
  limit?: number;
  visibility?: string;
  cursor?: string | null;
  tags?: string[] | string;
  author?: string;
  ranking?: string;
  rank?: string;
};

export type FeedResponse = {
  ok?: boolean;
  items?: FeedItem[];
  next_cursor?: string | null;
};


export type SessionLoginResponse = {
  ok?: boolean;
  account?: string;
  device?: {
    device_id?: string;
    pubkey?: string;
  };
  session?: {
    session_key?: string;
    issued_at_ts?: number;
    ttl_s?: number;
    active?: boolean;
  };
};

export async function createBrowserSession(input: {
  account: string;
  session_key: string;
  ttl_s: number;
  issued_at_ms: number;
  device_id: string;
  pubkey: string;
  sig?: string;
  signature?: string;
}, base?: string): Promise<SessionLoginResponse> {
  const sig = String(input.sig || input.signature || "").trim();
  return request<SessionLoginResponse>(
    "/v1/session/login",
    {
      method: "POST",
      body: JSON.stringify({
        account: input.account,
        session_key: input.session_key,
        ttl_s: input.ttl_s,
        issued_at_ms: input.issued_at_ms,
        device_id: input.device_id,
        pubkey: input.pubkey,
        sig,
      }),
    },
    base,
  );
}

export async function fetchStatus(base?: string): Promise<StatusResponse> {
  return request<StatusResponse>("/v1/status", { method: "GET" }, base);
}

export async function fetchFeed(params?: FeedParams, base?: string): Promise<FeedResponse> {
  const qs = withSearch("/v1/feed", {
    limit: params?.limit,
    visibility: params?.visibility,
    cursor: params?.cursor,
    tags: normalizeTagsParam(params?.tags),
    author: params?.author,
    ranking: params?.ranking || params?.rank,
  });
  return request<FeedResponse>(qs, { method: "GET" }, base);
}

function withSearch(
  path: string,
  params?: Record<string, string | number | boolean | null | undefined>,
): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params || {})) {
    if (value === undefined || value === null || value === "") continue;
    search.set(key, String(value));
  }
  const qs = search.toString();
  return qs ? `${path}?${qs}` : path;
}

function normalizeTagsParam(tags?: string[] | string): string | undefined {
  if (Array.isArray(tags)) {
    const filtered = tags.map((t) => String(t).trim()).filter(Boolean);
    return filtered.length ? filtered.join(",") : undefined;
  }
  if (typeof tags === "string" && tags.trim()) {
    return tags.trim();
  }
  return undefined;
}

function normalizeAccountField(input: {
  account?: string;
  account_id?: string;
  operator_account_id?: string;
}): string {
  return (
    input.account?.trim() ||
    input.account_id?.trim() ||
    input.operator_account_id?.trim() ||
    ""
  );
}

async function uploadFile<T = any>(
  path: string,
  file: File,
  base?: string,
  headers?: HeadersInit,
  extraFields?: Record<string, string>,
): Promise<T> {
  const form = new FormData();
  form.append("file", file);
  for (const [k, v] of Object.entries(extraFields || {})) {
    form.append(k, v);
  }
  return request<T>(
    path,
    {
      method: "POST",
      body: form,
      headers,
    },
    base,
  );
}

function looksLikeHeaders(value: unknown): value is HeadersInit {
  if (!value) return false;
  if (value instanceof Headers) return true;
  if (Array.isArray(value)) return true;
  return typeof value === "object";
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value) && !(value instanceof Headers);
}

function splitParamsBaseHeaders(
  a?: unknown,
  b?: unknown,
  c?: unknown,
): { params?: Record<string, unknown>; base?: string; headers?: HeadersInit } {
  let params: Record<string, unknown> | undefined;
  let base: string | undefined;
  let headers: HeadersInit | undefined;

  if (isPlainObject(a)) {
    params = a;
    if (typeof b === "string") base = b;
    if (looksLikeHeaders(c)) headers = c;
  } else {
    if (typeof a === "string") base = a;
    if (looksLikeHeaders(b)) headers = b;
  }

  return { params, base, headers };
}

export const weall = {
  status(base?: string) {
    return fetchStatus(base);
  },

  economicsStatus(params?: { account?: string }, base?: string, headers?: HeadersInit): Promise<any> {
    return apiGet(withSearch("/v1/economics/status", { account: params?.account }), base, headers);
  },

  walletStatus(account: string, base?: string, headers?: HeadersInit): Promise<any> {
    return apiGet(`/v1/wallet/${encodeURIComponent(account)}`, base, headers);
  },

  economicsActivationReadiness(base?: string, headers?: HeadersInit): Promise<any> {
    return apiGet("/v1/economics/activation/readiness", base, headers);
  },

  economicsTransferPreview(params: { from_account?: string; to_account?: string; amount?: number }, base?: string, headers?: HeadersInit): Promise<any> {
    return apiGet(withSearch("/v1/economics/transfer/preview", params || {}), base, headers);
  },

  treasuryStatus(base?: string, headers?: HeadersInit): Promise<any> {
    return apiGet("/v1/treasury/status", base, headers);
  },

  blockProductionProof(base?: string, headers?: HeadersInit): Promise<any> {
    return apiGet("/v1/consensus/block-production/proof", base, headers);
  },

  readyz(base?: string) {
    return apiGet("/v1/readyz", base);
  },

  health(base?: string) {
    return apiGet("/v1/health", base);
  },

  operatorStatus(base?: string, headers?: HeadersInit): Promise<any> {
    return apiGet("/v1/status/operator", base, headers);
  },

  consensusStatus(base?: string, headers?: HeadersInit): Promise<any> {
    return apiGet("/v1/status/consensus", base, headers);
  },

  mempoolStatus(base?: string, headers?: HeadersInit): Promise<any> {
    return apiGet("/v1/status/mempool", base, headers);
  },

  storageIpfsOps(base?: string, headers?: HeadersInit): Promise<any> {
    return apiGet("/v1/storage/ipfs/ops", base, headers);
  },

  chainHead(base?: string, headers?: HeadersInit): Promise<any> {
    return apiGet("/v1/chain/head", base, headers);
  },

  chainIdentity(base?: string, headers?: HeadersInit): Promise<any> {
    return apiGet("/v1/chain/identity", base, headers);
  },

  launchMatrix(base?: string, headers?: HeadersInit): Promise<any> {
    return apiGet("/v1/status/launch-matrix", base, headers);
  },

  testnetCapabilities(base?: string, headers?: HeadersInit): Promise<any> {
    return apiGet("/v1/status/testnet-capabilities", base, headers);
  },

  blockProductionReadiness(base?: string, headers?: HeadersInit): Promise<any> {
    return apiGet("/v1/consensus/block-production/readiness", base, headers);
  },

  helperReadiness(base?: string, headers?: HeadersInit): Promise<any> {
    return apiGet("/v1/status/helper/readiness", base, headers);
  },

  netSelf(base?: string, headers?: HeadersInit): Promise<any> {
    return apiGet("/v1/net/self", base, headers);
  },

  publicSeeds(base?: string, headers?: HeadersInit): Promise<any> {
    return apiGet("/v1/nodes/seeds", base, headers);
  },

  publicValidators(base?: string, headers?: HeadersInit): Promise<any> {
    return apiGet("/v1/nodes/validators", base, headers);
  },

  observerEdgeStatus(base?: string, headers?: HeadersInit): Promise<any> {
    return apiGet("/v1/observer/edge/status", base, headers);
  },

  account(account: string, base?: string, headers?: HeadersInit): Promise<any> {
    return apiGet(`/v1/accounts/${encodeURIComponent(account)}`, base, headers);
  },

  getAccount(account: string, base?: string, headers?: HeadersInit): Promise<any> {
    return apiGet(`/v1/accounts/${encodeURIComponent(account)}`, base, headers);
  },

  accountRegistered(account: string, base?: string, headers?: HeadersInit): Promise<any> {
    return apiGet(`/v1/accounts/${encodeURIComponent(account)}/registered`, base, headers);
  },

  accountReviewerStatus(account: string, base?: string, headers?: HeadersInit): Promise<any> {
    return apiGet(`/v1/accounts/${encodeURIComponent(account)}/reviewer-status`, base, headers);
  },

  accountOperatorStatus(
    account: string,
    base?: string,
    headers?: HeadersInit,
    params?: { node_pubkey?: string },
  ): Promise<any> {
    const query = params?.node_pubkey ? `?node_pubkey=${encodeURIComponent(params.node_pubkey)}` : "";
    return apiGet(`/v1/accounts/${encodeURIComponent(account)}/operator-status${query}`, base, headers);
  },

  reputationMe(base?: string, headers?: HeadersInit): Promise<any> {
    return apiGet("/v1/reputation/me", base, headers);
  },

  reputationSummary(account: string, base?: string, headers?: HeadersInit): Promise<any> {
    return apiGet(`/v1/reputation/${encodeURIComponent(account)}/summary`, base, headers);
  },

  reputationMatrix(account: string, base?: string, headers?: HeadersInit): Promise<any> {
    return apiGet(`/v1/reputation/${encodeURIComponent(account)}/matrix`, base, headers);
  },

  reputationEligibility(account: string, base?: string, headers?: HeadersInit): Promise<any> {
    return apiGet(`/v1/reputation/${encodeURIComponent(account)}/eligibility`, base, headers);
  },

  reputationEventCodes(base?: string, headers?: HeadersInit): Promise<any> {
    return apiGet("/v1/reputation/event-codes", base, headers);
  },

  reputationEvents(account: string, base?: string, headers?: HeadersInit): Promise<any> {
    return apiGet(`/v1/reputation/${encodeURIComponent(account)}/events`, base, headers);
  },

  accountNonce(account: string, base?: string, headers?: HeadersInit): Promise<any> {
    return apiGet(`/v1/accounts/${encodeURIComponent(account)}/nonce`, base, headers)
      .catch(() => apiGet(`/v1/accounts/${encodeURIComponent(account)}`, base, headers)
        .then((r: any) => ({
          ok: true,
          account,
          nonce: r?.state?.nonce ?? 0,
          chain_nonce: r?.state?.nonce ?? 0,
          nonce_cursor: r?.state?.nonce ?? 0,
          next_nonce: Number(r?.state?.nonce ?? 0) + 1,
        })));
  },

  accountFeed(
    account: string,
    a?: FeedParams | string,
    b?: string | HeadersInit,
    c?: HeadersInit,
  ): Promise<any> {
    const { params, base, headers } = splitParamsBaseHeaders(a, b, c);
    return apiGet(
      withSearch(`/v1/accounts/${encodeURIComponent(account)}/feed`, {
        limit: params?.limit as number | undefined,
        stage: (params as any)?.stage as string | undefined,
        active_only: (params as any)?.activeOnly ? 1 : undefined,
        include_summary: (params as any)?.includeSummary ? 1 : undefined,
        visibility: params?.visibility as string | undefined,
        cursor: params?.cursor as string | null | undefined,
        tags: normalizeTagsParam(params?.tags as string[] | string | undefined),
        author: params?.author as string | undefined,
      }),
      base,
      headers,
    );
  },

  feed(
    params?: FeedParams,
    base?: string,
    headers?: HeadersInit,
  ): Promise<any> {
    return apiGet(
      withSearch("/v1/feed", {
        limit: params?.limit,
        visibility: params?.visibility,
        cursor: params?.cursor,
        tags: normalizeTagsParam(params?.tags),
        author: params?.author,
        ranking: params?.ranking || params?.rank,
      }),
      base,
      headers,
    );
  },

  thread(
    id: string,
    a?: { limit?: number; cursor?: string | null } | string,
    b?: string | HeadersInit,
    c?: HeadersInit,
  ): Promise<any> {
    const { params, base, headers } = splitParamsBaseHeaders(a, b, c);
    return apiGet(
      withSearch(`/v1/thread/${encodeURIComponent(id)}`, {
        limit: params?.limit as number | undefined,
        cursor: params?.cursor as string | null | undefined,
      }),
      base,
      headers,
    );
  },


  proposals(
    a?: { limit?: number; stage?: string; activeOnly?: boolean; includeSummary?: boolean } | string,
    b?: string | HeadersInit,
    c?: HeadersInit,
  ): Promise<any> {
    const { params, base, headers } = splitParamsBaseHeaders(a, b, c);
    return apiGet(
      withSearch("/v1/gov/proposals", {
        limit: params?.limit as number | undefined,
        stage: (params as any)?.stage as string | undefined,
        active_only: (params as any)?.activeOnly ? 1 : undefined,
        include_summary: (params as any)?.includeSummary ? 1 : undefined,
      }),
      base,
      headers,
    );
  },

  proposal(id: string, base?: string, headers?: HeadersInit): Promise<any> {
    return apiGet(`/v1/gov/proposals/${encodeURIComponent(id)}`, base, headers);
  },

  proposalVotes(id: string, base?: string, headers?: HeadersInit): Promise<any> {
    return apiGet(`/v1/gov/proposals/${encodeURIComponent(id)}/votes`, base, headers);
  },

  stateSnapshot(base?: string, headers?: HeadersInit): Promise<any> {
    return apiGet("/v1/state/snapshot", base, headers);
  },

  activityNotices(base?: string, headers?: HeadersInit): Promise<any> {
    return apiGet("/v1/activity/notices", base, headers);
  },

  disputes(
    a?: { limit?: number; targetId?: string } | string,
    b?: string | HeadersInit,
    c?: HeadersInit,
  ): Promise<any> {
    const { params, base, headers } = splitParamsBaseHeaders(a, b, c);
    return apiGet(
      withSearch("/v1/disputes", {
        limit: params?.limit as number | undefined,
        stage: (params as any)?.stage as string | undefined,
        active_only: (params as any)?.activeOnly ? 1 : undefined,
        include_summary: (params as any)?.includeSummary ? 1 : undefined,
        target_id: params?.targetId as string | undefined,
      }),
      base,
      headers,
    );
  },

  dispute(id: string, base?: string, headers?: HeadersInit): Promise<any> {
    return apiGet(`/v1/disputes/${encodeURIComponent(id)}`, base, headers);
  },

  disputeVotes(id: string, base?: string, headers?: HeadersInit): Promise<any> {
    return apiGet(`/v1/disputes/${encodeURIComponent(id)}/votes`, base, headers);
  },

  disputesEligible(base?: string, headers?: HeadersInit): Promise<any> {
    return apiGet("/v1/disputes/eligible", base, headers);
  },

  disputesCurrent(base?: string, headers?: HeadersInit): Promise<any> {
    return apiGet("/v1/disputes/current", base, headers);
  },

  disputeAccept(id: string, base?: string, headers?: HeadersInit): Promise<any> {
    return apiPost(`/v1/disputes/${encodeURIComponent(id)}/accept`, {}, base, headers);
  },

  disputeWithdraw(id: string, base?: string, headers?: HeadersInit): Promise<any> {
    return apiPost(`/v1/disputes/${encodeURIComponent(id)}/withdraw`, {}, base, headers);
  },

  disputeVote(id: string, payload: Record<string, unknown>, base?: string, headers?: HeadersInit): Promise<any> {
    return apiPost(`/v1/disputes/${encodeURIComponent(id)}/vote`, payload || {}, base, headers);
  },

  content(id: string, base?: string, headers?: HeadersInit): Promise<any> {
    return apiGet(`/v1/content/${encodeURIComponent(id)}`, base, headers);
  },

  contentScoped(id: string, base?: string, headers?: HeadersInit): Promise<any> {
    return apiGet(`/v1/content/${encodeURIComponent(id)}/scoped`, base, headers);
  },

  groupFeed(
    id: string,
    a?: FeedParams | string,
    b?: string | HeadersInit,
    c?: HeadersInit,
  ): Promise<any> {
    const { params, base, headers } = splitParamsBaseHeaders(a, b, c);
    return apiGet(
      withSearch(`/v1/groups/${encodeURIComponent(id)}/feed`, {
        limit: params?.limit as number | undefined,
        stage: (params as any)?.stage as string | undefined,
        active_only: (params as any)?.activeOnly ? 1 : undefined,
        include_summary: (params as any)?.includeSummary ? 1 : undefined,
        visibility: params?.visibility as string | undefined,
        cursor: params?.cursor as string | null | undefined,
        tags: normalizeTagsParam(params?.tags as string[] | string | undefined),
        author: params?.author as string | undefined,
      }),
      base,
      headers,
    );
  },

  socialFollowing(account: string, base?: string, headers?: HeadersInit): Promise<any> {
    return apiGet(`/v1/social/${encodeURIComponent(account)}/following`, base, headers);
  },

  socialMe(base?: string, headers?: HeadersInit): Promise<any> {
    return apiGet("/v1/social/me", base, headers);
  },

  pohState(account: string, base?: string, headers?: HeadersInit): Promise<any> {
    return apiGet(`/v1/accounts/${encodeURIComponent(account)}`, base, headers).then((r: any) => ({ ok: true, account, poh_tier: r?.state?.poh_tier ?? 0, reputation: r?.state?.reputation ?? 0, banned: !!r?.state?.banned, locked: !!r?.state?.locked }));
  },


  pohAsyncMyCases(account: string, base?: string, headers?: HeadersInit): Promise<any> {
    return apiGet(withSearch('/v1/poh/async/my-cases', { account }), base, headers);
  },

  pohAsyncJurorCases(
    a?: string,
    b?: string | HeadersInit,
    c?: HeadersInit,
  ): Promise<any> {
    const base = typeof a === "string" && !a.startsWith("@") && !a.startsWith("did:") ? a : typeof b === "string" ? b : undefined;
    const headers =
      looksLikeHeaders(c) ? c : looksLikeHeaders(b) ? b : undefined;
    return apiGet(withSearch("/v1/poh/async/juror-cases", { juror: typeof a === "string" && (a.startsWith("@") || a.startsWith("did:")) ? a : undefined }), base, headers);
  },

  pohAsyncCase(caseId: string, base?: string, headers?: HeadersInit): Promise<any> {
    return apiGet(`/v1/poh/async/case/${encodeURIComponent(caseId)}`, base, headers);
  },

  pohTier2MyCases(account: string, base?: string, headers?: HeadersInit): Promise<any> {
    return apiGet(withSearch('/v1/poh/tier2/my-cases', { account }), base, headers);
  },

  pohTier2JurorCases(
    a?: string,
    b?: string | HeadersInit,
    c?: HeadersInit,
  ): Promise<any> {
    const base = typeof a === "string" && !a.startsWith("@") && !a.startsWith("did:") ? a : typeof b === "string" ? b : undefined;
    const headers =
      looksLikeHeaders(c) ? c : looksLikeHeaders(b) ? b : undefined;
    return apiGet(withSearch("/v1/poh/tier2/juror-cases", { juror: typeof a === "string" && (a.startsWith("@") || a.startsWith("did:")) ? a : undefined }), base, headers);
  },

  pohTier2Case(caseId: string, base?: string, headers?: HeadersInit): Promise<any> {
    return apiGet(`/v1/poh/tier2/case/${encodeURIComponent(caseId)}`, base, headers);
  },

  pohLiveAssigned(account: string, base?: string, headers?: HeadersInit): Promise<any> {
    return apiGet(withSearch('/v1/poh/live/assigned', { juror: account }), base, headers);
  },

  pohLiveMyCases(account: string, base?: string, headers?: HeadersInit): Promise<any> {
    return apiGet(withSearch('/v1/poh/live/my-cases', { account }), base, headers);
  },

  pohLiveSessions(base?: string, headers?: HeadersInit): Promise<any> {
    return apiGet("/v1/poh/live/sessions", base, headers);
  },

  pohLiveCase(caseId: string, base?: string, headers?: HeadersInit): Promise<any> {
    return apiGet(`/v1/poh/live/case/${encodeURIComponent(caseId)}`, base, headers);
  },

  pohLiveSessionParticipants(sessionId: string, base?: string, headers?: HeadersInit): Promise<any> {
    return apiGet(`/v1/poh/live/session/${encodeURIComponent(sessionId)}/participants`, base, headers);
  },

  pohLiveSessionPresence(sessionId: string, base?: string, headers?: HeadersInit): Promise<any> {
    return apiGet(`/v1/poh/live/session/${encodeURIComponent(sessionId)}/presence`, base, headers);
  },

  pohLiveSessionPresenceUpdate(sessionId: string, payload: unknown, base?: string, headers?: HeadersInit): Promise<any> {
    return apiPost(`/v1/poh/live/session/${encodeURIComponent(sessionId)}/presence`, payload, base, headers);
  },

  pohLiveWebRTCSignals(sessionId: string, sinceSeq = 0, base?: string, headers?: HeadersInit): Promise<any> {
    return apiGet(`/v1/poh/live/session/${encodeURIComponent(sessionId)}/webrtc/signals?since_seq=${encodeURIComponent(String(sinceSeq || 0))}`, base, headers);
  },

  pohLiveWebRTCRelayConfig(base?: string, headers?: HeadersInit): Promise<any> {
    return apiGet("/v1/poh/live/webrtc/relay-config", base, headers);
  },

  pohLiveWebRTCSignalSend(sessionId: string, payload: unknown, base?: string, headers?: HeadersInit): Promise<any> {
    return apiPost(`/v1/poh/live/session/${encodeURIComponent(sessionId)}/webrtc/signals`, payload, base, headers);
  },

  pohOperatorLiveFinalize(payload: unknown, base?: string, token?: string): Promise<any> {
    const headers = token ? { "X-WeAll-Operator-Token": token } : undefined;
    return apiPost("/v1/poh/operator/live/finalize", payload, base, headers);
  },

  pohLiveTxRequest(payload: unknown, base?: string, headers?: HeadersInit): Promise<any> {
    return apiPost("/v1/poh/live/tx/request", payload, base, headers);
  },


  pohAsyncTxJurorAccept(payload: unknown, base?: string, headers?: HeadersInit): Promise<any> {
    return apiPost("/v1/poh/async/tx/juror-accept", payload, base, headers);
  },

  pohAsyncTxJurorDecline(payload: unknown, base?: string, headers?: HeadersInit): Promise<any> {
    return apiPost("/v1/poh/async/tx/juror-decline", payload, base, headers);
  },

  pohAsyncTxReview(payload: unknown, base?: string, headers?: HeadersInit): Promise<any> {
    return apiPost("/v1/poh/async/tx/review", payload, base, headers);
  },

  pohLiveTxJurorAccept(payload: unknown, base?: string, headers?: HeadersInit): Promise<any> {
    return apiPost("/v1/poh/live/tx/juror-accept", payload, base, headers);
  },

  pohLiveTxJurorDecline(payload: unknown, base?: string, headers?: HeadersInit): Promise<any> {
    return apiPost("/v1/poh/live/tx/juror-decline", payload, base, headers);
  },

  pohLiveTxAttendance(payload: unknown, base?: string, headers?: HeadersInit): Promise<any> {
    return apiPost("/v1/poh/live/tx/attendance", payload, base, headers);
  },

  pohLiveTxVerdict(payload: unknown, base?: string, headers?: HeadersInit): Promise<any> {
    return apiPost("/v1/poh/live/tx/verdict", payload, base, headers);
  },

  pohAsyncVideoUpload(file: File, base?: string, headers?: HeadersInit): Promise<any> {
    return uploadFile('/v1/poh/async/evidence/video/upload', file, base, headers);
  },

  pohTier2VideoUpload(file: File, base?: string, headers?: HeadersInit): Promise<any> {
    return uploadFile('/v1/poh/tier2/video/upload', file, base, headers);
  },

  mediaUpload(file: File, base?: string, headers?: HeadersInit): Promise<any> {
    return uploadFile("/v1/media/upload", file, base, headers);
  },

  mediaStatus(cid: string, base?: string, headers?: HeadersInit): Promise<any> {
    return apiGet(`/v1/media/status/${encodeURIComponent(cid)}`, base, headers);
  },

  mediaResolve(ids: string[], base?: string, headers?: HeadersInit): Promise<any> {
    const cleanIds = Array.from(new Set((ids || []).map((x) => String(x || "").trim()).filter(Boolean)));
    return apiGet(withSearch("/v1/media/resolve", { ids: cleanIds.join(",") }), base, headers);
  },

  mediaProxyUrl(cid: string, base?: string) {
    return `${resolveBase(base)}/v1/media/proxy/${encodeURIComponent(cid)}`;
  },

  mediaGatewayUrl(cid: string, base?: string) {
    return `${resolveBase(base)}/v1/media/gateway/${encodeURIComponent(cid)}`;
  },

  txSubmit(payload: unknown, base?: string, headers?: HeadersInit): Promise<any> {
    return apiPost("/v1/tx/submit", payload, base, headers);
  },

  txStatus(txId: string, base?: string, headers?: HeadersInit): Promise<any> {
    return apiGet(`/v1/tx/status/${encodeURIComponent(txId)}`, base, headers);
  },

  txCatalog(
    params?: { context?: string; domain?: string; search?: string },
    base?: string,
    headers?: HeadersInit,
  ): Promise<any> {
    return apiGet(
      withSearch("/v1/tx/catalog", params as Record<string, string | number | boolean | null | undefined>),
      base,
      headers,
    );
  },
};

export const api = {
  account(account: string, base?: string, headers?: HeadersInit) {
    return weall.account(account, base, headers);
  },
  groups: {
    list(params?: { limit?: number }, base?: string, headers?: HeadersInit) {
      return apiGet(
        withSearch("/v1/groups", params as Record<string, string | number | boolean | null | undefined>),
        base,
        headers,
      );
    },
    get(id: string, base?: string, headers?: HeadersInit) {
      return apiGet(`/v1/groups/${encodeURIComponent(id)}`, base, headers);
    },
    members(id: string, base?: string, headers?: HeadersInit) {
      return apiGet(`/v1/groups/${encodeURIComponent(id)}/members`, base, headers);
    },
    membership(id: string, base?: string, headers?: HeadersInit) {
      return apiGet(`/v1/groups/${encodeURIComponent(id)}/membership`, base, headers);
    },
    join(payload: unknown, base?: string, headers?: HeadersInit) {
      return apiPost("/v1/groups/join", payload, base, headers);
    },
    leave(payload: unknown, base?: string, headers?: HeadersInit) {
      return apiPost("/v1/groups/leave", payload, base, headers);
    },
  },
};


export async function pohLiveWebRTCSignalDiagnostics(headers?: Record<string, string>): Promise<any> {
  return request(`/v1/poh/live/webrtc/signals/diagnostics`, { method: "GET", headers: headers || {} });
}
