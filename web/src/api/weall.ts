const ENV_API_BASE = String(((import.meta as any).env?.VITE_WEALL_API_BASE as string) || "").trim();
const DEFAULT_API_BASE = ENV_API_BASE || "/";
const DEFAULT_EMAIL_ORACLE_BASE = DEFAULT_API_BASE || "/";

export type HttpMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";

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

function readStoredEmailOracleBase(): string | null {
  try {
    return localStorage.getItem("weall.email.oracle.base");
  } catch {
    return null;
  }
}

function trimTrailingSlash(value: string): string {
  const trimmed = value.trim();
  if (!trimmed || trimmed === "/") return "/";
  return trimmed.replace(/\/+$/, "");
}

function canUseWindowLocation(): boolean {
  return typeof window !== "undefined" && !!window.location;
}

function isLoopbackHostname(hostname: string): boolean {
  const host = String(hostname || "").trim().toLowerCase();
  return host === "127.0.0.1" || host === "localhost";
}

function isLoopbackBackendUrl(value: string): boolean {
  try {
    const parsed = new URL(value);
    if (!isLoopbackHostname(parsed.hostname)) return false;
    return parsed.port === "8000" || parsed.port === "18000";
  } catch {
    return false;
  }
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
  const normalized = trimTrailingSlash(value);
  if (!normalized) return "/";
  if (shouldUseDevProxyForBase(normalized)) return "";
  return normalized;
}

export function getApiBase(): string {
  const stored = readStoredApiBase();
  return normalizeApiBaseForRuntime(stored !== null ? stored : DEFAULT_API_BASE);
}

export function setApiBase(next: string): string {
  const normalized = trimTrailingSlash(next);
  const runtimeValue = normalizeApiBaseForRuntime(normalized);
  localStorage.setItem("weall.api.base", normalized);
  return runtimeValue;
}

export function getApiBaseUrl(): string {
  return getApiBase();
}

export function setApiBaseUrl(next: string): string {
  return setApiBase(next);
}

export function getEmailOracleBaseUrl(): string {
  const stored = readStoredEmailOracleBase();
  return normalizeApiBaseForRuntime(
    stored !== null ? stored : (getApiBase() || DEFAULT_EMAIL_ORACLE_BASE),
  );
}

export function setEmailOracleBaseUrl(next: string): string {
  const normalized = trimTrailingSlash(next);
  const runtimeValue = normalizeApiBaseForRuntime(normalized);
  localStorage.setItem("weall.email.oracle.base", normalized);
  return runtimeValue;
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
};

export type FeedResponse = {
  ok?: boolean;
  items?: FeedItem[];
  next_cursor?: string | null;
};

export type PohEmailBeginResponse = {
  ok?: boolean;
  request_id?: string;
  challenge_id?: string;
  status?: string;
  message?: string;
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
  });
  return request<FeedResponse>(qs, { method: "GET" }, base);
}

export async function beginPohEmailVerification(input: {
  account?: string;
  account_id?: string;
  operator_account_id?: string;
  email: string;
  turnstile_token?: string;
}): Promise<PohEmailBeginResponse> {
  const account = normalizeAccountField(input);
  return request<PohEmailBeginResponse>(
    "/v1/poh/email/begin",
    {
      method: "POST",
      body: JSON.stringify({
        account,
        email: input.email,
        ...(input.turnstile_token ? { turnstile_token: input.turnstile_token } : {}),
      }),
    },
    undefined,
  );
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

  readyz(base?: string) {
    return apiGet("/v1/readyz", base);
  },

  health(base?: string) {
    return apiGet("/v1/health", base);
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

  accountNonce(account: string, base?: string, headers?: HeadersInit): Promise<any> {
    return apiGet(`/v1/accounts/${encodeURIComponent(account)}`, base, headers).then((r: any) => ({ ok: true, account, nonce: r?.state?.nonce ?? 0, next_nonce: r?.state?.nonce ?? 0 }));
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
      }),
      base,
      headers,
    );
  },

  thread(id: string, base?: string, headers?: HeadersInit): Promise<any> {
    return apiGet(`/v1/thread/${encodeURIComponent(id)}`, base, headers);
  },

  proposals(
    a?: { limit?: number } | string,
    b?: string | HeadersInit,
    c?: HeadersInit,
  ): Promise<any> {
    const { params, base, headers } = splitParamsBaseHeaders(a, b, c);
    return apiGet(
      withSearch("/v1/gov/proposals", {
        limit: params?.limit as number | undefined,
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

  content(id: string, base?: string, headers?: HeadersInit): Promise<any> {
    return apiGet(`/v1/content/${encodeURIComponent(id)}`, base, headers);
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

  pohTier3Assigned(account: string, base?: string, headers?: HeadersInit): Promise<any> {
    return apiGet(withSearch('/v1/poh/tier3/assigned', { juror: account }), base, headers);
  },

  pohTier3Sessions(base?: string, headers?: HeadersInit): Promise<any> {
    return apiGet("/v1/poh/tier3/sessions", base, headers);
  },

  pohTier3Case(caseId: string, base?: string, headers?: HeadersInit): Promise<any> {
    return apiGet(`/v1/poh/tier3/case/${encodeURIComponent(caseId)}`, base, headers);
  },

  pohTier3SessionParticipants(sessionId: string, base?: string, headers?: HeadersInit): Promise<any> {
    return apiGet(`/v1/poh/tier3/session/${encodeURIComponent(sessionId)}/participants`, base, headers);
  },

  emailOracleStart(
    payload: { account?: string; account_id?: string; operator_account_id?: string; email: string; turnstile_token?: string },
    base?: string,
    headers?: HeadersInit,
  ): Promise<any> {
    return apiPost(
      "/v1/poh/email/begin",
      {
        account: normalizeAccountField(payload),
        email: payload.email,
        ...(payload.turnstile_token ? { turnstile_token: payload.turnstile_token } : {}),
      },
      base,
      headers,
    );
  },

  emailOracleVerify(
    payload: {
      code: string;
      request_id?: string;
      challenge_id?: string;
      turnstile_token?: string;
    },
    base?: string,
    headers?: HeadersInit,
  ): Promise<any> {
    return apiPost(
      "/verify",
      {
        challenge_id: payload.challenge_id || payload.request_id || "",
        code: payload.code,
        ...(payload.turnstile_token ? { turnstile_token: payload.turnstile_token } : {}),
      },
      base,
      headers,
    );
  },

  pohEmailBegin(
    payload: { account?: string; account_id?: string; operator_account_id?: string; email: string; turnstile_token?: string },
    base?: string,
    headers?: HeadersInit,
  ): Promise<any> {
    return apiPost(
      "/v1/poh/email/begin",
      {
        account: normalizeAccountField(payload),
        email: payload.email,
        ...(payload.turnstile_token ? { turnstile_token: payload.turnstile_token } : {}),
      },
      base,
      headers,
    );
  },


  pohEmailReceiptTxSubmit(payload: unknown, base?: string, headers?: HeadersInit): Promise<any> {
    return apiPost("/v1/poh/email/tx/receipt-submit", payload, base, headers);
  },

  pohTier2TxRequest(payload: unknown, base?: string, headers?: HeadersInit): Promise<any> {
    return apiPost("/v1/poh/tier2/tx/request", payload, base, headers);
  },

  pohTier3TxRequest(payload: unknown, base?: string, headers?: HeadersInit): Promise<any> {
    return apiPost("/v1/poh/tier3/tx/request", payload, base, headers);
  },

  pohTier2TxJurorAccept(payload: unknown, base?: string, headers?: HeadersInit): Promise<any> {
    return apiPost("/v1/poh/tier2/tx/juror-accept", payload, base, headers);
  },

  pohTier2TxJurorDecline(payload: unknown, base?: string, headers?: HeadersInit): Promise<any> {
    return apiPost("/v1/poh/tier2/tx/juror-decline", payload, base, headers);
  },

  pohTier2TxReview(payload: unknown, base?: string, headers?: HeadersInit): Promise<any> {
    return apiPost("/v1/poh/tier2/tx/review", payload, base, headers);
  },

  pohTier3TxJurorAccept(payload: unknown, base?: string, headers?: HeadersInit): Promise<any> {
    return apiPost("/v1/poh/tier3/tx/juror-accept", payload, base, headers);
  },

  pohTier3TxJurorDecline(payload: unknown, base?: string, headers?: HeadersInit): Promise<any> {
    return apiPost("/v1/poh/tier3/tx/juror-decline", payload, base, headers);
  },

  pohTier3TxAttendance(payload: unknown, base?: string, headers?: HeadersInit): Promise<any> {
    return apiPost("/v1/poh/tier3/tx/attendance", payload, base, headers);
  },

  pohTier3TxVerdict(payload: unknown, base?: string, headers?: HeadersInit): Promise<any> {
    return apiPost("/v1/poh/tier3/tx/verdict", payload, base, headers);
  },

  pohTier2VideoUpload(file: File, base?: string, headers?: HeadersInit): Promise<any> {
    return uploadFile('/v1/media/upload', file, base, headers);
  },

  mediaUpload(file: File, base?: string, headers?: HeadersInit): Promise<any> {
    return uploadFile("/v1/media/upload", file, base, headers);
  },

  mediaStatus(cid: string, base?: string, headers?: HeadersInit): Promise<any> {
    return apiGet(`/v1/media/status/${encodeURIComponent(cid)}`, base, headers);
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
    join(payload: unknown, base?: string, headers?: HeadersInit) {
      return apiPost("/v1/groups/join", payload, base, headers);
    },
    leave(payload: unknown, base?: string, headers?: HeadersInit) {
      return apiPost("/v1/groups/leave", payload, base, headers);
    },
  },
};
