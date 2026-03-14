// src/api/weall.ts
// WeAll Web API client
//
// Stable UI-facing interface used throughout the frontend:
//   - export const weall
//   - export const api (alias)
//   - getApiBaseUrl / setApiBaseUrl
//   - stripTrailingSlashes
//   - apiGet (used by lib/chain.ts)
//   - getAccount() (returns current account from session storage)
//
// This version preserves the richer project-specific client from the latest
// codebase while also keeping a few compatibility helpers from the onboarding
// draft so other updated files do not break.

export type Json = any;
export type HttpMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
export type PohTier = 0 | 1 | 2 | 3;

export interface ApiStatus {
  ok?: boolean;
  status?: string;
  network?: string;
  mode?: string;
  version?: string;
  [key: string]: unknown;
}

export interface ApiHealth {
  ok?: boolean;
  status?: string;
  [key: string]: unknown;
}

export interface AccountRecord {
  id?: string;
  handle?: string;
  username?: string;
  display_name?: string;
  pubkey?: string;
  poh_tier?: PohTier;
  reputation?: number;
  banned?: boolean;
  restricted?: boolean;
  balance?: string | number;
  flags?: string[];
  state?: Record<string, unknown>;
  [key: string]: unknown;
}

export interface SubmitTxRequest<TPayload = Record<string, unknown>> {
  tx_type: string;
  payload: TPayload;
  pubkey?: string;
  signer?: string;
  signature?: string;
  sig?: string;
  nonce?: string | number;
  timestamp_ms?: number;
  parent?: string | null;
  chain_id?: string;
}

export interface SubmitTxResponse {
  ok?: boolean;
  tx_id?: string;
  accepted?: boolean;
  error?: string | { code?: string; message?: string; [key: string]: unknown };
  [key: string]: unknown;
}

export interface EmailVerificationRequest {
  account_id?: string;
  handle?: string;
  account?: string;
  email?: string;
  pubkey?: string;
  [key: string]: unknown;
}

export interface EmailVerificationConfirmRequest {
  token?: string;
  code?: string;
  account_id?: string;
  handle?: string;
  account?: string;
  pubkey?: string;
  [key: string]: unknown;
}

export interface MediaUploadResponse {
  ok?: boolean;
  cid?: string;
  upload_ref?: string;
  ref?: string;
  path?: string;
  key?: string;
  content_type?: string;
  size_bytes?: number;
  filename?: string;
  [key: string]: unknown;
}

export interface DeclareMediaRequest {
  cid: string;
  mime_type?: string;
  mime?: string;
  filename?: string;
  name?: string;
  size_bytes?: number;
  bytes?: number;
  sha256?: string;
  pubkey?: string;
  signature?: string;
  [key: string]: unknown;
}

export interface DeclaredMediaRecord {
  ok?: boolean;
  media_id?: string;
  cid?: string;
  filename?: string;
  mime_type?: string;
  size_bytes?: number;
  [key: string]: unknown;
}

export interface FeedItem {
  id?: string;
  post_id?: string;
  author_handle?: string;
  body?: string;
  created_at?: string;
  media?: unknown[];
  [key: string]: unknown;
}

export interface FeedResponse {
  items?: FeedItem[];
  next_cursor?: string | null;
  [key: string]: unknown;
}

const LS_API_BASE = "weall_api_base";
const DEFAULT_API_BASE =
  (typeof import.meta !== "undefined" &&
    (import.meta as ImportMeta).env &&
    (import.meta as ImportMeta).env.VITE_WEALL_API_BASE) ||
  "";

export function stripTrailingSlashes(s: string): string {
  return (s || "").replace(/\/+$/, "");
}

export function getApiBaseUrl(): string {
  try {
    const v = (globalThis as any)?.localStorage?.getItem(LS_API_BASE) ?? "";
    const out = stripTrailingSlashes(v);
    return out || stripTrailingSlashes(DEFAULT_API_BASE);
  } catch {
    return stripTrailingSlashes(DEFAULT_API_BASE);
  }
}

export function setApiBaseUrl(base: string): void {
  try {
    (globalThis as any)?.localStorage?.setItem(LS_API_BASE, stripTrailingSlashes(base || ""));
  } catch {
    // ignore
  }
}
const DEFAULT_EMAIL_ORACLE_BASE =
  (typeof import.meta !== "undefined" &&
    (import.meta as ImportMeta).env &&
    (import.meta as ImportMeta).env.VITE_WEALL_EMAIL_ORACLE_BASE) ||
  "";

export function getEmailOracleBaseUrl(): string {
  return stripTrailingSlashes(DEFAULT_EMAIL_ORACLE_BASE);
}

function resolveEmailOracleBase(base?: string): string {
  return stripTrailingSlashes(base ?? getEmailOracleBaseUrl());
}


function resolveBase(base?: string): string {
  return stripTrailingSlashes(base ?? getApiBaseUrl());
}

async function parseJson(res: Response): Promise<any> {
  const txt = await res.text();
  if (!txt) return null;
  try {
    return JSON.parse(txt);
  } catch {
    return { ok: false, error: { code: "non_json", message: txt } };
  }
}

export async function apiGet(path: string, base?: string, headers?: Record<string, string>) {
  const b = resolveBase(base);
  const url = `${b}${path}`;
  const res = await fetch(url, {
    method: "GET",
    headers: {
      Accept: "application/json",
      ...(headers || {}),
    },
  });
  const data = await parseJson(res);
  return { http_ok: res.ok, status: res.status, data };
}

async function apiRequestRaw(
  method: HttpMethod,
  path: string,
  body?: any,
  base?: string,
  headers?: Record<string, string>,
) {
  const b = resolveBase(base);
  const url = `${b}${path}`;
  const res = await fetch(url, {
    method,
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
      ...(headers || {}),
    },
    body: body === undefined ? undefined : JSON.stringify(body ?? {}),
  });
  const data = await parseJson(res);
  return { http_ok: res.ok, status: res.status, data };
}

async function apiPostRaw(path: string, body: any, base?: string, headers?: Record<string, string>) {
  return apiRequestRaw("POST", path, body, base, headers);
}

async function apiPostMultipart(path: string, form: FormData, base?: string, headers?: Record<string, string>) {
  const b = resolveBase(base);
  const url = `${b}${path}`;
  const res = await fetch(url, {
    method: "POST",
    headers: {
      Accept: "application/json",
      ...(headers || {}),
    },
    body: form,
  });
  const data = await parseJson(res);
  return { http_ok: res.ok, status: res.status, data };
}

async function apiPutRaw(path: string, body: any, base?: string, headers?: Record<string, string>) {
  return apiRequestRaw("PUT", path, body, base, headers);
}

async function tryPostPaths(
  paths: string[],
  body: any,
  base?: string,
  headers?: Record<string, string>,
): Promise<any> {
  let last: any = null;
  for (const path of paths) {
    const res = await apiPostRaw(path, body, base, headers);
    last = res.data;
    if (res.http_ok) return res.data;

    const code = res.status;
    if (code !== 404 && code !== 405) return res.data;
  }
  return last;
}

function toFeedParamsQuery(params: {
  limit?: number;
  cursor?: string | null;
  scope?: string;
  group_id?: string;
  visibility?: string;
  tags?: string | string[];
  author?: string;
} = {}): string {
  const q = new URLSearchParams();
  if (params.limit != null) q.set("limit", String(params.limit));
  if (params.cursor) q.set("cursor", params.cursor);
  if (params.scope) q.set("scope", params.scope);
  if (params.group_id) q.set("group_id", params.group_id);
  if (params.visibility) q.set("visibility", params.visibility);
  if (params.author) q.set("author", params.author);
  if (params.tags) {
    const t = Array.isArray(params.tags) ? params.tags.join(",") : params.tags;
    if (t) q.set("tags", t);
  }
  return q.toString();
}

export const weall = {
  async get(path: string, base?: string, headers?: Record<string, string>) {
    return (await apiGet(path, base, headers)).data;
  },

  async post(path: string, body: any, base?: string, headers?: Record<string, string>) {
    return (await apiPostRaw(path, body, base, headers)).data;
  },

  async put(path: string, body: any, base?: string, headers?: Record<string, string>) {
    return (await apiPutRaw(path, body, base, headers)).data;
  },

  // node
  async status(base?: string): Promise<ApiStatus> {
    return (await apiGet("/v1/status", base)).data;
  },

  async getStatus(base?: string): Promise<ApiStatus> {
    return await this.status(base);
  },

  async health(base?: string): Promise<ApiHealth> {
    return (await apiGet("/v1/health", base)).data;
  },

  async getHealth(base?: string): Promise<ApiHealth> {
    return await this.health(base);
  },

  async readyz(base?: string) {
    return (await apiGet("/v1/readyz", base)).data;
  },

  async snapshot(base?: string) {
    return (await apiGet("/v1/state/snapshot", base)).data;
  },

  async whoami(_base?: string, _headers?: Record<string, string>) {
    return {
      ok: false,
      error: {
        code: "not_supported",
        message: "No /v1/whoami endpoint. Use /v1/accounts/{account}.",
      },
    };
  },

  // accounts
  async account(account: string, base?: string): Promise<AccountRecord> {
    const enc = encodeURIComponent(account);
    return (await apiGet(`/v1/accounts/${enc}`, base)).data;
  },

  async getAccount(handleOrId: string, base?: string): Promise<AccountRecord> {
    return await this.account(handleOrId, base);
  },

  async getAccountByPubkey(_pubkey: string, _base?: string): Promise<AccountRecord | null> {
    // No canonical public backend route exists for pubkey lookup in the
    // current API surface. Keep this method for compatibility, but fail
    // closed instead of referencing a non-existent endpoint.
    return null;
  },

  async accountNonce(account: string, base?: string) {
    const a: any = await this.account(account, base);
    const nonce = a?.state?.nonce ?? 0;
    return { ok: true, account, nonce, next_nonce: nonce + 1 };
  },

  async accountRegistered(account: string, base?: string, headers?: Record<string, string>) {
    const enc = encodeURIComponent(account);
    return (await apiGet(`/v1/accounts/${enc}/registered`, base, headers)).data;
  },

  // content / feed
  async feed(
    params: {
      limit?: number;
      cursor?: string | null;
      scope?: string;
      group_id?: string;
      visibility?: string;
      tags?: string | string[];
      author?: string;
    } = {},
    base?: string,
    headers?: Record<string, string>,
  ): Promise<FeedResponse> {
    const qs = toFeedParamsQuery(params);
    return (await apiGet(`/v1/feed${qs ? `?${qs}` : ""}`, base, headers)).data;
  },

  async getGlobalFeed(base?: string, headers?: Record<string, string>): Promise<FeedResponse> {
    return await this.feed({}, base, headers);
  },

  async accountFeed(
    account: string,
    params: { limit?: number; cursor?: string | null; visibility?: string } = {},
    base?: string,
    headers?: Record<string, string>,
  ) {
    const q = new URLSearchParams();
    if (params.limit != null) q.set("limit", String(params.limit));
    if (params.cursor) q.set("cursor", params.cursor);
    if (params.visibility) q.set("visibility", params.visibility);
    const enc = encodeURIComponent(account);
    return (await apiGet(`/v1/accounts/${enc}/feed?${q.toString()}`, base, headers)).data;
  },

  async getFeedByAccount(
    account: string,
    base?: string,
    headers?: Record<string, string>,
  ): Promise<FeedResponse> {
    return await this.accountFeed(account, {}, base, headers);
  },

  async content(content_id: string, base?: string) {
    const enc = encodeURIComponent(content_id);
    return (await apiGet(`/v1/content/${enc}`, base)).data;
  },

  async thread(post_id: string, base?: string) {
    const enc = encodeURIComponent(post_id);
    return (await apiGet(`/v1/thread/${enc}`, base)).data;
  },

  // groups
  async group(group_id: string, base?: string) {
    const enc = encodeURIComponent(group_id);
    return (await apiGet(`/v1/groups/${enc}`, base)).data;
  },

  async groupMembers(group_id: string, base?: string) {
    const enc = encodeURIComponent(group_id);
    return (await apiGet(`/v1/groups/${enc}/members`, base)).data;
  },

  groups: {
    async list(params: { limit?: number; cursor?: string | null } = {}, base?: string) {
      const q = new URLSearchParams();
      if (params.limit != null) q.set("limit", String(params.limit));
      if (params.cursor) q.set("cursor", params.cursor);
      return (await apiGet(`/v1/groups?${q.toString()}`, base)).data;
    },
    async get(group_id: string, base?: string) {
      const enc = encodeURIComponent(group_id);
      return (await apiGet(`/v1/groups/${enc}`, base)).data;
    },
    async members(group_id: string, base?: string) {
      const enc = encodeURIComponent(group_id);
      return (await apiGet(`/v1/groups/${enc}/members`, base)).data;
    },
    async create(_body: any, _base?: string, _headers?: Record<string, string>) {
      return {
        ok: false,
        error: {
          code: "not_supported",
          message: "Group creation is not exposed as a REST endpoint. Submit GROUP_CREATE via /v1/tx/submit.",
        },
      };
    },
    async join(body: any, base?: string, headers?: Record<string, string>) {
      return (await apiPostRaw("/v1/groups/join", body, base, headers)).data;
    },
    async leave(body: any, base?: string, headers?: Record<string, string>) {
      return (await apiPostRaw("/v1/groups/leave", body, base, headers)).data;
    },
  },

  async groupContent(
    group_id: string,
    params: { limit?: number } = {},
    base?: string,
    headers?: Record<string, string>,
  ) {
    const q = new URLSearchParams();
    if (params.limit != null) q.set("limit", String(params.limit));
    const enc = encodeURIComponent(group_id);
    return (await apiGet(`/v1/groups/${enc}/content?${q.toString()}`, base, headers)).data;
  },

  async groupFeed(
    group_id: string,
    params: {
      limit?: number;
      cursor?: string | null;
      visibility?: string;
      tags?: string | string[];
      author?: string;
    } = {},
    base?: string,
    headers?: Record<string, string>,
  ) {
    const q = new URLSearchParams();
    if (params.limit != null) q.set("limit", String(params.limit));
    if (params.cursor) q.set("cursor", params.cursor);
    if (params.visibility) q.set("visibility", params.visibility);
    if (params.author) q.set("author", params.author);
    if (params.tags) {
      const t = Array.isArray(params.tags) ? params.tags.join(",") : params.tags;
      if (t) q.set("tags", t);
    }
    const enc = encodeURIComponent(group_id);
    return (await apiGet(`/v1/groups/${enc}/feed?${q.toString()}`, base, headers)).data;
  },

  // governance
  async proposals(params: { limit?: number; cursor?: string } = {}, base?: string) {
    const q = new URLSearchParams();
    if (params.limit != null) q.set("limit", String(params.limit));
    if (params.cursor) q.set("cursor", params.cursor);
    return (await apiGet(`/v1/gov/proposals?${q.toString()}`, base)).data;
  },

  async proposal(proposal_id: string, base?: string) {
    const enc = encodeURIComponent(proposal_id);
    return (await apiGet(`/v1/gov/proposals/${enc}`, base)).data;
  },

  async proposalVotes(proposal_id: string, base?: string, headers?: Record<string, string>) {
    const enc = encodeURIComponent(proposal_id);
    return (await apiGet(`/v1/gov/proposals/${enc}/votes`, base, headers)).data;
  },

  // tx
  async txSubmit(envelope: any, base?: string, headers?: Record<string, string>): Promise<SubmitTxResponse> {
    return (await apiPostRaw("/v1/tx/submit", envelope, base, headers)).data;
  },

  async submitTx<TPayload = Record<string, unknown>>(
    envelope: SubmitTxRequest<TPayload>,
    base?: string,
    headers?: Record<string, string>,
  ): Promise<SubmitTxResponse> {
    return await this.txSubmit(envelope, base, headers);
  },

  async txStatus(tx_id: string, base?: string) {
    const enc = encodeURIComponent(tx_id);
    return (await apiGet(`/v1/tx/status/${enc}`, base)).data;
  },

  // media
  async mediaUpload(file: File, base?: string, headers?: Record<string, string>): Promise<MediaUploadResponse> {
    const form = new FormData();
    form.append("file", file);
    return (await apiPostMultipart("/v1/media/upload", form, base, headers)).data;
  },

  async uploadMedia(file: File, base?: string, headers?: Record<string, string>): Promise<MediaUploadResponse> {
    return await this.mediaUpload(file, base, headers);
  },

  async mediaStatus(cid: string, base?: string, headers?: Record<string, string>) {
    const enc = encodeURIComponent(cid);
    return (await apiGet(`/v1/media/status/${enc}`, base, headers)).data;
  },

  mediaGatewayUrl(cid: string, base?: string) {
    const b = resolveBase(base);
    const enc = encodeURIComponent(cid);
    return `${b}/v1/media/gateway/${enc}`;
  },

  async declareMedia(
    _payload: DeclareMediaRequest,
    _base?: string,
    _headers?: Record<string, string>,
  ): Promise<DeclaredMediaRecord> {
    throw new Error(
      "media_declare_not_supported_via_rest: submit CONTENT_MEDIA_DECLARE via /v1/tx/submit",
    );
  },

  // social / chain / network / storage
  async socialMe(base?: string, headers?: Record<string, string>) {
    return (await apiGet("/v1/social/me", base, headers)).data;
  },

  async socialFollowing(account: string, base?: string, headers?: Record<string, string>) {
    const enc = encodeURIComponent(account);
    return (await apiGet(`/v1/social/${enc}/following`, base, headers)).data;
  },

  async chainHead(base?: string, headers?: Record<string, string>) {
    return (await apiGet("/v1/chain/head", base, headers)).data;
  },

  async statusMempool(base?: string, headers?: Record<string, string>) {
    return (await apiGet("/v1/status/mempool", base, headers)).data;
  },

  async statusAttestations(base?: string, headers?: Record<string, string>) {
    return (await apiGet("/v1/status/attestations", base, headers)).data;
  },

  async netSelf(base?: string, headers?: Record<string, string>) {
    return (await apiGet("/v1/net/self", base, headers)).data;
  },

  async netPeers(base?: string, headers?: Record<string, string>) {
    return (await apiGet("/v1/net/peers", base, headers)).data;
  },

  async storageIpfsOps(base?: string, headers?: Record<string, string>) {
    return (await apiGet("/v1/storage/ipfs/ops", base, headers)).data;
  },

  async nodes(base?: string, headers?: Record<string, string>) {
    return (await apiGet("/v1/nodes", base, headers)).data;
  },

  async nodeSeeds(base?: string, headers?: Record<string, string>) {
    return (await apiGet("/v1/nodes/seeds", base, headers)).data;
  },

  async nodeKnown(base?: string, headers?: Record<string, string>) {
    return (await apiGet("/v1/nodes/known", base, headers)).data;
  },

  async nodeCandidates() {
    try {
      const raw = (globalThis as any)?.localStorage?.getItem("weall.nodeCandidates");
      if (!raw) return [];
      const parsed = JSON.parse(raw);
      return Array.isArray(parsed) ? parsed : [];
    } catch {
      return [];
    }
  },

  async nodeSelection() {
    try {
      const raw = (globalThis as any)?.localStorage?.getItem("weall.nodeSelection");
      if (!raw) return null;
      return JSON.parse(raw);
    } catch {
      return null;
    }
  },

  async canon(base?: string) {
    const snap: any = await this.snapshot(base);
    const tx_index_hash =
      snap?.tx_index_hash ??
      snap?.state?.tx_index_hash ??
      snap?.snapshot?.tx_index_hash ??
      null;
    const chain_id =
      snap?.chain_id ??
      snap?.state?.chain_id ??
      snap?.snapshot?.chain_id ??
      null;
    return { ok: true, chain_id, tx_index_hash, snapshot: snap };
  },

  // PoH convenience
  async pohState(account: string, base?: string, _headers?: Record<string, string>) {
    const a: any = await this.account(account, base);
    const state = a?.state ?? null;
    const poh_tier = state?.poh_tier ?? state?.pohTier ?? state?.poh?.tier ?? state?.poh?.poh_tier ?? 0;
    const reputation = state?.reputation ?? state?.rep ?? 0;
    return { ok: true, account, poh_tier, reputation, state, account_view: a };
  },

  async pohEmailBegin(body: any, base?: string, headers?: Record<string, string>) {
    return (await apiPostRaw("/v1/poh/email/begin", body, base, headers)).data;
  },

  async pohEmailStart(body: any, base?: string, headers?: Record<string, string>) {
    return await this.pohEmailBegin(body, base, headers);
  },

  async requestEmailVerification(
    body: EmailVerificationRequest,
    base?: string,
    headers?: Record<string, string>,
  ) {
    return await this.pohEmailBegin(body, base, headers);
  },

  async pohEmailConfirm(body: any, base?: string, headers?: Record<string, string>) {
    return (await apiPostRaw("/v1/poh/email/confirm", body, base, headers)).data;
  },
  async emailOracleStart(body: any, oracleBase?: string) {
    return (await apiPostRaw("/start", body, resolveEmailOracleBase(oracleBase))).data;
  },

  async emailOracleVerify(body: any, oracleBase?: string) {
    return (await apiPostRaw("/verify", body, resolveEmailOracleBase(oracleBase))).data;
  },

  async pohEmailReceiptTxSubmit(body: any, base?: string, headers?: Record<string, string>) {
    return (await apiPostRaw("/v1/poh/email/tx/receipt-submit", body, base, headers)).data;
  },


  async verifyEmail(
    body: EmailVerificationConfirmRequest,
    base?: string,
    headers?: Record<string, string>,
  ) {
    return await this.pohEmailConfirm(body, base, headers);
  },

  async pohTier2VideoUpload(file: File, base?: string, headers?: Record<string, string>) {
    const form = new FormData();
    form.append("file", file);
    return (await apiPostMultipart("/v1/poh/tier2/video/upload", form, base, headers)).data;
  },

  async pohTier2RequestTx(body: any, base?: string, headers?: Record<string, string>) {
    return (await apiPostRaw("/v1/poh/tier2/tx/request", body, base, headers)).data;
  },

  async pohTier2TxRequest(body: any, base?: string, headers?: Record<string, string>) {
    return await this.pohTier2RequestTx(body, base, headers);
  },

  async pohTier2MyCases(account: string, base?: string, headers?: Record<string, string>) {
    const enc = encodeURIComponent(account);
    return (await apiGet(`/v1/poh/tier2/my-cases?account=${enc}`, base, headers)).data;
  },

  async pohTier2JurorCases(juror: string, base?: string, headers?: Record<string, string>) {
    const enc = encodeURIComponent(juror);
    return (await apiGet(`/v1/poh/tier2/juror-cases?juror=${enc}`, base, headers)).data;
  },

  async pohTier2Case(case_id: string, base?: string, headers?: Record<string, string>) {
    const enc = encodeURIComponent(case_id);
    return (await apiGet(`/v1/poh/tier2/case/${enc}`, base, headers)).data;
  },

  async pohTier2TxAccept(body: any, base?: string, headers?: Record<string, string>) {
    return (await apiPostRaw("/v1/poh/tier2/tx/juror-accept", body, base, headers)).data;
  },

  async pohTier2TxDecline(body: any, base?: string, headers?: Record<string, string>) {
    return (await apiPostRaw("/v1/poh/tier2/tx/juror-decline", body, base, headers)).data;
  },

  async pohTier2TxVote(body: any, base?: string, headers?: Record<string, string>) {
    return (await apiPostRaw("/v1/poh/tier2/tx/review", body, base, headers)).data;
  },

  async pohTier2TxJurorAccept(body: any, base?: string, headers?: Record<string, string>) {
    return await this.pohTier2TxAccept(body, base, headers);
  },

  async pohTier2TxJurorDecline(body: any, base?: string, headers?: Record<string, string>) {
    return await this.pohTier2TxDecline(body, base, headers);
  },

  async pohTier2TxReview(body: any, base?: string, headers?: Record<string, string>) {
    return await this.pohTier2TxVote(body, base, headers);
  },

  async pohTier3RequestTx(body: any, base?: string, headers?: Record<string, string>) {
    return (await apiPostRaw("/v1/poh/tier3/tx/request", body, base, headers)).data;
  },

  async pohTier3TxRequest(body: any, base?: string, headers?: Record<string, string>) {
    return await this.pohTier3RequestTx(body, base, headers);
  },

  async pohTier3Assigned(juror: string, base?: string, headers?: Record<string, string>) {
    const enc = encodeURIComponent(juror);
    return (await apiGet(`/v1/poh/tier3/assigned?juror=${enc}`, base, headers)).data;
  },

  async pohTier3Case(case_id: string, base?: string, headers?: Record<string, string>) {
    const enc = encodeURIComponent(case_id);
    return (await apiGet(`/v1/poh/tier3/case/${enc}`, base, headers)).data;
  },

  async pohTier3Sessions(base?: string, headers?: Record<string, string>) {
    return (await apiGet("/v1/poh/tier3/sessions", base, headers)).data;
  },

  async pohTier3Session(session_id: string, base?: string, headers?: Record<string, string>) {
    const enc = encodeURIComponent(session_id);
    return (await apiGet(`/v1/poh/tier3/session/${enc}`, base, headers)).data;
  },

  async pohTier3SessionParticipants(session_id: string, base?: string, headers?: Record<string, string>) {
    const enc = encodeURIComponent(session_id);
    return (await apiGet(`/v1/poh/tier3/session/${enc}/participants`, base, headers)).data;
  },

  async pohTier3TxAccept(body: any, base?: string, headers?: Record<string, string>) {
    return (await apiPostRaw("/v1/poh/tier3/tx/juror-accept", body, base, headers)).data;
  },

  async pohTier3TxDecline(body: any, base?: string, headers?: Record<string, string>) {
    return (await apiPostRaw("/v1/poh/tier3/tx/juror-decline", body, base, headers)).data;
  },

  async pohTier3TxJurorAccept(body: any, base?: string, headers?: Record<string, string>) {
    return await this.pohTier3TxAccept(body, base, headers);
  },

  async pohTier3TxJurorDecline(body: any, base?: string, headers?: Record<string, string>) {
    return await this.pohTier3TxDecline(body, base, headers);
  },

  async pohTier3TxAttendance(body: any, base?: string, headers?: Record<string, string>) {
    return (await apiPostRaw("/v1/poh/tier3/tx/attendance", body, base, headers)).data;
  },

  async pohTier3TxVerdict(body: any, base?: string, headers?: Record<string, string>) {
    return (await apiPostRaw("/v1/poh/tier3/tx/verdict", body, base, headers)).data;
  },
};

export const api = weall;

export function getAccount(): string | null {
  try {
    const v = (globalThis as any)?.localStorage?.getItem("weall_session_v1");
    if (!v) return null;
    const obj = JSON.parse(v);
    return obj?.account ?? null;
  } catch {
    return null;
  }
}
