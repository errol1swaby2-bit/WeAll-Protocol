export type ReconcilePhase = "confirmed" | "submitted" | "failed" | "unknown";

export type ReconcileResult = {
  phase: ReconcilePhase;
  detail?: string;
  txId?: string;
};

export type ReconcileFn = () => Promise<ReconcileResult | null>;

export type RefreshScope = "account" | "session" | "node" | "pending_work" | "route";

export type GlobalRefreshRequest = {
  reason?: string;
  scopes: RefreshScope[];
  at: number;
};

const GLOBAL_REFRESH_EVENT = "weall:global-refresh";

export const ACCOUNT_REFRESH_INTERVAL_MS = 15_000;
export const RAIL_REFRESH_INTERVAL_MS = 20_000;

export function refreshTouches(request: GlobalRefreshRequest, scopes: RefreshScope[]): boolean {
  const wanted = new Set(scopes);
  return request.scopes.some((scope) => wanted.has(scope));
}

export function confirmed(detail: string, txId?: string): ReconcileResult {
  return { phase: "confirmed", detail, txId };
}

export function submitted(detail: string, txId?: string): ReconcileResult {
  return { phase: "submitted", detail, txId };
}

export function failed(detail: string, txId?: string): ReconcileResult {
  return { phase: "failed", detail, txId };
}

export function unknown(detail: string, txId?: string): ReconcileResult {
  return { phase: "unknown", detail, txId };
}

export async function firstReconcile(...fns: Array<ReconcileFn | null | undefined>): Promise<ReconcileResult | null> {
  for (const fn of fns) {
    if (!fn) continue;
    try {
      const res = await fn();
      if (res) return res;
    } catch {
      // keep scanning other authoritative surfaces
    }
  }
  return null;
}

export function requestGlobalRefresh(request?: Partial<GlobalRefreshRequest>): void {
  if (typeof window === "undefined") return;
  const scopes: RefreshScope[] = Array.isArray(request?.scopes) && request?.scopes.length
    ? Array.from(new Set(request.scopes)) as RefreshScope[]
    : ["account", "session", "pending_work", "route"];
  const detail: GlobalRefreshRequest = {
    reason: String(request?.reason || "manual"),
    scopes,
    at: Date.now(),
  };
  window.dispatchEvent(new CustomEvent<GlobalRefreshRequest>(GLOBAL_REFRESH_EVENT, { detail }));
}

export function subscribeGlobalRefresh(listener: (request: GlobalRefreshRequest) => void): () => void {
  if (typeof window === "undefined") return () => {};
  const handler = (ev: Event) => {
    const custom = ev as CustomEvent<GlobalRefreshRequest>;
    listener(custom.detail || { reason: "unknown", scopes: ["account", "session", "pending_work", "route"], at: Date.now() });
  };
  window.addEventListener(GLOBAL_REFRESH_EVENT, handler as EventListener);
  return () => window.removeEventListener(GLOBAL_REFRESH_EVENT, handler as EventListener);
}

export async function refreshMutationSlices(
  ...fns: Array<(() => Promise<unknown>) | null | undefined>
): Promise<void> {
  for (const fn of fns) {
    if (!fn) continue;
    await fn();
  }
  requestGlobalRefresh({
    reason: "mutation-reconciled",
    scopes: ["account", "session", "node", "pending_work", "route"],
  });
}

/**
 * Bounded retry for idempotent canonical GETs only. A caller still has to
 * validate the returned record; a failed read never implies empty state.
 * Never pass a signing, submission, upload or other mutation callback here.
 */
export async function retryTransientCanonicalRead<T>(
  read: () => Promise<T>,
  isCurrent: () => boolean = () => true,
  pause: (milliseconds: number) => Promise<void> = (milliseconds) =>
    new Promise<void>((resolve) => setTimeout(resolve, milliseconds)),
): Promise<T> {
  const delays = [500, 1500];
  for (let attempt = 0; ; attempt += 1) {
    try {
      return await read();
    } catch (reason: unknown) {
      const status = reason && typeof reason === "object" && "status" in reason
        ? Number(reason.status) : 0;
      if (![429, 502, 503, 504].includes(status) || attempt >= delays.length || !isCurrent()) {
        throw reason;
      }
      await pause(delays[attempt]);
      if (!isCurrent()) throw reason;
    }
  }
}
