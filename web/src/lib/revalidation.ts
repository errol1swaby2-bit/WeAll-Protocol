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
