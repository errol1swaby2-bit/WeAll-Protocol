export type MutationEntityType = "proposal" | "dispute" | "group" | "content" | "account" | "session" | "unknown";

export type MutationSignalStatus = "recorded" | "confirmed" | "failed" | "submitted";

export type MutationSignal = {
  id: string;
  entityType: MutationEntityType;
  entityId?: string;
  txType?: string;
  txId?: string;
  title?: string;
  routeHint?: string;
  status: MutationSignalStatus;
  detail?: string;
  account?: string;
  emittedAt: number;
};

const STORAGE_KEY = "weall_mutation_signal_v1";
const EVENT_NAME = "weall:mutation-signal";

function normalizeString(value: unknown): string {
  return String(value || "").trim();
}

function safeEmitLocal(signal: MutationSignal): void {
  try {
    window.dispatchEvent(new CustomEvent(EVENT_NAME, { detail: signal }));
  } catch {
    // ignore
  }
}

export function emitMutationSignal(partial: Omit<MutationSignal, "id" | "emittedAt">): MutationSignal {
  const signal: MutationSignal = {
    id: `mutation_${Date.now()}_${Math.random().toString(36).slice(2, 10)}`,
    entityType: partial.entityType,
    entityId: normalizeString(partial.entityId) || undefined,
    txType: normalizeString(partial.txType) || undefined,
    txId: normalizeString(partial.txId) || undefined,
    title: normalizeString(partial.title) || undefined,
    routeHint: normalizeString(partial.routeHint) || undefined,
    status: partial.status,
    detail: normalizeString(partial.detail) || undefined,
    account: normalizeString(partial.account) || undefined,
    emittedAt: Date.now(),
  };

  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(signal));
  } catch {
    // ignore storage issues
  }
  safeEmitLocal(signal);
  return signal;
}

function parseSignal(raw: unknown): MutationSignal | null {
  if (!raw || typeof raw !== "object") return null;
  const obj = raw as Record<string, unknown>;
  const entityType = normalizeString(obj.entityType) as MutationEntityType;
  const status = normalizeString(obj.status) as MutationSignalStatus;
  if (!entityType || !status) return null;
  return {
    id: normalizeString(obj.id) || `mutation_${Date.now()}`,
    entityType,
    entityId: normalizeString(obj.entityId) || undefined,
    txType: normalizeString(obj.txType) || undefined,
    txId: normalizeString(obj.txId) || undefined,
    title: normalizeString(obj.title) || undefined,
    routeHint: normalizeString(obj.routeHint) || undefined,
    status,
    detail: normalizeString(obj.detail) || undefined,
    account: normalizeString(obj.account) || undefined,
    emittedAt: Number(obj.emittedAt || Date.now()),
  };
}

export function subscribeMutationSignals(listener: (signal: MutationSignal) => void): () => void {
  const onCustom = (event: Event) => {
    const detail = (event as CustomEvent<MutationSignal>).detail;
    const parsed = parseSignal(detail);
    if (parsed) listener(parsed);
  };

  const onStorage = (event: StorageEvent) => {
    if (event.key !== STORAGE_KEY || !event.newValue) return;
    try {
      const parsed = parseSignal(JSON.parse(event.newValue));
      if (parsed) listener(parsed);
    } catch {
      // ignore malformed payloads
    }
  };

  window.addEventListener(EVENT_NAME, onCustom as EventListener);
  window.addEventListener("storage", onStorage);
  return () => {
    window.removeEventListener(EVENT_NAME, onCustom as EventListener);
    window.removeEventListener("storage", onStorage);
  };
}
