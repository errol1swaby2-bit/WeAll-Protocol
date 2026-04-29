import React, { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";

import { getApiBaseUrl, weall } from "../api/weall";
import { ensureBackendSession, getSession } from "../auth/session";
import { normalizeTxStatus } from "../lib/status";
import { emitMutationSignal, type MutationEntityType } from "../lib/mutationSignals";
import { inferFeedbackFromUnknown, normalizeStoredTxStatus, type FrontendFeedback, type TxLifecycleStatus } from "../lib/txFeedback";
import TxStatusToast, { type TxToastItem } from "./TxStatusToast";

type ReconcilePhase = "confirmed" | "submitted" | "failed" | "unknown";

type MutationDescriptor = {
  entityType: MutationEntityType;
  entityId?: string;
  account?: string;
  routeHint?: string;
  txType?: string;
};

type TxLifecycleArgs<T> = {
  title: string;
  pendingKey?: string;
  pendingMessage?: string;
  successMessage?: string | ((result: T) => string);
  errorMessage?: string | ((error: unknown) => string);
  task: () => Promise<T>;
  getTxId?: (result: T) => string | undefined;
  finality?: {
    track?: boolean;
    txId?: string;
    base?: string;
    pollEveryMs?: number;
    timeoutMs?: number;
    reconcile?: () => Promise<{ phase: ReconcilePhase; detail?: string; txId?: string } | null>;
    mutation?: MutationDescriptor;
  };
};

type TxQueueContextValue = {
  items: TxToastItem[];
  dismiss: (id: string) => void;
  pushPending: (args: { title: string; message?: string }) => string;
  markSuccess: (id: string, args?: { message?: string; txId?: string }) => void;
  markError: (id: string, args?: { message?: string; txId?: string }) => void;
  runTx: <T>(args: TxLifecycleArgs<T>) => Promise<T>;
};

const TX_HISTORY_KEY = "weall_tx_activity_v3";
const TX_HISTORY_FALLBACK_KEYS = ["weall_tx_activity_v2", "weall_tx_activity_v1"];
const TX_HISTORY_LIMIT = 40;
const TxQueueContext = createContext<TxQueueContextValue | null>(null);

function uid(): string {
  return `tx_${Date.now()}_${Math.random().toString(36).slice(2, 10)}`;
}

function normalizeErrorMessage(error: unknown): string {
  return inferFeedbackFromUnknown(error, "Transaction failed.").message;
}

function extractTxIdCandidate(value: unknown, depth = 0, seen?: Set<unknown>): string | undefined {
  if (depth > 4 || value == null) return undefined;
  const visit = seen || new Set<unknown>();
  if (typeof value === "object") {
    if (visit.has(value)) return undefined;
    visit.add(value);
  }

  if (typeof value === "string") {
    const trimmed = value.trim();
    return trimmed || undefined;
  }

  if (Array.isArray(value)) {
    for (const item of value) {
      const nested = extractTxIdCandidate(item, depth + 1, visit);
      if (nested) return nested;
    }
    return undefined;
  }

  if (typeof value !== "object") return undefined;

  const record = value as Record<string, unknown>;
  const directKeys = ["tx_id", "txId", "existing_tx_id", "existingTxId"];
  for (const key of directKeys) {
    const nested = extractTxIdCandidate(record[key], depth + 1, visit);
    if (nested) return nested;
  }

  const nestedKeys = ["result", "submit", "payload", "data", "error", "detail", "details", "body", "response"];
  for (const key of nestedKeys) {
    const nested = extractTxIdCandidate(record[key], depth + 1, visit);
    if (nested) return nested;
  }

  return undefined;
}

function txIdFromUnknown(value: unknown): string | undefined {
  return extractTxIdCandidate(value, 0);
}

function txIdFromError(error: unknown): string | undefined {
  const payload: any = (error as any)?.body || (error as any)?.data || (error as any)?.payload || error;
  return txIdFromUnknown(payload) || txIdFromUnknown(error);
}

function shouldAttemptSessionRepair(error: unknown): boolean {
  const payload: any = (error as any)?.body || (error as any)?.data || (error as any)?.payload || error;
  const message = String(
    payload?.error?.message || payload?.message || payload?.detail?.message || (error as any)?.message || "",
  )
    .trim()
    .toLowerCase();
  const code = String(
    payload?.error?.code || payload?.code || payload?.detail?.code || payload?.details?.code || "",
  )
    .trim()
    .toLowerCase();
  const status = Number((error as any)?.status || payload?.status || payload?.error?.status || 0);
  return (
    code === "session_invalid" ||
    code === "pubkey_not_authorized" ||
    message === "session_invalid" ||
    message.includes("session invalid") ||
    message.includes("session expired") ||
    message.includes("pubkey is not an active key on this account") ||
    status === 401 ||
    status === 403
  );
}

function safeLoadHistory(): TxToastItem[] {
  try {
    const raw = localStorage.getItem(TX_HISTORY_KEY) || TX_HISTORY_FALLBACK_KEYS.map((key) => localStorage.getItem(key)).find(Boolean);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed
      .filter((item) => item && typeof item === "object")
      .map((item) => ({
        id: String((item as any).id || uid()),
        title: String((item as any).title || "Transaction"),
        status: normalizeStoredTxStatus((item as any).status),
        message: typeof (item as any).message === "string" ? (item as any).message : undefined,
        txId: typeof (item as any).txId === "string" ? (item as any).txId : undefined,
        createdAt: Number((item as any).createdAt || Date.now()),
        updatedAt: Number((item as any).updatedAt || Date.now()),
      }))
      .slice(0, TX_HISTORY_LIMIT);
  } catch {
    return [];
  }
}

function persistHistory(items: TxToastItem[]): void {
  try {
    localStorage.setItem(TX_HISTORY_KEY, JSON.stringify(items.slice(0, TX_HISTORY_LIMIT)));
  } catch {
    // ignore persistence failures
  }
}
function mutationFromArgs(mutation: MutationDescriptor | undefined, status: "recorded" | "confirmed" | "failed" | "submitted", args: { title: string; txId?: string; detail?: string }): void {
  if (!mutation) return;
  emitMutationSignal({
    entityType: mutation.entityType,
    entityId: mutation.entityId,
    account: mutation.account,
    routeHint: mutation.routeHint,
    txType: mutation.txType,
    txId: args.txId,
    title: args.title,
    detail: args.detail,
    status,
  });
}


export function TxQueueProvider({ children }: { children: React.ReactNode }): JSX.Element {
  const [items, setItems] = useState<TxToastItem[]>(() => safeLoadHistory().slice(0, 8));
  const itemsRef = useRef<TxToastItem[]>(items);
  const activePendingKeysRef = useRef<Map<string, string>>(new Map());

  useEffect(() => {
    itemsRef.current = items;
    persistHistory(items);
  }, [items]);

  const dismiss = useCallback((id: string) => {
    setItems((prev) => prev.filter((item) => item.id !== id));
  }, []);

  const updateItem = useCallback((id: string, status: TxLifecycleStatus, args?: { message?: string; txId?: string }) => {
    setItems((prev) =>
      prev.map((item) =>
        item.id === id
          ? {
              ...item,
              status,
              message: args?.message ?? item.message,
              txId: args?.txId ?? item.txId,
              updatedAt: Date.now(),
            }
          : item,
      ),
    );
  }, []);

  const pushPending = useCallback((args: { title: string; message?: string }): string => {
    const id = uid();
    const item: TxToastItem = {
      id,
      title: args.title,
      status: "validating",
      message: args.message,
      createdAt: Date.now(),
      updatedAt: Date.now(),
    };
    setItems((prev) => [item, ...prev].slice(0, 8));
    return id;
  }, []);

  const findItemById = useCallback((id: string): TxToastItem | null => {
    return itemsRef.current.find((item) => item.id === id) || null;
  }, []);

  const markSubmitting = useCallback((id: string, args?: { message?: string; txId?: string }) => {
    updateItem(id, "submitting", args);
  }, [updateItem]);

  const markRecorded = useCallback((id: string, args?: { message?: string; txId?: string }) => {
    updateItem(id, "recorded", args);
  }, [updateItem]);

  const markRefreshing = useCallback((id: string, args?: { message?: string; txId?: string }) => {
    updateItem(id, "refreshing", args);
  }, [updateItem]);

  const markSuccess = useCallback(
    (id: string, args?: { message?: string; txId?: string }) => {
      updateItem(id, "confirmed", args);
      window.setTimeout(() => dismiss(id), 5000);
    },
    [dismiss, updateItem],
  );

  const markError = useCallback((id: string, args?: { message?: string; txId?: string }) => {
    updateItem(id, "failed", args);
  }, [updateItem]);

  const applyReconciledPhase = useCallback(
    (id: string, txId: string, mutation: MutationDescriptor | undefined, title: string, reconciled: { phase: ReconcilePhase; detail?: string; txId?: string } | null): boolean => {
      if (!reconciled) return false;
      if (reconciled.phase === "confirmed") {
        const finalTxId = reconciled.txId || txId;
        const detail = reconciled.detail || "The affected surface has reconciled the recorded action.";
        markSuccess(id, {
          message: detail,
          txId: finalTxId,
        });
        mutationFromArgs(mutation, "confirmed", { title, txId: finalTxId, detail });
        return true;
      }
      if (reconciled.phase === "failed") {
        const finalTxId = reconciled.txId || txId;
        const detail = reconciled.detail || "The affected surface reports that the action failed.";
        markError(id, {
          message: detail,
          txId: finalTxId,
        });
        mutationFromArgs(mutation, "failed", { title, txId: finalTxId, detail });
        return true;
      }
      if (reconciled.phase === "submitted") {
        const finalTxId = reconciled.txId || txId;
        const detail = reconciled.detail || "The action is recorded. Refreshing the affected surface so it becomes visible.";
        markRefreshing(id, {
          message: detail,
          txId: finalTxId,
        });
        mutationFromArgs(mutation, "submitted", { title, txId: finalTxId, detail });
        return false;
      }
      const finalTxId = reconciled.txId || txId;
      const detail = reconciled.detail || "The action was recorded, but the affected surface has not confirmed visibility yet.";
      markRecorded(id, {
        message: detail,
        txId: finalTxId,
      });
      mutationFromArgs(mutation, "recorded", { title, txId: finalTxId, detail });
      return false;
    },
    [markError, markRecorded, markRefreshing, markSuccess],
  );

  const monitorFinality = useCallback(
    async (args: {
      id: string;
      txId: string;
      base?: string;
      pollEveryMs?: number;
      timeoutMs?: number;
      reconcile?: () => Promise<{ phase: ReconcilePhase; detail?: string; txId?: string } | null>;
      mutation?: MutationDescriptor;
      title: string;
    }) => {
      const base = args.base || getApiBaseUrl();
      const pollEveryMs = Math.max(250, Number(args.pollEveryMs ?? 1200));
      const timeoutMs = Math.max(2000, Number(args.timeoutMs ?? 12000));
      const lateReconcileWindowMs = Math.max(pollEveryMs * 2, 4000);
      const started = Date.now();
      let sawSubmittedReconcile = false;

      while (Date.now() - started < timeoutMs) {
        try {
          const raw = await weall.txStatus(args.txId, base);
          const normalized = normalizeTxStatus(raw, args.txId);
          if (normalized.phase === "confirmed") {
            markSuccess(args.id, { message: normalized.detail, txId: args.txId });
            mutationFromArgs(args.mutation, "confirmed", { title: args.title, txId: args.txId, detail: normalized.detail });
            return;
          }
          if (normalized.phase === "unknown") {
            if (args.reconcile) {
              const reconciled = await args.reconcile().catch(() => null);
              const terminal = applyReconciledPhase(args.id, args.txId, args.mutation, args.title, reconciled);
              if (terminal) return;
              if (reconciled?.phase === "submitted") {
                sawSubmittedReconcile = true;
              } else {
                const detail = `${normalized.detail} The action may already be recorded, but the visible surface has not caught up yet.`;
                markRecorded(args.id, {
                  message: detail,
                  txId: args.txId,
                });
                mutationFromArgs(args.mutation, "recorded", { title: args.title, txId: args.txId, detail });
                return;
              }
            } else {
              const detail = `${normalized.detail} Check the affected object before attempting another submission.`;
              markRecorded(args.id, {
                message: detail,
                txId: args.txId,
              });
              mutationFromArgs(args.mutation, "recorded", { title: args.title, txId: args.txId, detail });
              return;
            }
          }
        } catch {
          // keep polling until timeout
        }
        await new Promise((resolve) => window.setTimeout(resolve, pollEveryMs));
      }

      if (args.reconcile) {
        const reconciled = await args.reconcile().catch(() => null);
        const terminal = applyReconciledPhase(args.id, args.txId, args.mutation, args.title, reconciled);
        if (terminal) {
          return;
        }
        if (reconciled?.phase === "submitted") {
          sawSubmittedReconcile = true;
          await new Promise((resolve) => window.setTimeout(resolve, lateReconcileWindowMs));
          const secondReconcile = await args.reconcile().catch(() => null);
          const secondTerminal = applyReconciledPhase(args.id, args.txId, args.mutation, args.title, secondReconcile);
          if (secondTerminal) {
            return;
          }
        }
      }

      const detail = sawSubmittedReconcile
        ? "The action is recorded and partially visible, but final visibility has not arrived yet. Re-open the affected object before retrying."
        : "Submission appears recorded, but the frontend timed out before the dependent surface confirmed visibility. Open the affected object before retrying.";
      markRecorded(args.id, {
        message: detail,
        txId: args.txId,
      });
      mutationFromArgs(args.mutation, "recorded", { title: args.title, txId: args.txId, detail });
    },
    [applyReconciledPhase, markRecorded, markSuccess],
  );

  const runTx = useCallback(
    async <T,>(args: TxLifecycleArgs<T>): Promise<T> => {
      const pendingKey = String(args.pendingKey || "").trim();
      if (pendingKey) {
        const existingId = activePendingKeysRef.current.get(pendingKey);
        if (existingId) {
          const existing = findItemById(existingId);
          const duplicate: any = new Error("That action is already submitting. Wait for the current attempt to settle before trying again.");
          duplicate.code = "duplicate_submission_blocked";
          duplicate.payload = {
            code: "duplicate_submission_blocked",
            message: duplicate.message,
            existing_tx_id: existing?.txId,
            existing_status: existing?.status,
          };
          throw duplicate;
        }
      }

      const id = pushPending({
        title: args.title,
        message: args.pendingMessage || "Validating the action before a signed submission is attempted.",
      });
      if (pendingKey) {
        activePendingKeysRef.current.set(pendingKey, id);
      }

      let attemptedSessionRepair = false;
      try {
        markSubmitting(id, {
          message: "Submitting the signed action to the node.",
        });

        let result: T;
        try {
          result = await args.task();
        } catch (error) {
          const session = getSession();
          if (!attemptedSessionRepair && shouldAttemptSessionRepair(error) && session?.account) {
            attemptedSessionRepair = true;
            await ensureBackendSession({
              account: session.account,
              base: args.finality?.base,
            });
            result = await args.task();
          } else {
            throw error;
          }
        }
        const txId = args.finality?.txId || (args.getTxId ? args.getTxId(result) : undefined) || txIdFromUnknown(result);
        const successMessage =
          typeof args.successMessage === "function"
            ? args.successMessage(result)
            : args.successMessage || "Submission accepted. Waiting for the affected surface to reconcile visibly.";

        if (txId) {
          markRecorded(id, { message: successMessage, txId });
        } else {
          markRefreshing(id, { message: successMessage });
        }

        const shouldTrack = args.finality?.track !== false && !!txId;
        if (shouldTrack && txId) {
          mutationFromArgs(args.finality?.mutation, "recorded", { title: args.title, txId, detail: successMessage });
          void monitorFinality({
            id,
            txId,
            title: args.title,
            base: args.finality?.base,
            pollEveryMs: args.finality?.pollEveryMs,
            timeoutMs: args.finality?.timeoutMs,
            reconcile: args.finality?.reconcile,
            mutation: args.finality?.mutation,
          });
        } else if (!txId) {
          const detail = "Action finished without a trackable tx id. The affected surface should already reflect the change.";
          markSuccess(id, {
            message: detail,
          });
          mutationFromArgs(args.finality?.mutation, "confirmed", { title: args.title, detail });
        }
        return result;
      } catch (error) {
        const feedback: FrontendFeedback = inferFeedbackFromUnknown(error, typeof args.errorMessage === "string" ? args.errorMessage : "Transaction failed.");
        const errorMessage =
          typeof args.errorMessage === "function"
            ? args.errorMessage(error)
            : args.errorMessage || feedback.message || normalizeErrorMessage(error);
        const knownTxId = txIdFromError(error);

        if (feedback.category === "recorded_not_yet_visible") {
          markRecorded(id, {
            message: errorMessage,
            txId: knownTxId,
          });
          mutationFromArgs(args.finality?.mutation, "recorded", { title: args.title, txId: knownTxId, detail: errorMessage });
        } else {
          markError(id, { message: errorMessage, txId: knownTxId });
          mutationFromArgs(args.finality?.mutation, "failed", { title: args.title, txId: knownTxId, detail: errorMessage });
        }
        throw error;
      } finally {
        if (pendingKey && activePendingKeysRef.current.get(pendingKey) === id) {
          activePendingKeysRef.current.delete(pendingKey);
        }
      }
    },
    [findItemById, markError, markRecorded, markRefreshing, markSubmitting, markSuccess, monitorFinality, pushPending],
  );

  const value = useMemo<TxQueueContextValue>(
    () => ({
      items,
      dismiss,
      pushPending,
      markSuccess,
      markError,
      runTx,
    }),
    [dismiss, items, markError, markSuccess, pushPending, runTx],
  );

  return (
    <TxQueueContext.Provider value={value}>
      {children}
      <TxStatusToast items={items} onDismiss={dismiss} />
    </TxQueueContext.Provider>
  );
}

export function useTxQueueContext(): TxQueueContextValue {
  const ctx = useContext(TxQueueContext);
  if (!ctx) {
    throw new Error("useTxQueueContext must be used within TxQueueProvider");
  }
  return ctx;
}
