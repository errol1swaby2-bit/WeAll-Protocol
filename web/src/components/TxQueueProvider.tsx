import React, { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";

import { getApiBaseUrl, weall } from "../api/weall";
import { normalizeTxStatus } from "../lib/status";
import { inferFeedbackFromUnknown, normalizeStoredTxStatus, type TxLifecycleStatus } from "../lib/txFeedback";
import TxStatusToast, { type TxToastItem } from "./TxStatusToast";

type ReconcilePhase = "confirmed" | "submitted" | "failed" | "unknown";

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

const TX_HISTORY_KEY = "weall_tx_activity_v2";
const TX_HISTORY_FALLBACK_KEY = "weall_tx_activity_v1";
const TX_HISTORY_LIMIT = 40;
const TxQueueContext = createContext<TxQueueContextValue | null>(null);

function uid(): string {
  return `tx_${Date.now()}_${Math.random().toString(36).slice(2, 10)}`;
}

function normalizeErrorMessage(error: unknown): string {
  return inferFeedbackFromUnknown(error, "Transaction failed.").message;
}

function safeLoadHistory(): TxToastItem[] {
  try {
    const raw = localStorage.getItem(TX_HISTORY_KEY) || localStorage.getItem(TX_HISTORY_FALLBACK_KEY);
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
    (id: string, txId: string, reconciled: { phase: ReconcilePhase; detail?: string; txId?: string } | null): boolean => {
      if (!reconciled) return false;
      if (reconciled.phase === "confirmed") {
        markSuccess(id, {
          message: reconciled.detail || "The affected surface has reconciled the recorded action.",
          txId: reconciled.txId || txId,
        });
        return true;
      }
      if (reconciled.phase === "failed") {
        markError(id, {
          message: reconciled.detail || "The affected surface reports that the action failed.",
          txId: reconciled.txId || txId,
        });
        return true;
      }
      if (reconciled.phase === "submitted") {
        markRefreshing(id, {
          message: reconciled.detail || "The action is recorded. Refreshing the affected surface so it becomes visible.",
          txId: reconciled.txId || txId,
        });
        return false;
      }
      markRecorded(id, {
        message: reconciled.detail || "The action was recorded, but the affected surface has not confirmed visibility yet.",
        txId: reconciled.txId || txId,
      });
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
            return;
          }
          if (normalized.phase === "unknown") {
            if (args.reconcile) {
              const reconciled = await args.reconcile().catch(() => null);
              const terminal = applyReconciledPhase(args.id, args.txId, reconciled);
              if (terminal) return;
              if (reconciled?.phase === "submitted") {
                sawSubmittedReconcile = true;
              } else {
                markRecorded(args.id, {
                  message: `${normalized.detail} The action may already be recorded, but the visible surface has not caught up yet.`,
                  txId: args.txId,
                });
                return;
              }
            } else {
              markRecorded(args.id, {
                message: `${normalized.detail} Check the affected object before attempting another submission.`,
                txId: args.txId,
              });
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
        const terminal = applyReconciledPhase(args.id, args.txId, reconciled);
        if (terminal) {
          return;
        }
        if (reconciled?.phase === "submitted") {
          sawSubmittedReconcile = true;
          await new Promise((resolve) => window.setTimeout(resolve, lateReconcileWindowMs));
          const secondReconcile = await args.reconcile().catch(() => null);
          const secondTerminal = applyReconciledPhase(args.id, args.txId, secondReconcile);
          if (secondTerminal) {
            return;
          }
        }
      }

      markRecorded(args.id, {
        message: sawSubmittedReconcile
          ? "The action is recorded and partially visible, but final visibility has not arrived yet. Re-open the affected object before retrying."
          : "Submission appears recorded, but the frontend timed out before the dependent surface confirmed visibility. Open the affected object before retrying.",
        txId: args.txId,
      });
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

      try {
        markSubmitting(id, {
          message: "Submitting the signed action to the node.",
        });

        const result = await args.task();
        const txId = args.finality?.txId || (args.getTxId ? args.getTxId(result) : undefined);
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
          void monitorFinality({
            id,
            txId,
            base: args.finality?.base,
            pollEveryMs: args.finality?.pollEveryMs,
            timeoutMs: args.finality?.timeoutMs,
            reconcile: args.finality?.reconcile,
          });
        } else if (!txId) {
          markSuccess(id, {
            message: "Action finished without a trackable tx id. The affected surface should already reflect the change.",
          });
        }
        return result;
      } catch (error) {
        const errorMessage =
          typeof args.errorMessage === "function"
            ? args.errorMessage(error)
            : args.errorMessage || normalizeErrorMessage(error);
        markError(id, { message: errorMessage });
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
