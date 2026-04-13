import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";

import { getApiBaseUrl, weall } from "../api/weall";
import { normalizeTxStatus } from "../lib/status";
import TxStatusToast, { type TxToastItem } from "./TxStatusToast";

type TxLifecycleArgs<T> = {
  title: string;
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

const TX_HISTORY_KEY = "weall_tx_activity_v1";
const TX_HISTORY_LIMIT = 40;
const TxQueueContext = createContext<TxQueueContextValue | null>(null);

function uid(): string {
  return `tx_${Date.now()}_${Math.random().toString(36).slice(2, 10)}`;
}

function normalizeErrorMessage(error: unknown): string {
  if (error instanceof Error && error.message) return error.message;
  if (typeof error === "string") return error;
  if (error && typeof error === "object") {
    const maybeMessage = (error as any)?.message || (error as any)?.error?.message;
    if (typeof maybeMessage === "string" && maybeMessage.trim()) return maybeMessage;
  }
  return "Transaction failed.";
}

function safeLoadHistory(): TxToastItem[] {
  try {
    const raw = localStorage.getItem(TX_HISTORY_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed
      .filter((item) => item && typeof item === "object")
      .map((item) => ({
        id: String((item as any).id || uid()),
        title: String((item as any).title || "Transaction"),
        status: String((item as any).status || "unknown") as TxToastItem["status"],
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

  useEffect(() => {
    persistHistory(items);
  }, [items]);

  const dismiss = useCallback((id: string) => {
    setItems((prev) => prev.filter((item) => item.id !== id));
  }, []);

  const pushPending = useCallback((args: { title: string; message?: string }): string => {
    const id = uid();
    const item: TxToastItem = {
      id,
      title: args.title,
      status: "preparing",
      message: args.message,
      createdAt: Date.now(),
      updatedAt: Date.now(),
    };
    setItems((prev) => [item, ...prev].slice(0, 8));
    return id;
  }, []);

  const markSubmitted = useCallback((id: string, args?: { message?: string; txId?: string }) => {
    setItems((prev) =>
      prev.map((item) =>
        item.id === id
          ? {
              ...item,
              status: "submitted",
              message: args?.message ?? item.message,
              txId: args?.txId ?? item.txId,
              updatedAt: Date.now(),
            }
          : item,
      ),
    );
  }, []);

  const markSuccess = useCallback(
    (id: string, args?: { message?: string; txId?: string }) => {
      setItems((prev) =>
        prev.map((item) =>
          item.id === id
            ? {
                ...item,
                status: "confirmed",
                message: args?.message ?? item.message,
                txId: args?.txId ?? item.txId,
                updatedAt: Date.now(),
              }
            : item,
        ),
      );

      window.setTimeout(() => dismiss(id), 5000);
    },
    [dismiss],
  );

  const markUnknown = useCallback((id: string, args?: { message?: string; txId?: string }) => {
    setItems((prev) =>
      prev.map((item) =>
        item.id === id
          ? {
              ...item,
              status: "unknown",
              message: args?.message ?? item.message,
              txId: args?.txId ?? item.txId,
              updatedAt: Date.now(),
            }
          : item,
      ),
    );
  }, []);

  const markError = useCallback((id: string, args?: { message?: string; txId?: string }) => {
    setItems((prev) =>
      prev.map((item) =>
        item.id === id
          ? {
              ...item,
              status: "error",
              message: args?.message ?? item.message,
              txId: args?.txId ?? item.txId,
              updatedAt: Date.now(),
            }
          : item,
      ),
    );
  }, []);

  const monitorFinality = useCallback(
    async (args: { id: string; txId: string; base?: string; pollEveryMs?: number; timeoutMs?: number }) => {
      const base = args.base || getApiBaseUrl();
      const pollEveryMs = Math.max(250, Number(args.pollEveryMs ?? 1200));
      const timeoutMs = Math.max(2000, Number(args.timeoutMs ?? 12000));
      const started = Date.now();

      while (Date.now() - started < timeoutMs) {
        try {
          const raw = await weall.txStatus(args.txId, base);
          const normalized = normalizeTxStatus(raw, args.txId);
          if (normalized.phase === "confirmed") {
            markSuccess(args.id, { message: normalized.detail, txId: args.txId });
            return;
          }
          if (normalized.phase === "unknown") {
            markUnknown(args.id, {
              message: `${normalized.detail} Check the account or content surface to verify the final result.`,
              txId: args.txId,
            });
            return;
          }
        } catch {
          // keep polling until timeout
        }
        await new Promise((resolve) => window.setTimeout(resolve, pollEveryMs));
      }

      markUnknown(args.id, {
        message: "Submission succeeded, but the frontend timed out before final confirmation arrived.",
        txId: args.txId,
      });
    },
    [markSuccess, markUnknown],
  );

  const runTx = useCallback(
    async <T,>(args: TxLifecycleArgs<T>): Promise<T> => {
      const id = pushPending({
        title: args.title,
        message: args.pendingMessage || "Preparing and submitting transaction…",
      });

      try {
        const result = await args.task();
        const txId = args.finality?.txId || (args.getTxId ? args.getTxId(result) : undefined);
        const successMessage =
          typeof args.successMessage === "function"
            ? args.successMessage(result)
            : args.successMessage || "Submission accepted. Final confirmation may still be pending.";

        markSubmitted(id, { message: successMessage, txId });

        const shouldTrack = args.finality?.track !== false && !!txId;
        if (shouldTrack && txId) {
          void monitorFinality({
            id,
            txId,
            base: args.finality?.base,
            pollEveryMs: args.finality?.pollEveryMs,
            timeoutMs: args.finality?.timeoutMs,
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
      }
    },
    [markError, markSubmitted, monitorFinality, pushPending],
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
