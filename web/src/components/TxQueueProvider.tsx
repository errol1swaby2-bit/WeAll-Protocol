import React, { createContext, useCallback, useContext, useMemo, useState } from "react";

import TxStatusToast, { type TxToastItem } from "./TxStatusToast";

type TxLifecycleArgs<T> = {
  title: string;
  pendingMessage?: string;
  successMessage?: string | ((result: T) => string);
  errorMessage?: string | ((error: unknown) => string);
  task: () => Promise<T>;
  getTxId?: (result: T) => string | undefined;
};

type TxQueueContextValue = {
  items: TxToastItem[];
  dismiss: (id: string) => void;
  pushPending: (args: { title: string; message?: string }) => string;
  markSuccess: (id: string, args?: { message?: string; txId?: string }) => void;
  markError: (id: string, args?: { message?: string; txId?: string }) => void;
  runTx: <T>(args: TxLifecycleArgs<T>) => Promise<T>;
};

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

export function TxQueueProvider({ children }: { children: React.ReactNode }): JSX.Element {
  const [items, setItems] = useState<TxToastItem[]>([]);

  const dismiss = useCallback((id: string) => {
    setItems((prev) => prev.filter((item) => item.id !== id));
  }, []);

  const pushPending = useCallback((args: { title: string; message?: string }): string => {
    const id = uid();
    const item: TxToastItem = {
      id,
      title: args.title,
      status: "pending",
      message: args.message,
      createdAt: Date.now(),
    };
    setItems((prev) => [item, ...prev].slice(0, 6));
    return id;
  }, []);

  const markSuccess = useCallback(
    (id: string, args?: { message?: string; txId?: string }) => {
      setItems((prev) =>
        prev.map((item) =>
          item.id === id
            ? {
                ...item,
                status: "success",
                message: args?.message ?? item.message,
                txId: args?.txId ?? item.txId,
              }
            : item,
        ),
      );

      window.setTimeout(() => dismiss(id), 4500);
    },
    [dismiss],
  );

  const markError = useCallback((id: string, args?: { message?: string; txId?: string }) => {
    setItems((prev) =>
      prev.map((item) =>
        item.id === id
          ? {
              ...item,
              status: "error",
              message: args?.message ?? item.message,
              txId: args?.txId ?? item.txId,
            }
          : item,
      ),
    );
  }, []);

  const runTx = useCallback(
    async <T,>(args: TxLifecycleArgs<T>): Promise<T> => {
      const id = pushPending({
        title: args.title,
        message: args.pendingMessage || "Submitting transaction…",
      });

      try {
        const result = await args.task();
        const txId = args.getTxId ? args.getTxId(result) : undefined;
        const successMessage =
          typeof args.successMessage === "function"
            ? args.successMessage(result)
            : args.successMessage || "Transaction submitted successfully.";
        markSuccess(id, { message: successMessage, txId });
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
    [markError, markSuccess, pushPending],
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
