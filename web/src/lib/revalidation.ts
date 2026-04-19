export type ReconcilePhase = "confirmed" | "submitted" | "failed" | "unknown";

export type ReconcileResult = {
  phase: ReconcilePhase;
  detail?: string;
  txId?: string;
};

export type ReconcileFn = () => Promise<ReconcileResult | null>;

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

export async function refreshMutationSlices(
  ...fns: Array<(() => Promise<unknown>) | null | undefined>
): Promise<void> {
  for (const fn of fns) {
    if (!fn) continue;
    await fn();
  }
}
