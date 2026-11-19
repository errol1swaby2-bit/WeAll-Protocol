/**
 * A read model can show the effect of an action without proving that the
 * *specific signed transaction* committed successfully. Only the canonical
 * transaction status/receipt may settle a transaction toast or mutation.
 */
export type ReconcilePhase = "confirmed" | "submitted" | "failed" | "unknown";

export type ReadModelObservation = {
  phase: ReconcilePhase;
  detail?: string;
  txId?: string;
};

export type ReconciliationPresentation = {
  status: "refreshing" | "recorded";
  detail: string;
  txId: string;
  keepPolling: boolean;
};

/**
 * Normalize read-model reconciliation as *nonterminal evidence*. In
 * particular, "confirmed" here describes a domain record, not a successful
 * apply receipt for the submitted transaction.
 */
export function describeReadModelObservation(
  submittedTxId: string,
  observation: ReadModelObservation | null,
): ReconciliationPresentation | null {
  if (!observation) return null;
  const txId = String(submittedTxId || "").trim();
  const reportedId = String(observation.txId || "").trim();

  if (reportedId && reportedId !== txId) {
    return {
      status: "recorded",
      txId,
      keepPolling: false,
      detail: "The related record references a different action ID. This transaction remains unverified; check the original action before retrying.",
    };
  }

  switch (observation.phase) {
    case "confirmed":
      return {
        status: "refreshing",
        txId,
        keepPolling: true,
        detail: "The affected record is visible, but this signed action still needs its own successful canonical apply receipt.",
      };
    case "submitted":
      return {
        status: "refreshing",
        txId,
        keepPolling: true,
        detail: "The affected record is still updating. The signed action has not yet been verified by a canonical receipt.",
      };
    case "failed":
      return {
        status: "recorded",
        txId,
        keepPolling: true,
        detail: "The affected record reports a problem. Check the specific signed transaction receipt before treating it as rejected or retrying.",
      };
    case "unknown":
    default:
      return {
        status: "recorded",
        txId,
        keepPolling: false,
        detail: "The affected record cannot establish the transaction result. Inspect the original transaction status.",
      };
  }
}
