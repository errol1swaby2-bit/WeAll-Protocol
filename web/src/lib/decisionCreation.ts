export type DecisionCreationState = "pending" | "waiting_visibility" | "ready" | "rejected" | "unavailable";
type TrackedDecision = { id: string; txId: string; account: string };

/** Visibility alone is never proof that this particular creation succeeded. */
export function decisionCreationState(tracked: TrackedDecision, receipt: any, phase: string, proposal: any): DecisionCreationState {
  if (!tracked.txId || !receipt || String(receipt.tx_id || "").trim() !== tracked.txId) return "unavailable";
  if (phase === "failed") return "rejected";
  if (phase !== "confirmed" || receipt.apply_ok !== true || receipt.local_state_synced === false) return "pending";
  if (!proposal || String(proposal.proposal_id || proposal.id || "").trim() !== tracked.id || String(proposal.creator || "").trim() !== tracked.account) return "waiting_visibility";
  return "ready";
}
