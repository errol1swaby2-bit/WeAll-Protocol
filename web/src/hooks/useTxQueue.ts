import { useTxQueueContext } from "../components/TxQueueProvider";

export function useTxQueue() {
  return useTxQueueContext();
}
