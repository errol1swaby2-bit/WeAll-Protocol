import { useEffect, useMemo, useState } from "react";

import { getSignerSubmissionSnapshot, subscribeSignerSubmission } from "../auth/session";

export function useSignerSubmissionBusy(account: string | null | undefined): { busy: boolean; pendingCount: number } {
  const normalized = String(account || "").trim();
  const [pendingCount, setPendingCount] = useState<number>(() => getSignerSubmissionSnapshot(normalized).pendingCount);

  useEffect(() => {
    setPendingCount(getSignerSubmissionSnapshot(normalized).pendingCount);
    return subscribeSignerSubmission(normalized, (snapshot) => {
      setPendingCount(snapshot.pendingCount);
    });
  }, [normalized]);

  return useMemo(
    () => ({ busy: pendingCount > 0, pendingCount }),
    [pendingCount],
  );
}
