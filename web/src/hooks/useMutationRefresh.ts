import { useEffect, useRef } from "react";

import { subscribeMutationSignals, type MutationEntityType, type MutationSignal } from "../lib/mutationSignals";

type UseMutationRefreshArgs = {
  entityTypes: MutationEntityType[];
  entityIds?: Array<string | null | undefined>;
  account?: string | null;
  onRefresh: (signal: MutationSignal) => void | Promise<void>;
};

function normalize(value: string | null | undefined): string {
  return String(value || "").trim().toLowerCase();
}

export function useMutationRefresh(args: UseMutationRefreshArgs): void {
  const entityTypeSet = useRef<Set<string>>(new Set());
  const entityIdSet = useRef<Set<string>>(new Set());
  const accountRef = useRef<string>("");
  const onRefreshRef = useRef(args.onRefresh);

  entityTypeSet.current = new Set(args.entityTypes.map((value) => normalize(value)));
  entityIdSet.current = new Set((args.entityIds || []).map((value) => normalize(value)).filter(Boolean));
  accountRef.current = normalize(args.account || "");
  onRefreshRef.current = args.onRefresh;

  useEffect(() => {
    return subscribeMutationSignals((signal) => {
      const signalType = normalize(signal.entityType);
      if (!entityTypeSet.current.has(signalType)) return;
      const normalizedSignalId = normalize(signal.entityId);
      const normalizedSignalAccount = normalize(signal.account);
      const entityIds = entityIdSet.current;
      const account = accountRef.current;

      const idMatched = entityIds.size === 0 || (!!normalizedSignalId && entityIds.has(normalizedSignalId));
      const accountMatched = !account || !normalizedSignalAccount || normalizedSignalAccount === account;
      if (!idMatched || !accountMatched) return;
      void onRefreshRef.current(signal);
    });
  }, []);
}
