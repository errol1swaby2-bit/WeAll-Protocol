import React, { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import { getAccount, weall } from "../api/weall";
import { ACCOUNT_REFRESH_INTERVAL_MS, refreshTouches, subscribeGlobalRefresh } from "../lib/revalidation";

type AccountState = {
  account?: string;
  nonce?: number;
  poh_tier?: number;
  banned?: boolean;
  locked?: boolean;
  reputation?: number;
};

type AccountContextValue = {
  state: AccountState | null;
  loading: boolean;
  lastUpdatedAt: number | null;
  refresh: () => Promise<void>;
  setState: React.Dispatch<React.SetStateAction<AccountState | null>>;
};

const AccountContext = createContext<AccountContextValue>({
  state: null,
  loading: false,
  lastUpdatedAt: null,
  refresh: async () => {},
  setState: () => {},
});

function asNumber(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function asBoolean(value: unknown): boolean | undefined {
  return typeof value === "boolean" ? value : undefined;
}

function mapAccountState(acct: string, raw: unknown): AccountState {
  const src = raw && typeof raw === "object" ? (raw as Record<string, unknown>) : {};
  return {
    account: acct,
    nonce: asNumber(src.nonce),
    poh_tier: asNumber(src.poh_tier),
    banned: asBoolean(src.banned),
    locked: asBoolean(src.locked),
    reputation: asNumber(src.reputation),
  };
}

export function AccountProvider({ children }: { children: React.ReactNode }) {
  const [state, setState] = useState<AccountState | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [lastUpdatedAt, setLastUpdatedAt] = useState<number | null>(null);
  const refreshInFlight = useRef<Promise<void> | null>(null);

  const refresh = useCallback(async () => {
    const acct = getAccount();
    if (!acct) {
      setState(null);
      setLastUpdatedAt(Date.now());
      return;
    }

    if (refreshInFlight.current) {
      await refreshInFlight.current;
      return;
    }

    const run = (async () => {
      setLoading(true);
      try {
        const res = await weall.account(acct);
        const rawState =
          res && typeof res === "object" && "state" in res && res.state && typeof res.state === "object"
            ? (res.state as Record<string, unknown>)
            : {};
        setState(mapAccountState(acct, rawState));
        setLastUpdatedAt(Date.now());
      } catch {
        setState({ account: acct });
        setLastUpdatedAt(Date.now());
      } finally {
        setLoading(false);
        refreshInFlight.current = null;
      }
    })();

    refreshInFlight.current = run;
    await run;
  }, []);

  useEffect(() => {
    void refresh();

    const onStorage = (ev: StorageEvent) => {
      if (!ev.key) return;
      if (ev.key === "weall_session_v1" || ev.key === "weall.account" || ev.key.startsWith("weall_kp_v1::")) {
        void refresh();
      }
    };

    const poll = window.setInterval(() => {
      if (!document.hidden) void refresh();
    }, ACCOUNT_REFRESH_INTERVAL_MS);
    const unsubscribe = subscribeGlobalRefresh((request) => {
      if (refreshTouches(request, ["account", "session", "route"])) {
        void refresh();
      }
    });

    window.addEventListener("storage", onStorage);
    window.addEventListener("focus", refresh);

    return () => {
      unsubscribe();
      window.removeEventListener("storage", onStorage);
      window.removeEventListener("focus", refresh);
      window.clearInterval(poll);
    };
  }, [refresh]);

  const value = useMemo<AccountContextValue>(
    () => ({
      state,
      loading,
      lastUpdatedAt,
      refresh,
      setState,
    }),
    [state, loading, lastUpdatedAt, refresh],
  );

  return <AccountContext.Provider value={value}>{children}</AccountContext.Provider>;
}

export function useAccount() {
  return useContext(AccountContext);
}
