import { useEffect, useMemo, useRef, useState } from "react";

import { getSessionHealth, type SessionHealth } from "../auth/session";
import { ACCOUNT_REFRESH_INTERVAL_MS, refreshTouches, subscribeGlobalRefresh } from "../lib/revalidation";

export function useSessionHealth(version?: number): SessionHealth {
  const [tick, setTick] = useState<number>(0);
  const refreshQueued = useRef<boolean>(false);

  useEffect(() => {
    const refresh = () => {
      if (refreshQueued.current) return;
      refreshQueued.current = true;
      window.requestAnimationFrame(() => {
        refreshQueued.current = false;
        setTick((v) => v + 1);
      });
    };
    const onStorage = (ev: StorageEvent) => {
      const key = String(ev.key || "");
      if (key === "weall_session_v1" || key === "weall.account" || key.startsWith("weall_kp_v1::")) {
        refresh();
      }
    };

    const intervalId = window.setInterval(() => {
      if (!document.hidden) refresh();
    }, ACCOUNT_REFRESH_INTERVAL_MS);
    const unsubscribe = subscribeGlobalRefresh((request) => {
      if (refreshTouches(request, ["session", "account", "route"])) {
        refresh();
      }
    });

    window.addEventListener("storage", onStorage);
    window.addEventListener("focus", refresh);
    document.addEventListener("visibilitychange", refresh);

    return () => {
      unsubscribe();
      window.clearInterval(intervalId);
      window.removeEventListener("storage", onStorage);
      window.removeEventListener("focus", refresh);
      document.removeEventListener("visibilitychange", refresh);
    };
  }, []);

  return useMemo(() => getSessionHealth(), [tick, version]);
}
