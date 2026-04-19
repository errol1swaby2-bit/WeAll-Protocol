import { useEffect, useMemo, useState } from "react";

import { getSessionHealth, type SessionHealth } from "../auth/session";

export function useSessionHealth(version?: number): SessionHealth {
  const [tick, setTick] = useState<number>(0);

  useEffect(() => {
    const refresh = () => setTick((v) => v + 1);
    const onStorage = (ev: StorageEvent) => {
      const key = String(ev.key || "");
      if (key === "weall_session_v1" || key === "weall.account" || key.startsWith("weall_kp_v1::")) {
        refresh();
      }
    };

    const intervalId = window.setInterval(refresh, 15000);
    window.addEventListener("storage", onStorage);
    window.addEventListener("focus", refresh);
    document.addEventListener("visibilitychange", refresh);

    return () => {
      window.clearInterval(intervalId);
      window.removeEventListener("storage", onStorage);
      window.removeEventListener("focus", refresh);
      document.removeEventListener("visibilitychange", refresh);
    };
  }, []);

  return useMemo(() => getSessionHealth(), [tick, version]);
}
