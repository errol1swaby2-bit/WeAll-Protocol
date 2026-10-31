import React, { useEffect, useMemo, useState } from "react";

import { getApiBaseUrl, weall } from "../api/weall";
import { getAuthHeaders } from "../auth/session";
import {
  ACTIVITY_READ_CHANGED,
  activityReadKey,
  getReadActivityIds,
  countRecentAttention,
  readActivityPreference,
} from "../lib/activityReadState";
import { nav } from "../lib/router";

type ActivityFeed = {
  ids: Array<{ id: string; type: string; priority?: string }>;
  key: string;
  more: boolean;
};

export default function ActivityBell({
  account,
  refreshToken,
}: {
  account: string;
  refreshToken: string;
}): JSX.Element {
  const base = useMemo(() => getApiBaseUrl(), []);
  const [feed, setFeed] = useState<ActivityFeed | null>(null);
  const [readRevision, setReadRevision] = useState(0);
  const [clockRevision, setClockRevision] = useState(0);
  const [available, setAvailable] = useState(false);

  useEffect(() => {
    const onReadStateChange = () => setReadRevision((value) => value + 1);
    window.addEventListener(ACTIVITY_READ_CHANGED, onReadStateChange);
    window.addEventListener("storage", onReadStateChange);
    return () => {
      window.removeEventListener(ACTIVITY_READ_CHANGED, onReadStateChange);
      window.removeEventListener("storage", onReadStateChange);
    };
  }, []);

  useEffect(() => {
    const interval = window.setInterval(() => setClockRevision((value) => value + 1), 60_000);
    return () => window.clearInterval(interval);
  }, []);

  useEffect(() => {
    let active = true;
    setFeed(null);
    setAvailable(false);
    if (!account.trim()) return () => { active = false; };

    // Only read with the browser's existing protected account session.
    // Never retain the bearer token or session header in local storage.
    const headers = getAuthHeaders(account);
    void weall.activityNotices(base, headers, { limit: 100 })
      .then((response: any) => {
        if (!active) return;
        if (
          response?.ok !== true
          || response?.authenticated !== true
          || response?.account_id !== account
          || !Array.isArray(response.items)
        ) {
          return;
        }
        const key = activityReadKey(base, account, response);
        if (!key) return;
        const ids = response.items
          .filter((item: any) => item && typeof item.id === "string" && typeof item.type === "string")
          .map((item: any) => ({
            id: String(item.id),
            type: String(item.type),
            priority: item.priority === "high" ? "high" : "normal",
          }));
        setFeed({ ids, key, more: typeof response.next_cursor === "string" });
        setAvailable(true);
      })
      .catch(() => {
        // A failed or unauthorized read is NOT an empty inbox.
      });
    return () => { active = false; };
  }, [account, base, refreshToken]);

  // The revision signal only re-reads client-side state, not protocol events.
  void readRevision;
  void clockRevision;
  const count = feed
    ? countRecentAttention(
        feed.ids,
        getReadActivityIds(feed.key),
        readActivityPreference(feed.key),
      )
    : null;

  const accessibleStatus = count === null
    ? available ? "Activity notices" : "Activity notices, count unavailable"
    : `${count} need attention among the latest ${feed?.ids.length || 0} loaded public notices (local mutes and quiet hours apply)`;

  return (
    <button
      type="button"
      className="appShellInfoToggle"
      onClick={() => nav(account ? "/activity" : "/login")}
      aria-label={accessibleStatus}
      title={accessibleStatus}
    >
      <span aria-hidden="true">🔔</span>
      <span>Activity</span>
      {count !== null && count > 0 ? (
        <span className="statusPill warning" aria-hidden="true">
          {count}{feed?.more ? "+" : ""}
        </span>
      ) : null}
    </button>
  );
}
