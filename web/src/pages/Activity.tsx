import React, { useEffect, useMemo, useRef, useState } from "react";

import { getAuthHeaders, getSession } from "../auth/session";
import { normalizeAccount } from "../auth/keys";
import { getApiBaseUrl, weall } from "../api/weall";
import ErrorBanner from "../components/ErrorBanner";
import { nav } from "../lib/router";
import {
  activityReadKey,
  countRecentAttention,
  DEFAULT_ACTIVITY_PREFERENCE,
  getReadActivityIds,
  readActivityPreference,
  setReadActivityIds,
  writeActivityPreference,
  type ActivityPreference,
} from "../lib/activityReadState";

type ActivityItem = {
  id: string;
  type: string;
  title: string;
  body: string;
  href?: string;
  source?: string;
  height?: number;
  priority?: "normal" | "high";
};

type Filter = "all" | "unread" | "high";

function parseNotices(response: any): ActivityItem[] {
  if (!response || response.ok !== true || !Array.isArray(response.items)) {
    throw new Error("The node did not return a valid public activity notice list.");
  }
  return response.items
    .filter((value: any) => value && typeof value.id === "string" && typeof value.type === "string")
    .map((value: any) => ({
      id: value.id,
      type: value.type,
      title: String(value.title || "Public activity"),
      body: String(value.body || ""),
      // Only internal application routes are valid navigation targets.
      href: typeof value.href === "string" && /^\/[a-zA-Z0-9@/_%-]*$/.test(value.href)
        ? value.href
        : "/activity",
      source: String(value.source || ""),
      height: Number.isSafeInteger(value.height) ? value.height : undefined,
      priority: value.priority === "high" ? "high" : "normal",
    }));
}

export default function Activity(): JSX.Element {
  const base = useMemo(() => getApiBaseUrl(), []);
  const session = getSession();
  const account = normalizeAccount(session?.account || "");
  const headers = useMemo(() => (account ? getAuthHeaders(account) : undefined), [account]);
  const requestVersion = useRef(0);
  const [items, setItems] = useState<ActivityItem[]>([]);
  const [readIds, setReadIds] = useState<string[]>([]);
  const [preferences, setPreferences] = useState<ActivityPreference>(DEFAULT_ACTIVITY_PREFERENCE);
  const [storageKey, setStorageKey] = useState("");
  const [cursor, setCursor] = useState<string | null>(null);
  const [filter, setFilter] = useState<Filter>("all");
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<{ msg: string; details: any } | null>(null);

  async function load(nextCursor?: string): Promise<void> {
    const version = ++requestVersion.current;
    setLoading(true);
    setErr(null);
    if (!nextCursor) {
      setItems([]);
      setCursor(null);
      setReadIds([]);
      setPreferences(DEFAULT_ACTIVITY_PREFERENCE);
      setStorageKey("");
    }
    if (!account) {
      setLoading(false);
      return;
    }

    try {
      const response = await weall.activityNotices(base, headers, {
        limit: 50,
        cursor: nextCursor,
      });
      if (version !== requestVersion.current) return;
      if (response?.authenticated !== true || response?.account_id !== account) {
        throw new Error("Account session is required to view personalized public notices.");
      }
      const received = parseNotices(response);
      const key = activityReadKey(base, account, response);
      if (!nextCursor) {
        setStorageKey(key);
        setReadIds(getReadActivityIds(key));
        setPreferences(readActivityPreference(key));
        setItems(received);
      } else {
        setItems((current) => {
          const byId = new Map(current.map((item) => [item.id, item]));
          received.forEach((item) => byId.set(item.id, item));
          return Array.from(byId.values());
        });
      }
      setCursor(typeof response.next_cursor === "string" ? response.next_cursor : null);
    } catch (e: any) {
      if (version !== requestVersion.current) return;
      setErr({
        msg: e?.message || "Unable to load public activity notices.",
        details: e?.payload || e?.body || e,
      });
    } finally {
      if (version === requestVersion.current) setLoading(false);
    }
  }

  useEffect(() => {
    void load();
    return () => { requestVersion.current += 1; };
  }, [account, base]);

  function markRead(ids: string[]): void {
    const combined = Array.from(new Set([...readIds, ...ids]));
    setReadIds(combined);
    if (storageKey) {
      setReadActivityIds(storageKey, combined);
    }
  }

  function changePreferences(next: ActivityPreference): void {
    setPreferences(next);
    writeActivityPreference(storageKey, next);
  }

  const unread = items.filter((item) => !readIds.includes(item.id));
  const attentionCount = countRecentAttention(items, readIds, preferences);
  const noticeCategories = Array.from(new Set(items.map((item) => item.type))).sort();
  const visible = items.filter((item) => (
    filter === "all"
      || (filter === "unread" && !readIds.includes(item.id))
      || (filter === "high" && item.priority === "high")
  ));

  return (
    <section className="pageStack">
      <div className="pageHeader">
        <div>
          <div className="eyebrow">Public activity</div>
          <h1>Activity notices</h1>
          <p>
            Notices come from publicly inspectable protocol events. Supported activity includes
            mentions, replies, review assignments, governance events, reputation updates, and
            validator/operator alerts. Read and filtering choices are local to this browser.
          </p>
        </div>
        <button className="btn" onClick={() => void load()} disabled={loading || !account}>
          {loading ? "Refreshing…" : "Refresh"}
        </button>
      </div>

      <section className="card">
        <div className="cardBody formStack">
          <div className="eyebrow">Protocol rule</div>
          <h2 className="cardTitle">Public events, personal attention</h2>
          <p className="cardDesc">
            Participation may require membership or verification, but public protocol visibility is
            not restricted by your notification choices. This is not a private message inbox.
          </p>
          {!storageKey && account && items.length > 0 ? (
            <p className="cardDesc">This node did not provide a full chain and genesis identity, so read status will not persist across visits.</p>
          ) : null}
        </div>
      </section>

      {err ? (
        <ErrorBanner message={err.msg} details={err.details} onRetry={() => void load()} onDismiss={() => setErr(null)} />
      ) : null}

      <section className="card">
        <div className="cardBody formStack">
          <div className="sectionTitleRow">
            <div>
              <div className="eyebrow">Public event notices</div>
              <h2 className="cardTitle">
                {account ? `${unread.length} unread · ${items.length} loaded` : "Sign in to view activity"}
              </h2>
            </div>
            {items.length > 0 ? (
              <button className="btn btnSmall" onClick={() => markRead(items.map((item) => item.id))}>
                Mark all read
              </button>
            ) : null}
          </div>

          <div className="infoCardText">
            {attentionCount} recent notice{attentionCount === 1 ? "" : "s"} requiring attention in this loaded page.
            Muted categories and local quiet hours never remove public protocol events or suppress high-priority safety and review duties.
          </div>

          <div className="buttonRow" role="group" aria-label="Filter activity notices">
            {(["all", "unread", "high"] as Filter[]).map((option) => (
              <button
                key={option}
                className={`btn btnSmall ${filter === option ? "btnPrimary" : ""}`.trim()}
                onClick={() => setFilter(option)}
                aria-pressed={filter === option}
              >
                {option === "all" ? "All" : option === "unread" ? "Unread" : "High priority"}
              </button>
            ))}
          </div>


          {account && (
            <section aria-label="Local notification preferences" className="infoCard compact">
              <h3>Local notification preferences</h3>
              <p className="cardDesc">
                These settings affect only the recent-attention bell, never the public event history
                or protocol permissions. High-priority safety and review-duty alerts remain visible.
              </p>
              <label>
                <input
                  type="checkbox"
                  checked={preferences.quietHours.enabled}
                  disabled={!storageKey}
                  onChange={(event) => changePreferences({
                    ...preferences,
                    quietHours: { ...preferences.quietHours, enabled: event.target.checked },
                  })}
                />
                Quiet hours for normal-priority attention
              </label>
              <div className="buttonRow">
                <label>Start
                  <input
                    type="time"
                    value={preferences.quietHours.start}
                    disabled={!storageKey}
                    onChange={(event) => changePreferences({
                      ...preferences,
                      quietHours: { ...preferences.quietHours, start: event.target.value },
                    })}
                  />
                </label>
                <label>End
                  <input
                    type="time"
                    value={preferences.quietHours.end}
                    disabled={!storageKey}
                    onChange={(event) => changePreferences({
                      ...preferences,
                      quietHours: { ...preferences.quietHours, end: event.target.value },
                    })}
                  />
                </label>
              </div>
              <div className="buttonRow" role="group" aria-label="Mute normal-priority categories">
                {noticeCategories.map((category) => {
                  const muted = preferences.mutedTypes.includes(category);
                  return (
                    <button
                      key={category}
                      className="btn btnSmall"
                      disabled={!storageKey}
                      aria-pressed={muted}
                      onClick={() => changePreferences({
                        ...preferences,
                        mutedTypes: muted
                          ? preferences.mutedTypes.filter((entry) => entry !== category)
                          : [...preferences.mutedTypes, category],
                      })}
                    >
                      {muted ? "Unmute " : "Mute "}{category.replace(/_/g, " ")}
                    </button>
                  );
                })}
              </div>
            </section>
          )}

          {visible.length > 0 ? (
            <div className="listStack">
              {visible.map((item) => {
                const isUnread = !readIds.includes(item.id);
                return (
                  <article key={item.id} className="listItem">
                    <div>
                      <div className="eyebrow">
                        {item.type.replace(/_/g, " ")}
                        {item.priority === "high" ? " · high priority" : ""}
                        {isUnread ? " · unread" : ""}
                      </div>
                      <h3>{item.title}</h3>
                      <p>{item.body}</p>
                    </div>
                    <div className="buttonRow">
                      {isUnread ? (
                        <button className="btn btnSmall" onClick={() => markRead([item.id])}>Mark read</button>
                      ) : null}
                      {item.href ? (
                        <button className="btn btnSmall" onClick={() => { markRead([item.id]); nav(item.href || "/activity"); }}>Open</button>
                      ) : null}
                    </div>
                  </article>
                );
              })}
            </div>
          ) : (
            <p className="cardDesc">
              {!account ? "Connect an account session first."
                : loading ? "Loading public notices…"
                  : err ? "The notice feed could not be refreshed; do not interpret this as an empty inbox."
                    : items.length === 0 ? "No finalized public notices were found for this account in the currently supported categories."
                      : "No notices match the selected filter."}
            </p>
          )}
          {cursor && !err ? (
            <button className="btn" disabled={loading} onClick={() => void load(cursor)}>
              {loading ? "Loading…" : "Load more"}
            </button>
          ) : null}
        </div>
      </section>
    </section>
  );
}
