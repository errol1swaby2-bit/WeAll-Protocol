/** Client-only attention state; never a protocol transaction or consensus input. */

export const ACTIVITY_READ_CHANGED = "weall:activity-read-changed";

type ChainIdentity = {
  chain_id?: unknown;
  genesis_id?: unknown;
};

export function activityReadKey(
  base: string,
  account: string,
  chain: ChainIdentity,
): string {
  const chainId = String(chain.chain_id || "").trim();
  const genesisId = String(chain.genesis_id || "").trim();
  const owner = account.trim();
  if (!base.trim() || !chainId || !genesisId || !owner) return "";
  return [
    "weall:public-activity:v1",
    encodeURIComponent(base.trim()),
    encodeURIComponent(chainId),
    encodeURIComponent(genesisId),
    encodeURIComponent(owner),
  ].join(":");
}

export function getReadActivityIds(key: string): string[] {
  if (!key) return [];
  try {
    const parsed: unknown = JSON.parse(window.localStorage.getItem(key) || "[]");
    return Array.isArray(parsed)
      ? parsed.filter((id): id is string => typeof id === "string")
      : [];
  } catch {
    return [];
  }
}

export function setReadActivityIds(key: string, ids: string[]): void {
  if (!key) return;
  const unique = Array.from(new Set(ids.filter((id) => typeof id === "string")));
  try {
    window.localStorage.setItem(key, JSON.stringify(unique));
    window.dispatchEvent(new Event(ACTIVITY_READ_CHANGED));
  } catch {
    // Local read state is optional and cannot change protocol-visible events.
  }
}

export function recentUnreadActivityCount(
  items: Array<{ id: string }>,
  readIds: string[],
): number {
  const read = new Set(readIds);
  return items.filter((item) => !read.has(item.id)).length;
}

export type ActivityPreference = {
  mutedTypes: string[];
  quietHours: {
    enabled: boolean;
    start: string;
    end: string;
  };
};

export const DEFAULT_ACTIVITY_PREFERENCE: ActivityPreference = {
  mutedTypes: [],
  quietHours: { enabled: false, start: "22:00", end: "08:00" },
};

function isValidTime(input: string): boolean {
  return /^([01]\\d|2[0-3]):[0-5]\\d$/.test(input);
}

export function readActivityPreference(key: string): ActivityPreference {
  if (!key) return DEFAULT_ACTIVITY_PREFERENCE;
  try {
    const obj = JSON.parse(window.localStorage.getItem(`${key}:preference`) || "{}");
    if (!obj || typeof obj !== "object") return DEFAULT_ACTIVITY_PREFERENCE;
    const muted = Array.isArray(obj.mutedTypes)
      ? obj.mutedTypes.filter((x: unknown): x is string => typeof x === "string").slice(0, 100)
      : [];
    const q = obj.quietHours && typeof obj.quietHours === "object" ? obj.quietHours : {};
    return {
      mutedTypes: Array.from(new Set(muted)),
      quietHours: {
        enabled: q.enabled === true,
        start: typeof q.start === "string" && isValidTime(q.start)
          ? q.start
          : DEFAULT_ACTIVITY_PREFERENCE.quietHours.start,
        end: typeof q.end === "string" && isValidTime(q.end)
          ? q.end
          : DEFAULT_ACTIVITY_PREFERENCE.quietHours.end,
      },
    };
  } catch {
    return DEFAULT_ACTIVITY_PREFERENCE;
  }
}

export function writeActivityPreference(key: string, value: ActivityPreference): void {
  if (!key) return;
  try {
    window.localStorage.setItem(`${key}:preference`, JSON.stringify(value));
    window.dispatchEvent(new Event(ACTIVITY_READ_CHANGED));
  } catch {
    // Client attention only. The ledger and all public notices remain unchanged.
  }
}

function inLocalQuietHours(
  quiet: ActivityPreference["quietHours"],
  now: Date,
): boolean {
  if (!quiet.enabled || quiet.start === quiet.end) return false;
  const time = now.getHours() * 60 + now.getMinutes();
  const [startHour, startMin] = quiet.start.split(":").map(Number);
  const [endHour, endMin] = quiet.end.split(":").map(Number);
  const start = startHour * 60 + startMin;
  const end = endHour * 60 + endMin;
  if (start < end) return time >= start && time < end;
  return time >= start || time < end;
}

export function countRecentAttention(
  items: Array<{ id: string; type: string; priority?: string }>,
  readIds: string[],
  prefs: ActivityPreference,
  now: Date = new Date(),
): number {
  const read = new Set(readIds);
  const muted = new Set(prefs.mutedTypes);
  const quiet = inLocalQuietHours(prefs.quietHours, now);
  return items.filter((item) => {
    if (read.has(item.id)) return false;
    // Urgent, public safety/review-duty items cannot be hidden from attention
    // by client-side mutes or quiet hours.
    if (item.priority === "high") return true;
    return !quiet && !muted.has(item.type);
  }).length;
}
