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
