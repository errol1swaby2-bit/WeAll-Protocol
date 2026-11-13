/** Read-only helpers. No browser role or scoped report match grants review authority. */
export function publicRoleAccounts(value: unknown): string[] {
  const entries = Array.isArray(value)
    ? value
    : value && typeof value === "object" ? Object.keys(value as Record<string, unknown>) : [];
  return [...new Set(entries.map((entry) => String(entry || "").trim()).filter(Boolean))].sort();
}

/** Only verified content provenance from the public API may scope a report to a group.
 * A missing source never becomes group-local authority or an exhaustive count.
 */
export function groupReportSource(
  report: unknown,
  groupId: string,
  returnedPostIds: ReadonlySet<string>,
): "canonical_target_snapshot" | "returned_group_post" | null {
  if (!report || typeof report !== "object" || !groupId.trim()) return null;
  const record = report as Record<string, any>;
  const target = String(record.target_id || "").trim();
  const type = String(record.target_type || "content").trim().toLowerCase();
  if (!target || !["content", "post", "comment"].includes(type)) return null;
  const snapshot = record.target_content_snapshot || record.target_content;
  if (snapshot && typeof snapshot === "object" && !Array.isArray(snapshot)) {
    const scope = String(snapshot.group_id || "").trim();
    if (scope) return scope === groupId ? "canonical_target_snapshot" : null;
  }
  // The group feed indexes only group posts, not all historical hidden posts
  // and not arbitrary comment IDs. Never infer a complete moderation index.
  if ((type === "content" || type === "post") && returnedPostIds.has(target)) {
    return "returned_group_post";
  }
  return null;
}
