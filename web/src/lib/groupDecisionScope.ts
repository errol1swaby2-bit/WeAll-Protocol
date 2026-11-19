/** Fail-closed binding for a group-context proposal. URL context cannot grant authority.
 * The backend remains authoritative for every signed governance operation.
 */
export function requireExactGroupProposalScope(
  candidate: unknown,
  canonicalGroupId: string,
): void {
  const groupId = String(canonicalGroupId || "").trim();
  if (!groupId || !candidate || typeof candidate !== "object" || Array.isArray(candidate)) {
    throw new Error("A verified canonical group and proposal object are required.");
  }
  const payload = candidate as Record<string, unknown>;
  if (String(payload.group_id || "") !== groupId || payload.electorate_scope !== "group_members") {
    throw new Error("Decision scope does not match this group's canonical ID and electorate.");
  }
  // scope_id is optional in the schema but must never smuggle a second scope.
  if (payload.scope_id != null && payload.scope_id !== groupId) {
    throw new Error("Conflicting scope_id is not permitted in a group-bound decision.");
  }
}

export function verifiedGroupContract(candidate: unknown, canonicalGroupId: string): boolean {
  if (!candidate || typeof candidate !== "object") return false;
  const contract = candidate as Record<string, unknown>;
  return contract.ok === true &&
    String(contract.group_id || "").trim() === String(canonicalGroupId || "").trim() &&
    !!String(canonicalGroupId || "").trim();
}
