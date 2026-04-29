import { api } from "../api/weall";
import { confirmed, type ReconcileResult } from "./revalidation";


function memberMatchesAccount(member: any, account: string | null | undefined): boolean {
  const needle = String(account || "").trim().toLowerCase();
  if (!needle) return false;
  return [member?.account, member?.account_id, member?.id, member?.member_account_id]
    .map((value) => String(value || "").trim().toLowerCase())
    .some((value) => value === needle);
}

export async function reconcileGroupVisible(groupId: string, base: string): Promise<ReconcileResult | null> {
  if (!groupId) return null;
  try {
    const groupRes: any = await api.groups.get(groupId, base);
    const group = groupRes?.group || groupRes || null;
    if (group && String(group?.group_id || group?.id || "").trim() === groupId) {
      return confirmed(`Group ${groupId} is already visible on the authoritative groups surface.`);
    }
  } catch {
    // ignore and fall back to list scan
  }
  try {
    const listRes: any = await api.groups.list({ limit: 250 }, base);
    const items = Array.isArray(listRes?.items) ? listRes.items : [];
    if (items.some((item: any) => String(item?.group_id || item?.id || "").trim() === groupId)) {
      return confirmed(`Group ${groupId} is already listed on the authoritative groups surface.`);
    }
  } catch {
    // ignore
  }
  return null;
}

export async function reconcileMembershipState(args: { groupId: string; account: string; expectMember: boolean; base: string }): Promise<ReconcileResult | null> {
  try {
    const membersRes: any = await api.groups.members(args.groupId, args.base);
    const members = Array.isArray(membersRes?.members) ? membersRes.members : [];
    const matched = members.some((member: any) => memberMatchesAccount(member, args.account));
    if (matched === args.expectMember) {
      return {
        phase: "confirmed",
        detail: args.expectMember
          ? `Your membership is already visible on ${args.groupId}.`
          : `Your membership removal is already visible on ${args.groupId}.`,
      };
    }
  } catch {
    // ignore and fall back to list/detail scan
  }

  try {
    const groupRes: any = await api.groups.get(args.groupId, args.base);
    const group = groupRes?.group || groupRes || null;
    const rawMembers = Array.isArray(group?.members) ? group.members : [];
    if (rawMembers.length) {
      const matched = rawMembers.some((member: any) => memberMatchesAccount(member, args.account));
      if (matched === args.expectMember) {
        return confirmed(args.expectMember
          ? `Your membership is already reflected in the group detail view.`
          : `The group detail view already reflects your membership removal.`);
      }
    }
  } catch {
    // ignore
  }

  return null;
}

export async function reconcileMembershipPending(args: { groupId: string; account: string; base: string }): Promise<ReconcileResult | null> {
  try {
    const groupRes: any = await api.groups.get(args.groupId, args.base);
    const group = groupRes?.group || groupRes || null;
    const reqs = group?.membership_requests && typeof group.membership_requests === "object" ? group.membership_requests : {};
    if (reqs && typeof reqs === "object" && reqs[args.account]) {
      return confirmed(`Your membership request is pending on ${args.groupId}.`);
    }
  } catch {
    // ignore and let caller continue polling
  }
  return null;
}

