/** Only the exact canonical account's same-node media proxy is eligible. */
export function canonicalAvatarPath(response: any, account: string): string {
  if (response?.ok !== true || response.account !== account) return "";
  const profile = response.profile;
  if (profile?.account_id && profile.account_id !== account) return "";
  const cid = String(profile?.avatar_cid || "");
  if (!/^[A-Za-z0-9]{1,256}$/.test(cid) || profile?.avatar_media?.cid !== cid) return "";
  const expected = "/v1/media/proxy/" + cid;
  return profile.avatar_media.fetch_path === expected ? expected : "";
}
