import React, { useEffect, useState } from "react";

import { weall } from "../api/weall";
import { useMutationRefresh } from "../hooks/useMutationRefresh";
import { canonicalAvatarPath } from "../lib/accountAvatar";

const TTL_MS = 60_000;
const MAX_ENTRIES = 256;
type AvatarEntry = { expires: number; pending: boolean; promise: Promise<string> };
const avatars = new Map<string, AvatarEntry>();

function loadAvatar(base: string, account: string, force = false): Promise<string> {
  const key = JSON.stringify([base, account]);
  const prior = avatars.get(key);
  if (prior && (prior.pending || (!force && prior.expires > Date.now()))) return prior.promise;
  const entry: AvatarEntry = { expires: 0, pending: true, promise: Promise.resolve("") };
  entry.promise = weall.accountProfile(account, base)
    .then(response => canonicalAvatarPath(response, account))
    .catch(() => "")
    .then(path => { entry.pending = false; entry.expires = Date.now() + TTL_MS; return path; });
  avatars.delete(key);
  avatars.set(key, entry);
  while (avatars.size > MAX_ENTRIES) avatars.delete(avatars.keys().next().value!);
  return entry.promise;
}

export default function AccountIdentity({ base, account, fallback = "Unknown account" }: { base: string; account: string; fallback?: string }): JSX.Element {
  const label = String(account || "").trim();
  const handle = /^@[a-z0-9_.-]+$/i.test(label) ? label.toLowerCase() : "";
  const key = JSON.stringify([base, handle]);
  const [resolved, setResolved] = useState<{ key: string; path: string } | null>(null);
  const [brokenUrl, setBrokenUrl] = useState("");
  const [revision, setRevision] = useState(0);
  useMutationRefresh({
    entityTypes: ["account"],
    entityIds: handle ? [handle] : ["__no_account__"],
    onRefresh: (signal) => {
      if (signal.txType === "PROFILE_UPDATE" && signal.status === "confirmed") setRevision(value => value + 1);
    },
  });
  useEffect(() => {
    let active = true;
    if (!handle) return;
    void loadAvatar(base, handle, revision > 0).then(path => {
      if (active) { setResolved({ key, path }); setBrokenUrl(""); }
    });
    return () => { active = false; };
  }, [base, handle, key, revision]);
  if (!handle) return <span>{label || fallback}</span>;
  const path = resolved?.key === key ? resolved.path : "";
  const url = path ? base.replace(/\/+$/, "") + path : "";
  const thumbnailStyle: React.CSSProperties = { width: "1.55rem", height: "1.55rem", borderRadius: "50%", flex: "0 0 1.55rem", objectFit: "cover" };
  return (
    <a href={`#/account/${encodeURIComponent(handle)}`} className="accountIdentity" data-testid="account-identity"
      style={{ display: "inline-flex", alignItems: "center", gap: "0.4rem", maxWidth: "100%", verticalAlign: "middle" }}>
      {url && brokenUrl !== url ? <img src={url} alt="" loading="lazy" decoding="async" referrerPolicy="no-referrer" style={thumbnailStyle} onError={() => setBrokenUrl(url)} /> :
        <span aria-hidden="true" style={{ ...thumbnailStyle, display: "inline-grid", placeItems: "center", background: "rgba(128,128,128,.22)", fontSize: "0.8rem" }}>{handle.slice(1, 2).toUpperCase()}</span>}
      <span className="mono" style={{ overflowWrap: "anywhere" }}>{handle}</span>
    </a>
  );
}
