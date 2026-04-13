import React, { useEffect, useMemo, useState } from "react";

import { api, getApiBaseUrl } from "../api/weall";
import ErrorBanner from "../components/ErrorBanner";
import { getAuthHeaders, getKeypair, getSession, submitSignedTx } from "../auth/session";
import { normalizeAccount } from "../auth/keys";
import { checkGates, summarizeAccountState } from "../lib/gates";
import { nav } from "../lib/router";
import { useAccount } from "../context/AccountContext";
import { useTxQueue } from "../hooks/useTxQueue";

function prettyErr(e: any): { msg: string; details: any } {
  const details = e?.body || e?.data || e;
  const msg = details?.message || e?.error?.message || e?.message || "error";
  return { msg, details };
}

function slugifyGroupId(s: string): string {
  const raw = String(s || "").trim().toLowerCase();
  const slug = raw
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+/, "")
    .replace(/-+$/, "")
    .slice(0, 40);
  return `g:${slug || "group"}`;
}

type GroupListItem = {
  id: string;
  name: string;
  description: string;
  isPrivate: boolean;
  memberCountHint: number | null;
  raw: any;
};

function mapGroup(obj: any): GroupListItem {
  const id = String(obj?.group_id || obj?.id || "").trim();
  const charter = obj?.charter && typeof obj.charter === "object" ? obj.charter : null;
  const meta = obj?.meta && typeof obj.meta === "object" ? obj.meta : null;
  const roles = obj?.roles && typeof obj.roles === "object" ? obj.roles : null;
  const members = obj?.members && typeof obj.members === "object" ? obj.members : roles?.members;
  const name = String(charter?.name || meta?.name || obj?.name || id);
  const description = String(charter?.description || meta?.description || obj?.description || "");
  const visibility = String(
    obj?.visibility || obj?.privacy || meta?.visibility || meta?.privacy || "public",
  ).toLowerCase();

  return {
    id,
    name: name || id,
    description: description || "",
    isPrivate: ["private", "closed", "members"].includes(visibility),
    memberCountHint: members && typeof members === "object" ? Object.keys(members).length : null,
    raw: obj,
  };
}

export default function Groups(props: { groupId?: string }): JSX.Element {
  const base = useMemo(() => getApiBaseUrl(), []);
  const initialGroupId = props.groupId ?? "";

  const [groups, setGroups] = useState<GroupListItem[]>([]);
  const [selected, setSelected] = useState<string>(initialGroupId);
  const [detail, setDetail] = useState<any | null>(null);
  const [members, setMembers] = useState<any[]>([]);
  const [createName, setCreateName] = useState<string>("");
  const [createDesc, setCreateDesc] = useState<string>("");
  const [err, setErr] = useState<{ msg: string; details: any } | null>(null);
  const [busy, setBusy] = useState<boolean>(false);

  const session = getSession();
  const acct = session ? normalizeAccount(session.account) : null;
  const kp = acct ? getKeypair(acct) : null;
  const canSign = !!kp?.secretKeyB64;
  const [acctState, setAcctState] = useState<any | null>(null);
  const { refresh: refreshAccountContext } = useAccount();
  const tx = useTxQueue();

  const createGate = useMemo(
    () => checkGates({ loggedIn: !!acct, canSign, accountState: acctState, requireTier: 3 }),
    [acct, canSign, acctState],
  );
  const membershipGate = useMemo(
    () => checkGates({ loggedIn: !!acct, canSign, accountState: acctState, requireTier: 2 }),
    [acct, canSign, acctState],
  );

  const selectedItem = useMemo(() => groups.find((g) => g.id === selected) || null, [groups, selected]);
  const accountSummary = acctState ? summarizeAccountState(acctState) : "(state unknown)";

  async function loadAccountState(): Promise<void> {
    if (!acct) {
      setAcctState(null);
      return;
    }
    try {
      const r: any = await api.account(acct, base);
      setAcctState(r?.account?.state ?? r?.state ?? r?.account_state ?? null);
    } catch {
      setAcctState(null);
    }
  }

  async function refreshGroups(): Promise<void> {
    setErr(null);
    try {
      const r: any = await api.groups.list({ limit: 250 }, base);
      const raw = Array.isArray(r?.items) ? r.items : [];
      const mapped = raw.map(mapGroup).filter((g: GroupListItem) => !!g.id);
      setGroups(mapped);

      if (props.groupId) {
        setSelected(props.groupId);
      } else if (!selected && mapped.length) {
        setSelected(mapped[0].id);
      }
    } catch (e: any) {
      setErr(prettyErr(e));
      setGroups([]);
    }
  }

  async function refreshSelected(id: string): Promise<void> {
    if (!id) {
      setDetail(null);
      setMembers([]);
      return;
    }

    setErr(null);
    try {
      const d: any = await api.groups.get(id, base);
      setDetail(d?.group || d || null);

      const m: any = await api.groups.members(id, base).catch(() => ({ members: [] }));
      setMembers(Array.isArray(m?.members) ? m.members : []);
    } catch (e: any) {
      setErr(prettyErr(e));
      setDetail(null);
      setMembers([]);
    }
  }

  useEffect(() => {
    void refreshGroups();
    void loadAccountState();
  }, []);

  useEffect(() => {
    if (props.groupId && props.groupId !== selected) setSelected(props.groupId);
  }, [props.groupId, selected]);

  useEffect(() => {
    if (selected) void refreshSelected(selected);
  }, [selected]);

  async function createGroup(): Promise<void> {
    setErr(null);

    const name = createName.trim();
    const description = createDesc.trim();

    if (!name) {
      setErr({ msg: "Group name is required.", details: null });
      return;
    }
    if (!acct || !canSign) {
      setErr({
        msg: "You are not logged in on this device.",
        details: "Restore your device signer in Settings or PoH first.",
      });
      return;
    }
    if (!createGate.ok) {
      setErr({ msg: createGate.reason || "gated", details: acctState });
      return;
    }

    setBusy(true);
    try {
      const group_id = slugifyGroupId(name);

      await tx.runTx({
        title: "Create group",
        pendingMessage: "Submitting group creation…",
        successMessage: "Group created.",
        errorMessage: (e) => prettyErr(e).msg,
        getTxId: (res: any) => res?.result?.tx_id,
        task: async () =>
          submitSignedTx({
            account: acct,
            tx_type: "GROUP_CREATE",
            payload: {
              group_id,
              charter: {
                name,
                description: description || null,
              },
            },
            parent: null,
            base,
          }),
      });

      setCreateName("");
      setCreateDesc("");
      await refreshGroups();
      setSelected(group_id);
      await refreshSelected(group_id);
      await refreshAccountContext();
    } catch (e: any) {
      setErr(prettyErr(e));
    } finally {
      setBusy(false);
    }
  }

  async function joinOrLeave(kind: "join" | "leave"): Promise<void> {
    if (!selected) return;

    setErr(null);

    if (!acct || !canSign) {
      setErr({
        msg: "You are not logged in on this device.",
        details: "Restore your device signer in Settings or PoH first.",
      });
      return;
    }
    if (!membershipGate.ok) {
      setErr({ msg: membershipGate.reason || "gated", details: acctState });
      return;
    }

    setBusy(true);
    try {
      const headers = getAuthHeaders(acct);
      const skel: any =
        kind === "join"
          ? await api.groups.join({ group_id: selected }, base, headers)
          : await api.groups.leave({ group_id: selected }, base, headers);

      const skeletonTx = skel?.tx;
      if (!skel || skel.ok !== true || !skeletonTx?.tx_type) throw skel;

      await tx.runTx({
        title: kind === "join" ? "Join group" : "Leave group",
        pendingMessage: kind === "join" ? "Joining group…" : "Leaving group…",
        successMessage: kind === "join" ? "Joined group." : "Left group.",
        errorMessage: (e) => prettyErr(e).msg,
        getTxId: (res: any) => res?.result?.tx_id,
        task: async () =>
          submitSignedTx({
            account: acct,
            tx_type: String(skeletonTx.tx_type),
            payload: skeletonTx.payload ?? {},
            parent: skeletonTx.parent ?? null,
            base,
          }),
      });

      await refreshSelected(selected);
      await refreshGroups();
      await refreshAccountContext();
    } catch (e: any) {
      setErr(prettyErr(e));
    } finally {
      setBusy(false);
    }
  }

  const detailName = String(
    detail?.charter?.name || detail?.meta?.name || detail?.name || selectedItem?.name || "No group selected",
  );
  const detailDescription = String(
    detail?.charter?.description || detail?.meta?.description || detail?.description || "",
  );
  const detailVisibility = String(
    detail?.visibility ||
      detail?.privacy ||
      detail?.meta?.visibility ||
      detail?.meta?.privacy ||
      (selectedItem?.isPrivate ? "private" : "public"),
  ).toLowerCase();
  const detailIsPrivate = ["private", "closed", "members"].includes(detailVisibility);
  const isMember =
    !!acct &&
    members.some((m: any) => String(m?.account || "").toLowerCase() === String(acct).toLowerCase());

  return (
    <div className="pageStack">
      <section className="card heroCard">
        <div className="cardBody heroBody compactHero">
          <div className="heroSplit">
            <div>
              <div className="eyebrow">Groups</div>
              <h1 className="heroTitle heroTitleSm">Explore and form working circles</h1>
              <p className="heroText">
                Groups let members organize around a charter, membership, and shared public output.
                This page keeps discovery, creation, and membership actions in one place while separating what any reader can inspect from what a signed, eligible account can actually submit.
              </p>
            </div>

            <div className="heroInfoPanel">
              <div className="heroInfoTitle">Participation rules</div>
              <div className="heroInfoList">
                <span className={`statusPill ${createGate.ok ? "ok" : ""}`}>
                  {createGate.ok ? "Create unlocked" : "Create requires Tier 3"}
                </span>
                <span className={`statusPill ${membershipGate.ok ? "ok" : ""}`}>{membershipGate.ok ? "Membership unlocked" : "Membership requires Tier 2"}</span>
                <span className="statusPill">{accountSummary}</span>
                <span className="statusPill mono">{acct || "Read-only"}</span>
              </div>
            </div>
          </div>

          <div className="statsGrid statsGridCompact">
            <div className="statCard">
              <span className="statLabel">Visible groups</span>
              <span className="statValue">{groups.length}</span>
            </div>
            <div className="statCard">
              <span className="statLabel">Selected</span>
              <span className="statValue">{selectedItem?.name || selected || "None"}</span>
            </div>
            <div className="statCard">
              <span className="statLabel">Members listed</span>
              <span className="statValue">{members.length}</span>
            </div>
            <div className="statCard">
              <span className="statLabel">Membership gate</span>
              <span className="statValue">{membershipGate.ok ? "Tier 2+ ready" : "Tier 2 required"}</span>
            </div>
          </div>
        </div>
      </section>

      <ErrorBanner
        message={err?.msg}
        details={err?.details}
        onRetry={() => {
          void refreshGroups();
          void loadAccountState();
          if (selected) void refreshSelected(selected);
        }}
        onDismiss={() => setErr(null)}
      />

      <section className="summaryCardGrid">
        <article className="summaryCard">
          <div className="summaryCardLabel">Public vs governed</div>
          <div className="summaryCardValue">Groups are more than chat rooms</div>
          <div className="summaryCardText">Readers can inspect charters and membership signals, but the protocol also supports moderators, signers, emissaries, and treasury-linked actions that should remain legible as the surface expands.</div>
        </article>
        <article className="summaryCard">
          <div className="summaryCardLabel">Alignment fix</div>
          <div className="summaryCardValue">Join uses Tier 2+, create uses Tier 3+</div>
          <div className="summaryCardText">Membership request and group creation do not share the same gate. This surface now reflects the stricter split instead of collapsing them into one requirement.</div>
        </article>
      </section>

      <section className="grid2">
        <article className="card">
          <div className="cardBody formStack">
            <div className="sectionHead">
              <div>
                <div className="eyebrow">Directory</div>
                <h2 className="cardTitle">Available groups</h2>
              </div>
              <div className="statusSummary">
                <button className="btn" onClick={() => void refreshGroups()}>
                  Refresh
                </button>
              </div>
            </div>

            {groups.length === 0 ? (
              <div className="cardDesc">No groups returned yet.</div>
            ) : (
              <div className="pageStack">
                {groups.map((g) => (
                  <button
                    key={g.id}
                    className={`quickCard ${selected === g.id ? "quickCardActive" : ""}`}
                    onClick={() => setSelected(g.id)}
                  >
                    <span>
                      <strong>{g.name}</strong>
                      <small>
                        {g.id} · {g.isPrivate ? "private" : "public"}
                        {g.memberCountHint != null ? ` · ${g.memberCountHint} member(s)` : ""}
                      </small>
                    </span>
                  </button>
                ))}
              </div>
            )}
          </div>
        </article>

        <article className="card">
          <div className="cardBody formStack">
            <div className="sectionHead">
              <div>
                <div className="eyebrow">Create</div>
                <h2 className="cardTitle">Start a new group</h2>
              <div className="cardDesc">Creating a group is a higher-trust action than requesting membership. This form remains explicit about that distinction.</div>
              </div>
            </div>

            {!createGate.ok ? <div className="inlineError">Gated: {createGate.reason}</div> : null}

            <label className="fieldLabel">
              Name
              <input value={createName} onChange={(e) => setCreateName(e.target.value)} placeholder="Community builders" />
            </label>

            <label className="fieldLabel">
              Description
              <textarea
                value={createDesc}
                onChange={(e) => setCreateDesc(e.target.value)}
                rows={6}
                placeholder="Describe the purpose and scope of the group."
              />
            </label>

            <div className="feedMediaCard">
              <div className="feedMediaTitle">Preview group id</div>
              <div className="feedMediaMeta mono">{slugifyGroupId(createName || "group")}</div>
            </div>

            <div className="buttonRow">
              <button className="btn btnPrimary" onClick={() => void createGroup()} disabled={busy}>
                {busy ? "Creating…" : "Create group"}
              </button>
            </div>
          </div>
        </article>
      </section>

      <section className="card">
        <div className="cardBody formStack">
          <div className="sectionHead">
            <div>
              <div className="eyebrow">Selected group</div>
              <h2 className="cardTitle">{detailName}</h2>
              <div className="cardDesc">Membership actions submit protocol transactions. Group governance, moderator roles, and signer-controlled operations can expand from this same base surface over time.</div>
            </div>
            <div className="statusSummary">
              {selected ? <span className="statusPill mono">{selected}</span> : null}
              <span className="statusPill">{detailIsPrivate ? "Private" : "Public"}</span>
            </div>
          </div>

          {detailDescription ? (
            <div className="feedBodyText">{detailDescription}</div>
          ) : (
            <div className="cardDesc">No description provided.</div>
          )}

          <div className="buttonRow buttonRowWide">
            {selected ? (
              <button className="btn" onClick={() => nav(`/group/${encodeURIComponent(selected)}`)}>
                Open full group page
              </button>
            ) : null}
            {selected && acct ? (
              <button
                className="btn btnPrimary"
                onClick={() => void joinOrLeave(isMember ? "leave" : "join")}
                disabled={busy || !membershipGate.ok}
              >
                {busy ? "Working…" : isMember ? "Leave group" : "Request / join group"}
              </button>
            ) : null}
          </div>

          <div className="statsGrid statsGridCompact">
            <div className="statCard">
              <span className="statLabel">Known members</span>
              <span className="statValue">{members.length}</span>
            </div>
            <div className="statCard">
              <span className="statLabel">Your membership</span>
              <span className="statValue">{acct ? (isMember ? "Member" : "Not a member") : "Read-only"}</span>
            </div>
          </div>

          {members.length ? (
            <div className="milestoneList">
              {members.map((m: any, idx) => (
                <span key={`${String(m?.account || idx)}`} className="miniTag">
                  {String(m?.account || "member")}
                </span>
              ))}
            </div>
          ) : (
            <div className="cardDesc">No member list returned yet.</div>
          )}
        </div>
      </section>
    </div>
  );
}
