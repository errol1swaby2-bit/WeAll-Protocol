import React, { useEffect, useMemo, useState } from "react";

import { api, getApiBaseUrl, weall } from "../api/weall";
import ErrorBanner from "../components/ErrorBanner";
import { getAuthHeaders, getKeypair, getSession, submitSignedTx } from "../auth/session";
import { normalizeAccount } from "../auth/keys";
import { checkGates, summarizeAccountState } from "../lib/gates";
import { nav, navWithReturn } from "../lib/router";
import { useAccount } from "../context/AccountContext";
import { useTxQueue } from "../hooks/useTxQueue";
import { useMutationRefresh } from "../hooks/useMutationRefresh";
import { useSignerSubmissionBusy } from "../hooks/useSignerSubmissionBusy";
import { reconcileMembershipPending, reconcileMembershipState } from "../lib/groupsRevalidation";
import { refreshMutationSlices, requestGlobalRefresh } from "../lib/revalidation";
import { actionableTxError, txPendingKey } from "../lib/txAction";

function prettyErr(e: any): { msg: string; details: any } {
  if (!e) return null as any;
  return actionableTxError(e, "Group action failed.");
}

type MembershipStatus = {
  ok?: boolean;
  group_id?: string;
  account?: string | null;
  phase?: string;
  is_member?: boolean;
  is_pending?: boolean;
  group_exists?: boolean;
  visibility?: string;
};

function shouldFallbackDirectMembershipSubmit(e: any): boolean {
  const status = Number(e?.status || e?.payload?.status || e?.body?.status || 0);
  const msg = String(e?.message || e?.payload?.message || e?.body?.message || e?.payload || "").toLowerCase();
  return status >= 500 || msg.includes("internal server error") || msg.includes("unexpected error");
}

export default function Group({ groupId }: { groupId?: string }): JSX.Element {
  const base = useMemo(() => getApiBaseUrl(), []);
  const selected = String(groupId || "").trim();
  const [detail, setDetail] = useState<any | null>(null);
  const [members, setMembers] = useState<any[]>([]);
  const [groupPosts, setGroupPosts] = useState<any[]>([]);
  const [membershipStatus, setMembershipStatus] = useState<MembershipStatus | null>(null);
  const [acctState, setAcctState] = useState<any | null>(null);
  const [err, setErr] = useState<{ msg: string; details: any } | null>(null);
  const [busy, setBusy] = useState<boolean>(false);

  const session = getSession();
  const acct = session ? normalizeAccount(session.account) : null;
  const kp = acct ? getKeypair(acct) : null;
  const canSign = !!kp?.secretKeyB64;
  const tx = useTxQueue();
  const signerSubmission = useSignerSubmissionBusy(acct);
  const { refresh: refreshAccountContext } = useAccount();

  const membershipGate = useMemo(
    () => checkGates({ loggedIn: !!acct, canSign, accountState: acctState, requireTier: 2 }),
    [acct, canSign, acctState],
  );
  const accountSummary = acctState ? summarizeAccountState(acctState) : "(state unknown)";
  const currentGroupRoute = selected ? `/groups/${encodeURIComponent(selected)}` : "/groups";

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

  async function loadMembershipStatus(): Promise<void> {
    if (!selected || !acct) {
      setMembershipStatus(null);
      return;
    }
    try {
      const headers = getAuthHeaders(acct);
      const r: any = await api.groups.membership(selected, base, headers);
      setMembershipStatus(r || null);
    } catch {
      setMembershipStatus(null);
    }
  }

  async function refreshSelected(): Promise<void> {
    if (!selected) {
      setDetail(null);
      setMembers([]);
      setGroupPosts([]);
      setMembershipStatus(null);
      return;
    }

    setErr(null);
    try {
      const d: any = await api.groups.get(selected, base);
      setDetail(d?.group || d || null);

      const m: any = await api.groups.members(selected, base).catch(() => ({ members: [] }));
      setMembers(Array.isArray(m?.members) ? m.members : []);
      const feedHeaders = acct ? getAuthHeaders(acct) : undefined;
      const feedRes: any = await weall.groupFeed(selected, { limit: 6 }, base, feedHeaders).catch(() => ({ items: [] }));
      setGroupPosts(Array.isArray(feedRes?.items) ? feedRes.items.slice(0, 6) : []);
      await loadMembershipStatus();
    } catch (e: any) {
      setErr(prettyErr(e));
      setDetail(null);
      setMembers([]);
      setGroupPosts([]);
      setMembershipStatus(null);
    }
  }

  useMutationRefresh({
    entityTypes: ["group"],
    entityIds: [selected],
    account: acct,
    onRefresh: async () => {
      await refreshSelected();
      await loadAccountState();
      await refreshAccountContext();
    },
  });

  useEffect(() => {
    void Promise.allSettled([refreshSelected(), loadAccountState(), refreshAccountContext()]);
  }, [selected, acct, refreshAccountContext]);

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
      let skeletonTx: any = null;
      try {
        const skel: any =
          kind === "join"
            ? await api.groups.join({ group_id: selected, message: "" }, base, headers)
            : await api.groups.leave({ group_id: selected }, base, headers);
        skeletonTx = skel?.tx;
        if (!skel || skel.ok !== true || !skeletonTx?.tx_type) throw skel;
      } catch (e: any) {
        if (!(kind === "join" && shouldFallbackDirectMembershipSubmit(e))) throw e;
        skeletonTx = {
          tx_type: "GROUP_MEMBERSHIP_REQUEST",
          parent: null,
          payload: { group_id: selected },
        };
      }

      const joinWillAutoAccept = kind === "join" && !detailIsPrivate;

      await tx.runTx({
        title: kind === "join" ? "Join group" : "Leave group",
        pendingKey: txPendingKey(["group-membership", kind, selected, acct]),
        pendingMessage: kind === "join" ? (joinWillAutoAccept ? "Joining group…" : "Submitting membership request…") : "Leaving group…",
        successMessage: kind === "join" ? (joinWillAutoAccept ? "Joined group." : "Membership request submitted.") : "Left group.",
        errorMessage: (e) => prettyErr(e).msg,
        getTxId: (res: any) => res?.result?.tx_id,
        finality: {
          timeoutMs: 16000,
          mutation: { entityType: "group", entityId: selected, account: acct || undefined, routeHint: `/groups/${encodeURIComponent(selected)}`, txType: String(skeletonTx.tx_type) },
          reconcile: async () => {
            if (kind === "join" && detailIsPrivate) {
              return reconcileMembershipPending({ groupId: selected, account: acct, base });
            }
            return reconcileMembershipState({
              groupId: selected,
              account: acct,
              expectMember: kind === "join",
              base,
            });
          },
        },
        task: async () =>
          submitSignedTx({
            account: acct,
            tx_type: String(skeletonTx.tx_type),
            payload: skeletonTx.payload ?? {},
            parent: skeletonTx.parent ?? null,
            base,
          }),
      });

      await refreshMutationSlices(
        refreshSelected,
        loadMembershipStatus,
        refreshAccountContext,
      );
      requestGlobalRefresh({ reason: "group-membership-updated", scopes: ["account", "pending_work", "route"] });
    } catch (e: any) {
      setErr(prettyErr(e));
    } finally {
      setBusy(false);
    }
  }

  const detailCharterText = typeof detail?.charter === "string" ? detail.charter.trim() : "";
  const detailCharterParts = detailCharterText
    ? detailCharterText.split(/\n{2,}|\r\n\r\n/).map((part: string) => part.trim()).filter(Boolean)
    : [];
  const detailName = String(
    detail?.charter?.name || detail?.meta?.name || detail?.name || detailCharterParts[0] || selected || "Group",
  );
  const detailDescription = String(
    detail?.charter?.description || detail?.meta?.description || detail?.description || detailCharterParts.slice(1).join("\n\n") || "",
  );
  const detailVisibility = String(
    detail?.visibility ||
      detail?.privacy ||
      detail?.meta?.visibility ||
      detail?.meta?.privacy ||
      "public",
  ).toLowerCase();
  const detailIsPrivate = ["private", "closed", "members"].includes(detailVisibility);
  const membershipPhase = String(membershipStatus?.phase || "").trim().toLowerCase();
  const isPendingMembership = membershipPhase === "pending";
  const isMember =
    (!!acct && !!membershipStatus?.is_member) ||
    (!!acct && members.some((m: any) => String(m?.account || "").toLowerCase() === String(acct).toLowerCase()));

  return (
    <div className="pageStack groupDetailPage">
      <section className="card heroCard">
        <div className="cardBody heroBody compactHero">
          <div className="heroSplit">
            <div>
              <div className="eyebrow">Group detail</div>
              <h1 className="heroTitle heroTitleSm">{detailName}</h1>
              <p className="heroText">
                This route owns membership state, scoped activity, and direct navigation for the selected group. The directory stays separate,
                so this page can focus on one object and one primary action.
              </p>
            </div>

            <div className="heroInfoPanel">
              <div className="heroInfoTitle">Current posture</div>
              <div className="heroInfoList">
                <span className="statusPill mono">{selected || "No group id"}</span>
                <span className="statusPill">{detailIsPrivate ? "Private" : "Public"}</span>
                <span className={`statusPill ${membershipGate.ok ? "ok" : ""}`}>
                  {membershipGate.ok ? "Membership unlocked" : "Membership requires Tier 2"}
                </span>
                <span className="statusPill">{accountSummary}</span>
              </div>
            </div>
          </div>

          <div className="statsGrid statsGridCompact">
            <div className="statCard">
              <span className="statLabel">Known members</span>
              <span className="statValue">{members.length}</span>
            </div>
            <div className="statCard">
              <span className="statLabel">Your membership</span>
              <span className="statValue">{acct ? (isMember ? "Member" : isPendingMembership ? "Pending" : "Not a member") : "Read-only"}</span>
            </div>
            <div className="statCard">
              <span className="statLabel">Visibility</span>
              <span className="statValue">{detailIsPrivate ? "Private" : "Public"}</span>
            </div>
            <div className="statCard">
              <span className="statLabel">Preview posts</span>
              <span className="statValue">{groupPosts.length}</span>
            </div>
          </div>
        </div>
      </section>

      <section className="surfaceBoundaryBar" aria-label="Group detail route contract">
        <div className="surfaceBoundaryHeader">
          <div>
            <h2 className="surfaceBoundaryTitle">Group detail stays single-purpose</h2>
            <p className="surfaceBoundaryText">
              This route owns one group, one membership posture, and one scoped next step. Discovery stays on the hub, while this page only carries a small activity preview instead of turning into a second mixed feed.
            </p>
          </div>
          <div className="statusSummary">
            <button className="btn" onClick={() => nav("/groups")}>Return to groups hub</button>
          </div>
        </div>
        <div className="surfaceBoundaryList">
          <span className="surfaceBoundaryTag">Primary object: selected group</span>
          <span className="surfaceBoundaryTag">Primary action: {isMember ? "Leave group" : isPendingMembership ? "Await membership decision" : detailIsPrivate ? "Request membership" : "Join group"}</span>
          <span className="surfaceBoundaryTag">Scoped posting: action-routed</span>
        </div>
      </section>

      <section className="detailFocusStrip" aria-label="Group detail posture">
        <article className="detailFocusCard">
          <div className="detailFocusLabel">Membership state</div>
          <div className="detailFocusValue">{acct ? (isMember ? "Member" : isPendingMembership ? "Pending" : "Not a member") : "Read-only"}</div>
          <div className="detailFocusText">
            {!acct || !canSign
              ? "Recover the current session on this device before attempting a signer-gated group action."
              : isPendingMembership
                ? "Your request is already recorded. Stay on this route while authoritative group state catches up."
                : isMember
                  ? "You already have member posture for this group. Scoped posting stays available through the dedicated post action route."
                  : detailIsPrivate
                    ? "This group requires a membership request before private activity unlocks."
                    : "This public group can be joined directly from this route."}
          </div>
        </article>
        <article className="detailFocusCard">
          <div className="detailFocusLabel">Visibility contract</div>
          <div className="detailFocusValue">{detailIsPrivate ? "Private" : "Public"}</div>
          <div className="detailFocusText">
            Private groups keep membership and posting gated. Public groups allow direct entry without moving creation controls into the directory feed.
          </div>
        </article>
        <article className="detailFocusCard">
          <div className="detailFocusLabel">Next step</div>
          <div className="detailFocusValue">{selected && acct && (isMember || !detailIsPrivate) ? "Open scoped posting action" : !acct || !canSign ? "Recover session" : isPendingMembership ? "Await review" : "Complete membership action"}</div>
          <div className="detailFocusText">
            The next action stays explicit so this page remains object-first instead of becoming another hub with mixed controls.
          </div>
        </article>
      </section>

      {signerSubmission.busy ? (
        <div className="calloutInfo">
          Another signed action for {acct || "this account"} is still settling. Group membership actions wait for the signer lane to clear so nonces stay ordered.
        </div>
      ) : null}

      <ErrorBanner
        message={err?.msg}
        details={err?.details}
        onRetry={() => void refreshMutationSlices(refreshSelected, loadAccountState, refreshAccountContext)}
        onDismiss={() => setErr(null)}
      />

      <section className="card">
        <div className="cardBody formStack">
          <div className="sectionHead">
            <div>
              <div className="eyebrow">Charter</div>
              <h2 className="cardTitle">About this group</h2>
              <div className="cardDesc">Membership actions submit protocol transactions. This page keeps those actions narrow and leaves broader group administration for future dedicated surfaces instead of turning detail into a second hub.</div>
            </div>
            <div className="statusSummary">
              <button className="btn" onClick={() => nav("/groups")}>Back to groups</button>
            </div>
          </div>

          {detailDescription ? <div className="feedBodyText">{detailDescription}</div> : <div className="cardDesc">No description provided.</div>}

          <div className="buttonRow buttonRowWide">
            {selected ? (
              <button
                className="btn btnPrimary"
                onClick={() => {
                  if (!acct || !canSign) {
                    navWithReturn(acct ? "/session" : "/login", currentGroupRoute);
                    return;
                  }
                  void joinOrLeave(isMember ? "leave" : "join");
                }}
                disabled={busy || signerSubmission.busy || (!!acct && !!canSign && (!membershipGate.ok || isPendingMembership))}
              >
                {!acct || !canSign
                  ? "Restore session to join"
                  : busy
                  ? "Working…"
                  : signerSubmission.busy
                    ? "Waiting for signer…"
                    : isMember
                      ? "Leave group"
                      : isPendingMembership
                        ? "Membership pending"
                        : detailIsPrivate
                          ? "Request membership"
                          : "Join group"}
              </button>
            ) : null}
          </div>

          {isPendingMembership ? (
            <div className="calloutInfo">
              Your membership request is already pending on the authoritative group state. This detail page stays on the group route instead of bouncing you away while the request settles.
            </div>
          ) : null}

          {!acct || !canSign ? (
            <div className="calloutInfo">
              This group page stays in place even when the signer or browser session is missing. Recover locally, then return here and continue the membership flow.
            </div>
          ) : null}

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

      <section className="card">
        <div className="cardBody formStack">
          <div className="sectionHead">
            <div>
              <div className="eyebrow">Activity</div>
              <h3 className="cardTitle">Group activity preview</h3>
            </div>
          </div>
          <div className="cardDesc">This is a preview slice, not a second full feed. Open a post for deeper inspection. New group posts stay on the dedicated post action route.</div>
          {groupPosts.length ? (
            <div className="pageStack">
              {groupPosts.map((post: any) => {
                const pid = String(post?.post_id || post?.id || "").trim();
                return (
                  <button key={pid} className="quickCard" onClick={() => nav(`/content/${encodeURIComponent(pid)}`)}>
                    <span>
                      <strong>{String(post?.body || "Untitled post").slice(0, 100) || pid}</strong>
                      <small>{String(post?.author || "unknown")} · {String(post?.visibility || "public")}</small>
                    </span>
                  </button>
                );
              })}
            </div>
          ) : (
            <div className="cardDesc">No posts in this group yet. Scoped posting remains available through the dedicated post action route once membership posture allows it.</div>
          )}
        </div>
      </section>
    </div>
  );
}
