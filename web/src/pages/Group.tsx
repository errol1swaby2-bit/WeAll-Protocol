import React, { useEffect, useMemo, useState } from "react";

import { api, getApiBaseUrl, weall, type GroupGovernanceContract } from "../api/weall";
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
  const [governanceContract, setGovernanceContract] = useState<GroupGovernanceContract | null>(null);
  const [acctState, setAcctState] = useState<any | null>(null);
  const [err, setErr] = useState<{ msg: string; details: any } | null>(null);
  const [busy, setBusy] = useState<boolean>(false);
  const [reportBusyId, setReportBusyId] = useState<string | null>(null);
  const [reportInfo, setReportInfo] = useState<{ msg: string; details?: any } | null>(null);

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
      setGovernanceContract(null);
    }
  }

  async function refreshSelected(): Promise<void> {
    if (!selected) {
      setDetail(null);
      setMembers([]);
      setGroupPosts([]);
      setMembershipStatus(null);
      setGovernanceContract(null);
      return;
    }

    setErr(null);
    try {
      const d: any = await api.groups.get(selected, base);
      setDetail(d?.group || d || null);

      const m: any = await api.groups.members(selected, base).catch(() => ({ members: [] }));
      setMembers(Array.isArray(m?.members) ? m.members : []);
      const contract: GroupGovernanceContract | null = await weall.groupGovernanceContract(selected, base).catch(() => null);
      setGovernanceContract(contract);
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
      setGovernanceContract(null);
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
        details: "Restore your device signer in Settings or Account Verification first.",
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

      await tx.runTx({
        title: kind === "join" ? "Join group" : "Leave group",
        pendingKey: txPendingKey(["group-membership", kind, selected, acct]),
        pendingMessage: kind === "join" ? "Joining group…" : "Leaving group…",
        successMessage: kind === "join" ? "Joined group." : "Left group.",
        errorMessage: (e) => prettyErr(e).msg,
        getTxId: (res: any) => res?.result?.tx_id,
        finality: {
          timeoutMs: 16000,
          mutation: { entityType: "group", entityId: selected, account: acct || undefined, routeHint: `/groups/${encodeURIComponent(selected)}`, txType: String(skeletonTx.tx_type) },
          reconcile: async () => reconcileMembershipState({
            groupId: selected,
            account: acct,
            expectMember: kind === "join",
            base,
          }),
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

  async function waitForGroupDispute(targetId: string, attempts = 8): Promise<any | null> {
    for (let i = 0; i < attempts; i += 1) {
      try {
        const headers = acct ? getAuthHeaders(acct) : undefined;
        const r: any = await weall.disputes({ targetId, limit: 5 }, base, headers);
        const items = Array.isArray(r?.items) ? r.items : [];
        const found = items.find((item: any) => String(item?.target_id || "") === String(targetId));
        if (found) return found;
      } catch {
        // keep polling; the observer/genesis read models can lag briefly.
      }
      await new Promise((resolve) => window.setTimeout(resolve, 300));
    }
    return null;
  }

  async function reportGroupPost(post: any): Promise<void> {
    const targetId = String(post?.post_id || post?.id || "").trim();
    if (!targetId) return;
    setErr(null);
    setReportInfo(null);
    if (!acct || !canSign) {
      setErr({ msg: "You are not logged in on this device.", details: "Restore your device signer before reporting group content." });
      return;
    }
    if (!membershipGate.ok) {
      setErr({ msg: membershipGate.reason || "Complete live verification before reporting group content.", details: acctState });
      return;
    }
    const reason = window.prompt("Why are you reporting this group post? (optional)", "") || "";
    setReportBusyId(targetId);
    try {
      await tx.runTx({
        title: "Report group content",
        pendingKey: txPendingKey(["group-content-flag", selected, targetId, acct]),
        pendingMessage: "Sending this group post for community review…",
        successMessage: "Report sent. Checking whether the review record is visible yet…",
        errorMessage: (e) => prettyErr(e).msg,
        getTxId: (res: any) => String(res?.tx_id || res?.result?.tx_id || "") || undefined,
        finality: {
          mutation: { entityType: "content", entityId: targetId, account: acct || undefined, routeHint: `/groups/${encodeURIComponent(selected)}`, txType: "CONTENT_FLAG" },
        },
        task: async () =>
          submitSignedTx({
            account: acct,
            tx_type: "CONTENT_FLAG",
            payload: reason.trim() ? { target_id: targetId, reason: reason.trim() } : { target_id: targetId },
            parent: null,
            base,
          }),
      });
      const dispute = await waitForGroupDispute(targetId);
      setReportInfo({
        msg: dispute?.id ? `Report sent for this group post. Review ${String(dispute.id)} is visible.` : "Report sent for this group post. Community review may take a moment to appear.",
        details: dispute || { target_id: targetId },
      });
      await refreshMutationSlices(refreshSelected, refreshAccountContext);
    } catch (e: any) {
      setErr(prettyErr(e));
    } finally {
      setReportBusyId(null);
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
  const membershipPhase = String(membershipStatus?.phase || "").trim().toLowerCase();
  const isPendingMembership = membershipPhase === "pending";
  const isMember =
    (!!acct && !!membershipStatus?.is_member) ||
    (!!acct && members.some((m: any) => String(m?.account || "").toLowerCase() === String(acct).toLowerCase()));
  const groupGovernanceModel = String(governanceContract?.governance_model || "protocol_governance_scaled_to_group_scope");
  const groupReadVisibility = String(governanceContract?.public_only_contract?.read_visibility || "public");
  const adminShortcutsSupported = governanceContract?.authority_contract?.admin_shortcuts_supported === true;
  const permissionSummary = governanceContract?.participation_permissions || {};
  const activeGroupElections = Array.isArray(governanceContract?.authority_contract?.active_group_elections)
    ? governanceContract?.authority_contract?.active_group_elections || []
    : [];
  const contractCounts = governanceContract?.counts || {};
  const signerThreshold = governanceContract?.authority_contract?.signer_threshold;
  const signerCount = governanceContract?.authority_contract?.signer_count;
  const moderatorCount = governanceContract?.authority_contract?.moderator_count;

  return (
    <div className="pageStack groupDetailPage">
      <section className="card heroCard">
        <div className="cardBody heroBody compactHero">
          <div className="heroSplit">
            <div>
              <div className="eyebrow">Group detail</div>
              <h1 className="heroTitle heroTitleSm">{detailName}</h1>
              <p className="heroText">
                Read the public group charter, inspect membership and governance posture, and use signed actions only for participation changes.
              </p>
            </div>

            <div className="heroInfoPanel">
              <div className="heroInfoTitle">Group status</div>
              <div className="heroInfoList">
                <span className="statusPill mono">{selected || "No group id"}</span>
                <span className="statusPill">Public reads · member-gated participation</span>
                <span className={`statusPill ${membershipGate.ok ? "ok" : ""}`}>
                  {membershipGate.ok ? "Can join" : "Complete verification to join"}
                </span>
                <span className="statusPill">{accountSummary}</span>
              </div>
            </div>
          </div>

          <div className="statsGrid statsGridCompact">
            <div className="statCard">
              <span className="statLabel">Members</span>
              <span className="statValue">{members.length}</span>
            </div>
            <div className="statCard">
              <span className="statLabel">Your membership</span>
              <span className="statValue">{acct ? (isMember ? "Member" : isPendingMembership ? "Pending" : "Not a member") : "Read-only"}</span>
            </div>
            <div className="statCard">
              <span className="statLabel">Read visibility</span>
              <span className="statValue">Public</span>
            </div>
            <div className="statCard">
              <span className="statLabel">Active elections</span>
              <span className="statValue">{Number(contractCounts.active_elections || activeGroupElections.length || 0)}</span>
            </div>
          </div>
        </div>
      </section>

      <section className="surfaceBoundaryBar" aria-label="Group detail route contract">
        <div className="surfaceBoundaryHeader">
          <div>
            <h2 className="surfaceBoundaryTitle">About this group</h2>
            <p className="surfaceBoundaryText">
              This page keeps the group description, membership action, and recent activity in one easy place.
            </p>
          </div>
          <div className="statusSummary">
            <button className="btn" onClick={() => nav("/groups")}>Back to groups</button>
          </div>
        </div>
        <div className="surfaceBoundaryList">
          <span className="surfaceBoundaryTag">Selected group</span>
          <span className="surfaceBoundaryTag">Action: {isMember ? "Leave group" : isPendingMembership ? "Await membership decision" : "Join group"}</span>
          <span className="surfaceBoundaryTag">Posting uses the create-post page</span>
        </div>
      </section>

      <section className="card" aria-label="Group governance contract">
        <div className="cardBody formStack">
          <div className="sectionHead">
            <div>
              <div className="eyebrow">Group governance contract</div>
              <h2 className="cardTitle">Protocol governance scaled to group scope</h2>
              <div className="cardDesc">
                This is a public derived read model. It does not grant authority; it explains how this group surface maps reads, membership, actions, emissary records, and audit trails.
              </div>
            </div>
          </div>
          <div className="surfaceBoundaryList">
            <span className="surfaceBoundaryTag">Model: {groupGovernanceModel.replace(/_/g, " ")}</span>
            <span className="surfaceBoundaryTag">Reads: {groupReadVisibility}</span>
            <span className="surfaceBoundaryTag">Signer threshold: {signerThreshold == null ? "not returned" : String(signerThreshold)}</span>
            <span className="surfaceBoundaryTag">Signers: {signerCount == null ? "not returned" : String(signerCount)}</span>
            <span className="surfaceBoundaryTag">Moderators: {moderatorCount == null ? "not returned" : String(moderatorCount)}</span>
            <span className="surfaceBoundaryTag">Admin shortcuts: {adminShortcutsSupported ? "unsupported contract violated" : "not exposed"}</span>
            <span className="surfaceBoundaryTag">Frontend cache authority: never</span>
          </div>
          <div className="detailFocusStrip actionFocusStrip">
            <article className="detailFocusCard">
              <div className="detailFocusLabel">Public-only rule</div>
              <div className="detailFocusValue">Read access is public</div>
              <div className="detailFocusText">Group membership may gate posting, commenting, voting, moderation, invitation, and administration, but not reading protocol-native group content.</div>
            </article>
            <article className="detailFocusCard">
              <div className="detailFocusLabel">Participation gates</div>
              <div className="detailFocusValue">{String(permissionSummary.post || "members")} posting</div>
              <div className="detailFocusText">Comment: {String(permissionSummary.comment || "members")} · Vote: {String(permissionSummary.vote || "members")} · Moderate: {String(permissionSummary.moderate || "moderators")}.</div>
            </article>
            <article className="detailFocusCard">
              <div className="detailFocusLabel">Audit trail</div>
              <div className="detailFocusValue">Receipts inspectable</div>
              <div className="detailFocusText">Membership changes are signed transactions; use transaction status and this group feed/members view to inspect the public result.</div>
            </article>
            <article className="detailFocusCard">
              <div className="detailFocusLabel">Emissary elections</div>
              <div className="detailFocusValue">Public candidate records</div>
              <div className="detailFocusText">Candidate lists, candidate votes, term activation, and term expiration must be public group-governance records; the UI should not present admin-only appointment as group authority.</div>
            </article>
          </div>
        </div>
      </section>

      <section className="card" aria-label="Group emissary election records">
        <div className="cardBody formStack">
          <div className="sectionHead">
            <div>
              <div className="eyebrow">Emissary election records</div>
              <h2 className="cardTitle">Public group-governance records</h2>
              <div className="cardDesc">
                Emissaries are seated through public group election records. Candidate lists, ballots/counts, winners, term activation, and term expiration must be inspectable when present in chain state.
              </div>
            </div>
            <div className="statusSummary">
              <button className="btn" onClick={() => nav("/transactions")}>Track related transactions</button>
            </div>
          </div>

          {activeGroupElections.length ? (
            <div className="milestoneList">
              {activeGroupElections.map((election: Record<string, unknown>, idx: number) => (
                <span key={String(election.election_id || idx)} className="miniTag">
                  {String(election.election_id || "election")} · {String(election.status || "open")} · {String(election.candidate_count ?? "?")} candidate(s)
                </span>
              ))}
            </div>
          ) : (
            <div className="cardDesc">No active emissary election records were returned for this group. That is an honest empty state, not an admin appointment path.</div>
          )}

          <div className="surfaceBoundaryList">
            <span className="surfaceBoundaryTag">Election creation: signed group tx</span>
            <span className="surfaceBoundaryTag">Ballots: public group-scope governance tx</span>
            <span className="surfaceBoundaryTag">Finalization: deterministic group outcome</span>
            <span className="surfaceBoundaryTag">Owner appointment path: unsupported</span>
          </div>
        </div>
      </section>

      <section className="detailFocusStrip" aria-label="Group detail posture">
        <article className="detailFocusCard">
          <div className="detailFocusLabel">Membership state</div>
          <div className="detailFocusValue">{acct ? (isMember ? "Member" : isPendingMembership ? "Pending" : "Not a member") : "Read-only"}</div>
          <div className="detailFocusText">
            {!acct || !canSign
              ? "Sign in or restore this device before joining or leaving groups."
              : isPendingMembership
                ? "Your membership request is already pending."
                : isMember
                  ? "You are a member of this group."
                  : "You can join this public group from here."}
          </div>
        </article>
        <article className="detailFocusCard">
          <div className="detailFocusLabel">Visibility</div>
          <div className="detailFocusValue">Public</div>
          <div className="detailFocusText">
            Group content and moderation activity are public. Membership can gate posting, commenting, voting, moderation, and administration only.
          </div>
        </article>
        <article className="detailFocusCard">
          <div className="detailFocusLabel">Next step</div>
          <div className="detailFocusValue">{selected && acct && isMember ? "Create a group post" : !acct || !canSign ? "Sign in" : isPendingMembership ? "Wait for approval" : "Join group"}</div>
          <div className="detailFocusText">
            Use the main button below for the next membership step.
          </div>
        </article>
      </section>

      {signerSubmission.busy ? (
        <div className="calloutInfo">
          Another action for {acct || "this account"} is still saving. Group membership actions will wait until it finishes.
        </div>
      ) : null}

      <ErrorBanner
        message={err?.msg}
        details={err?.details}
        onRetry={() => void refreshMutationSlices(refreshSelected, loadAccountState, refreshAccountContext)}
        onDismiss={() => setErr(null)}
      />

      {reportInfo ? (
        <section className="card">
          <div className="cardBody formStack">
            <div className="eyebrow">Report status</div>
            <h3 className="cardTitle">Group post report recorded</h3>
            <div className="cardDesc">{reportInfo.msg}</div>
            <div className="buttonRow buttonRowWide">
              <button className="btn" onClick={() => nav("/reports")}>Open reports</button>
              <button className="btn" onClick={() => setReportInfo(null)}>Dismiss</button>
            </div>
          </div>
        </section>
      ) : null}

      <section className="card">
        <div className="cardBody formStack">
          <div className="sectionHead">
            <div>
              <div className="eyebrow">Charter</div>
              <h2 className="cardTitle">About this group</h2>
              <div className="cardDesc">Read the group description, join if eligible, and see who is already here.</div>
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
              Sign in or restore this device, then return here to continue.
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
              <h3 className="cardTitle">Recent group activity</h3>
            </div>
          </div>
          <div className="cardDesc">Open a post to read the public replies. Use Create Post when you want to share something with this group. Posting is participation and may be member-gated; reading remains public.</div>
          {groupPosts.length ? (
            <div className="pageStack">
              {groupPosts.map((post: any) => {
                const pid = String(post?.post_id || post?.id || "").trim();
                return (
                  <div key={pid} className="quickCard quickCardSplit">
                    <button className="quickCardMain" onClick={() => nav(`/content/${encodeURIComponent(pid)}`)}>
                      <span>
                        <strong>{String(post?.body || "Untitled post").slice(0, 100) || pid}</strong>
                        <small>{String(post?.author || "unknown")} · {String(post?.visibility || "public")} · public group record</small>
                      </span>
                    </button>
                    <button
                      className="btn"
                      onClick={(event) => { event.stopPropagation(); void reportGroupPost(post); }}
                      disabled={!pid || reportBusyId === pid || signerSubmission.busy || !membershipGate.ok}
                      title={membershipGate.ok ? "Report this group post for community review" : (membershipGate.reason || "Complete verification before reporting")}
                    >
                      {reportBusyId === pid ? "Reporting…" : "Report"}
                    </button>
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="cardDesc">No posts are visible in this group yet.</div>
          )}
        </div>
      </section>
    </div>
  );
}
