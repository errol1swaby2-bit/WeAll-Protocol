import React, { useEffect, useMemo, useState } from "react";

import { api, getApiBaseUrl, weall, type GroupGovernanceContract, type GroupElectionRecord } from "../api/weall";
import ErrorBanner from "../components/ErrorBanner";
import GroupBallotPlanner from "../components/GroupBallotPlanner";
import { getAuthHeaders, getKeypair, getSession, submitSignedTx } from "../auth/session";
import { normalizeAccount } from "../auth/keys";
import { checkGates, summarizeAccountState } from "../lib/gates";
import { nav, navWithReturn } from "../lib/router";
import { GROUP_PROFILE_TABS, groupWorkspaceTabFromHash, groupElectionIdFromHash, type GroupProfileTab, type GroupWorkspaceTab } from "../lib/groupProfileTabs";
import { useAccount } from "../context/AccountContext";
import { useTxQueue } from "../hooks/useTxQueue";
import { useMutationRefresh } from "../hooks/useMutationRefresh";
import { useSignerSubmissionBusy } from "../hooks/useSignerSubmissionBusy";
import { reconcileMembershipDecision, reconcileMembershipPending, reconcileMembershipState } from "../lib/groupsRevalidation";
import { groupReportSource, publicRoleAccounts } from "../lib/groupOversight";
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
  const [groupDecisions, setGroupDecisions] = useState<any[]>([]);
  const [groupReports, setGroupReports] = useState<Array<{ item: any; source: string }>>([]);
  const [groupReportsStatus, setGroupReportsStatus] = useState<"idle" | "loading" | "ready" | "error">("idle");
  const [groupReportsBounded, setGroupReportsBounded] = useState(true);
  const [decisionsStatus, setDecisionsStatus] = useState<"idle" | "loading" | "ready" | "error">("idle");
  const [electionRows, setElectionRows] = useState<GroupElectionRecord[]>([]);
  const [electionDetail, setElectionDetail] = useState<GroupElectionRecord | null>(null);
  const [electionTotal, setElectionTotal] = useState<number | null>(null);
  const [electionNextOffset, setElectionNextOffset] = useState<number | null>(null);
  const [electionsStatus, setElectionsStatus] = useState<"idle" | "loading" | "ready" | "error">("idle");
  const [membershipStatus, setMembershipStatus] = useState<MembershipStatus | null>(null);
  const [governanceContract, setGovernanceContract] = useState<GroupGovernanceContract | null>(null);
  const [acctState, setAcctState] = useState<any | null>(null);
  const [err, setErr] = useState<{ msg: string; details: any } | null>(null);
  const [busy, setBusy] = useState<boolean>(false);
  const [reportBusyId, setReportBusyId] = useState<string | null>(null);
  const [reportInfo, setReportInfo] = useState<{ msg: string; details?: any } | null>(null);
  const [activeTab, setActiveTab] = useState<GroupWorkspaceTab>(() => groupWorkspaceTabFromHash(typeof window !== "undefined" ? window.location.hash : ""));
  const [electionDetailId, setElectionDetailId] = useState<string>(() => groupElectionIdFromHash(typeof window !== "undefined" ? window.location.hash : ""));

  useEffect(() => {
    const onHashChange = () => {
      setActiveTab(groupWorkspaceTabFromHash(window.location.hash));
      setElectionDetailId(groupElectionIdFromHash(window.location.hash));
    };
    window.addEventListener("hashchange", onHashChange);
    return () => window.removeEventListener("hashchange", onHashChange);
  }, []);

  const session = getSession();
  const acct = session ? normalizeAccount(session.account) : null;
  const kp = acct ? getKeypair(acct) : null;
  const canSign = !!kp?.secretKeyB64;
  const tx = useTxQueue();
  const signerSubmission = useSignerSubmissionBusy(acct);
  const { refresh: refreshAccountContext } = useAccount();

  const membershipGate = useMemo(
    // GROUP_MEMBERSHIP_REQUEST is canonically Tier1+; actual authority remains backend checked.
    () => checkGates({ loggedIn: !!acct, canSign, accountState: acctState, requireTier: 1 }),
    [acct, canSign, acctState],
  );
  const accountSummary = acctState ? summarizeAccountState(acctState) : "(state unknown)";
  const currentGroupRoute = selected ? `/groups/${encodeURIComponent(selected)}` : "/groups";
  const openGroupTab = (tab: GroupProfileTab) => nav(`${currentGroupRoute}?tab=${tab}`);

  useEffect(() => {
    if (!selected || (activeTab !== "elections" && activeTab !== "election_detail")) return;
    let active = true;
    setElectionsStatus("loading");
    setElectionRows([]);
    setElectionDetail(null);
    setElectionTotal(null);
    setElectionNextOffset(null);
    const headers = acct ? getAuthHeaders(acct) : undefined;
    const source = activeTab === "elections"
      ? weall.groupElections(selected, { limit: 100, offset: 0 }, base, headers)
      : weall.groupElection(selected, electionDetailId, base, headers);
    void source.then(response => {
      if (!active) return;
      if (response.ok !== true || response.group_id !== selected || response.read_only !== true) {
        throw new Error("Election response has invalid group provenance.");
      }
      if ("items" in response) {
        if (!Array.isArray(response.items) || response.items.some(item =>
            item.group_id !== selected || item.source !== "canonical_group_emissary_elections_snapshot")) {
          throw new Error("Election index contains a mismatched group.");
        }
        setElectionRows(response.items);
        setElectionTotal(response.total);
        setElectionNextOffset(response.next_offset);
      } else {
        const item = response.election;
        if (!item || item.group_id !== selected || item.election_id !== electionDetailId ||
            item.source !== "canonical_group_emissary_elections_snapshot") {
          throw new Error("Election detail does not match the requested group and election.");
        }
        setElectionDetail(item);
      }
      setElectionsStatus("ready");
    }).catch(() => {
      if (!active) return;
      setElectionRows([]);
      setElectionDetail(null);
      setElectionTotal(null);
      setElectionNextOffset(null);
      setElectionsStatus("error");
    });
    return () => { active = false; };
  }, [activeTab, selected, electionDetailId, base, acct]);

  useEffect(() => {
    if (activeTab !== "decisions" || !selected) return;
    let active = true;
    setGroupDecisions([]);
    setDecisionsStatus("loading");
    // Canonical group scope is taken from each returned proposal; never infer it
    // from browser navigation or a group membership cached in this client.
    void weall.proposals({ limit: 200, includeSummary: true }, base)
      .then((result: any) => {
        if (!active) return;
        const rows = Array.isArray(result?.items) ? result.items : [];
        const scoped = rows.filter((item: any) =>
          String(item?.group_id || item?.raw?.group_id || "").trim() === selected,
        );
        setGroupDecisions(scoped);
        setDecisionsStatus("ready");
      })
      .catch(() => {
        if (!active) return;
        setGroupDecisions([]);
        setDecisionsStatus("error");
      });
    return () => { active = false; };
  }, [activeTab, selected, base]);

  useEffect(() => {
    if (!selected || activeTab !== "reports") return;
    let active = true;
    setGroupReports([]);
    setGroupReportsBounded(true);
    setGroupReportsStatus("loading");
    // The dispute endpoint has no exact group_id filter. Match ONLY against
    // group-feed post IDs or the canonical target snapshot's group_id.
    // Both lists are capped; a zero match does NOT mean zero historical reports.
    const headers = acct ? getAuthHeaders(acct) : undefined;
    void Promise.all([
      weall.groupFeed(selected, { limit: 100 }, base, headers),
      weall.disputes({ limit: 200, includeSummary: true }, base, headers),
    ]).then(([feed, reports]: [any, any]) => {
      if (!active) return;
      if (String(feed?.group_id || "").trim() !== selected || !Array.isArray(feed?.items) || !Array.isArray(reports?.items)) {
        throw new Error("Group report sources are incomplete or scoped to a different group.");
      }
      const postIds = new Set<string>(feed.items.map((p: any) =>
        String(p?.post_id || p?.id || "").trim()).filter(Boolean));
      const matched: Array<{ item: any; source: string }> = [];
      for (const item of reports.items) {
        const reportId = String(item?.id || item?.dispute_id || "").trim();
        if (!reportId) continue;
        const source = groupReportSource(item, selected, postIds);
        if (source) matched.push({ item, source });
      }
      setGroupReports(matched);
      const total = Number(reports?.summary?.total);
      setGroupReportsBounded(Boolean(feed?.next_cursor) || feed.items.length >= 100 ||
        reports.items.length >= 200 || !Number.isFinite(total) || total > reports.items.length);
      setGroupReportsStatus("ready");
    }).catch(() => {
      if (!active) return;
      setGroupReports([]);
      setGroupReportsBounded(true);
      setGroupReportsStatus("error");
    });
    return () => { active = false; };
  }, [activeTab, selected, base, acct]);

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

    const approvalRequired = String(detail?.membership_mode || detail?.meta?.membership_mode || "open").trim().toLowerCase() === "approval_required";
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
        successMessage: kind === "join"
          ? (approvalRequired ? "Membership request submitted; moderator approval is still required." : "Joined group.")
          : "Left group.",
        errorMessage: (e) => prettyErr(e).msg,
        getTxId: (res: any) => res?.result?.tx_id,
        finality: {
          timeoutMs: 16000,
          mutation: { entityType: "group", entityId: selected, account: acct || undefined, routeHint: `/groups/${encodeURIComponent(selected)}`, txType: String(skeletonTx.tx_type) },
          reconcile: async () => kind === "join" && approvalRequired
            ? reconcileMembershipPending({ groupId: selected, account: acct, base })
            : reconcileMembershipState({
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

  async function decideMembership(member: string, decision: "accept" | "reject"): Promise<void> {
    if (!selected || !acct || !canSign || !canModerate || busy || signerSubmission.busy) return;
    setErr(null);
    setBusy(true);
    try {
      // A visible role badge is not authority. Re-read current group state
      // before signing so revoked moderators and settled requests fail closed.
      const freshResponse: any = await api.groups.get(selected, base);
      const freshGroup: any = freshResponse?.group || freshResponse;
      const freshModerators = publicRoleAccounts(freshGroup?.moderators || freshGroup?.roles?.moderators);
      if (!freshModerators.some((candidate) => candidate.toLowerCase() === acct.toLowerCase())) {
        throw new Error("Your moderator assignment is not present in the latest group state. No decision was submitted.");
      }
      const freshMode = String(freshGroup?.membership_mode || freshGroup?.meta?.membership_mode || "").trim().toLowerCase();
      const freshRequests = freshGroup?.membership_requests;
      if (freshMode !== "approval_required" ||
          !freshRequests || typeof freshRequests !== "object" ||
          Array.isArray(freshRequests) ||
          !Object.prototype.hasOwnProperty.call(freshRequests, member)) {
        throw new Error("This membership request is not pending in the latest group state. No decision was submitted.");
      }
      await tx.runTx({
        title: decision === "accept" ? "Approve membership" : "Reject membership",
        pendingKey: txPendingKey(["group-membership-decision", selected, member, decision, acct]),
        pendingMessage: "Submitting signed membership decision…",
        successMessage: "Membership decision submitted; verify its inclusion and canonical group state.",
        errorMessage: (e) => prettyErr(e).msg,
        getTxId: (res: any) => res?.result?.tx_id,
        finality: {
          timeoutMs: 16000,
          mutation: { entityType: "group", entityId: selected, account: acct, routeHint: currentGroupRoute, txType: "GROUP_MEMBERSHIP_DECIDE" },
          reconcile: async () => reconcileMembershipDecision({ groupId: selected, account: member, decision, base }),
        },
        task: async () => submitSignedTx({
          account: acct,
          tx_type: "GROUP_MEMBERSHIP_DECIDE",
          payload: { group_id: selected, account: member, decision },
          parent: null,
          base,
        }),
      });
      await refreshMutationSlices(refreshSelected, loadMembershipStatus, refreshAccountContext);
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
  const membershipMode = String(detail?.membership_mode || detail?.meta?.membership_mode || "open").trim().toLowerCase();
  const pendingMembershipAccounts = detail?.membership_requests && typeof detail.membership_requests === "object"
    && !Array.isArray(detail.membership_requests)
    ? Object.keys(detail.membership_requests).sort() : [];
  const moderatorAccounts = publicRoleAccounts(detail?.moderators || detail?.roles?.moderators);
  // The backend is authoritative: revoked moderators cannot approve even if
  // the local role cache has not refreshed.
  const canModerate = !!acct && moderatorAccounts.some((member: unknown) =>
    String(member || "").trim().toLowerCase() === acct.toLowerCase(),
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
                {detailDescription || "Public community profile. Browse this group's posts, membership and governance records."}
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

      <nav className="groupProfileTabs" aria-label="Group profile sections">
        {GROUP_PROFILE_TABS.filter((tab) => tab.id !== "responsibilities" || !!acct).map((tab) => (
          <button
            key={tab.id}
            type="button"
            className={`groupProfileTab ${activeTab === tab.id ? "isActive" : ""}`}
            aria-current={activeTab === tab.id ? "page" : undefined}
            onClick={() => openGroupTab(tab.id)}
          >
            {tab.label}
          </button>
        ))}
      </nav>

      {activeTab === "about" ? (
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
      ) : null}

      {activeTab === "governance" ? (
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
      ) : null}

      {activeTab === "decisions" ? (
      <section className="card" aria-label="Group-specific decisions">
        <div className="cardBody formStack">
          <div className="sectionHead">
            <div>
              <div className="eyebrow">Group governance</div>
              <h2 className="cardTitle">Decisions in this community</h2>
              <p className="cardDesc">
                Only proposals explicitly identifying this group's canonical scope appear here.
                The bounded public index returns at most 200 proposals; this is not an exhaustive historical archive.
              </p>
            </div>
            <div className="buttonRow buttonRowWide">
              <button className="btn" onClick={() => nav("/decisions")}>Browse all decisions</button>
              <button className="btn btnPrimary" onClick={() => nav(`${currentGroupRoute}/decisions/new`)}>Propose for this group</button>
            </div>
          </div>
          {decisionsStatus === "loading" ? <div className="cardDesc">Loading group decisions…</div> : null}
          {decisionsStatus === "error" ? <div className="calloutDanger">Group decisions could not be loaded from this node. No absence claim is made.</div> : null}
          {decisionsStatus === "ready" && !groupDecisions.length ? (
            <div className="emptyState compactEmpty">
              <div className="emptyTitle">No group-scoped decisions in the returned index</div>
              <div className="emptyText">This does not prove there have never been group decisions.</div>
            </div>
          ) : null}
          {decisionsStatus === "ready" ? groupDecisions.map((item: any, index: number) => {
            const proposalId = String(item?.proposal_id || item?.id || "").trim();
            if (!proposalId) return null;
            return (
              <button
                type="button"
                className="quickCard quickCardMain"
                key={proposalId || String(index)}
                onClick={() => nav(`/decisions/${encodeURIComponent(proposalId)}`)}
              >
                <strong>{String(item?.title || "Group decision")}</strong>
                <span className="miniTag">{String(item?.stage || item?.status || "status unavailable")}</span>
              </button>
            );
          }) : null}
        </div>
      </section>
      ) : null}

      {activeTab === "treasury" ? (
      <section className="card" aria-label="Group treasury transparency">
        <div className="cardBody formStack">
          <div className="eyebrow">Group treasury</div>
          <h2 className="cardTitle">Treasury status and mandate</h2>
          <div className="calloutInfo">
            This integration does not expose a verified group treasury ledger or authorized payment workflow.
            No balance, proposed spending power, or executable group payment is claimed here.
          </div>
          <p className="cardDesc">
            Group-scoped spending decisions and authorization records must be reviewed under the same
            constitutional and economic activation gates as the protocol. A ballot or elected emissary
            is not, by itself, authority to transfer funds.
          </p>
          <div className="buttonRow buttonRowWide">
            <button className="btn" onClick={() => openGroupTab("decisions")}>View group decisions</button>
            <button className="btn" onClick={() => nav("/protocol/economics")}>Read locked economics status</button>
          </div>
        </div>
      </section>
      ) : null}

      {activeTab === "responsibilities" ? (
      <section className="card" aria-label="My group responsibilities">
        <div className="cardBody formStack">
          <div className="eyebrow">My work · this group only</div>
          <h2 className="cardTitle">Group responsibilities</h2>
          <p className="cardDesc">
            This dashboard routes your actual membership and moderator tasks. It does not
            assign any role, confer juror authority, or authorize treasury or emissary execution.
          </p>
          {!acct ? (
            <div className="calloutInfo">
              Sign in to inspect your group responsibilities. Public records remain available in the other tabs.
              <div className="buttonRow"><button className="btn" onClick={() => navWithReturn("/login", currentGroupRoute + "?tab=responsibilities")}>Sign in</button></div>
            </div>
          ) : (
            <>
              <div className="surfaceBoundaryList">
                <span className="surfaceBoundaryTag">Account: {acct}</span>
                <span className="surfaceBoundaryTag">Membership: {isMember ? "member" : isPendingMembership ? "pending" : "not confirmed"}</span>
                <span className="surfaceBoundaryTag">Moderator listing: {canModerate ? "present in group read model" : "not present"}</span>
                <span className="surfaceBoundaryTag">Signing device: {canSign ? "available" : "unavailable"}</span>
              </div>
              <div className="detailFocusStrip actionFocusStrip">
                <article className="detailFocusCard">
                  <div className="detailFocusLabel">Member participation</div>
                  <div className="detailFocusValue">{isMember ? "Membership confirmed" : isPendingMembership ? "Request awaiting decision" : "No confirmed membership"}</div>
                  <div className="detailFocusText">Join or leave using the existing signed membership action. Posting and voting remain subject to canonical account and group rules.</div>
                  <button className="btn" onClick={() => openGroupTab("members")}>Open membership</button>
                </article>
                <article className="detailFocusCard">
                  <div className="detailFocusLabel">Membership moderator</div>
                  <div className="detailFocusValue">{canModerate ? "Listed as moderator" : "Not assigned"}</div>
                  <div className="detailFocusText">
                    {canModerate
                      ? membershipMode === "approval_required"
                        ? "Open the dedicated request desk. Each signed decision rechecks the live group state."
                        : "This group does not currently use an approval-required membership queue."
                      : "No moderator action is offered without the group listing your account as a moderator."}
                  </div>
                  {canModerate && membershipMode === "approval_required" ? (
                    <button className="btn" disabled={!canSign} onClick={() => nav(currentGroupRoute + "/manage/members")}>Open membership approval desk</button>
                  ) : null}
                </article>
                <article className="detailFocusCard">
                  <div className="detailFocusLabel">Public content oversight</div>
                  <div className="detailFocusValue">Reports are not jury assignments</div>
                  <div className="detailFocusText">
                    Browse public reports matched to this group's canonical posts. Group moderation does not
                    grant dispute juror authority; assigned verdict work remains in the Review Center.
                  </div>
                  <button className="btn" onClick={() => openGroupTab("reports")}>Inspect group reports</button>
                  {canModerate ? (
                    <button className="btn" onClick={() => nav(currentGroupRoute + "/manage/moderation")}>Moderator case routing</button>
                  ) : null}
                </article>
                <article className="detailFocusCard">
                  <div className="detailFocusLabel">Emissary and treasury mandates</div>
                  <div className="detailFocusValue">Execution desk unavailable</div>
                  <div className="detailFocusText">No verified group-scoped mandate, treasury signer, expiry or execution receipt API is connected. An election or role listing cannot substitute for one.</div>
                  <button className="btn" onClick={() => openGroupTab("emissaries")}>Inspect public election records</button>
                  <button className="btn" onClick={() => nav(currentGroupRoute + "/emissaries/work")}>Mandate availability</button>
                </article>
              </div>
              {!canSign ? <div className="calloutInfo">Restore your local signing key before attempting any signed action.</div> : null}
            </>
          )}
        </div>
      </section>
      ) : null}

      {activeTab === "reports" ? (
        <section className="card" aria-label="Public group report records">
          <div className="cardBody formStack">
            <div className="sectionHead">
              <div>
                <div className="eyebrow">Group · public oversight</div>
                <h2 className="cardTitle">Reports on group content</h2>
                <p className="cardDesc">
                  Matched using the public dispute target's canonical group snapshot or a post ID from
                  this group's returned feed. The APIs do not expose a complete group-filtered dispute index.
                </p>
              </div>
              <button className="btn" onClick={() => nav("/reports")}>All public reports</button>
            </div>
            <div className="calloutInfo">
              This is a bounded, public record sample, not a comprehensive moderation queue.
              A group moderator does not automatically become a dispute juror. No verdict or removal controls are available here.
            </div>
            {groupReportsStatus === "loading" ? <p className="cardDesc">Loading the group's public report sample…</p> : null}
            {groupReportsStatus === "error" ? <div className="calloutDanger">Public report sources could not be verified for this group. No absence claim is made.</div> : null}
            {groupReportsStatus === "ready" ? (
              <>
                <div className="surfaceBoundaryList">
                  <span className="surfaceBoundaryTag">{groupReports.length} matches in returned sample</span>
                  <span className="surfaceBoundaryTag">{groupReportsBounded ? "Source window is incomplete or unverified" : "Current bounded source window inspected; history not guaranteed"}</span>
                </div>
                {groupReports.map(({ item, source }) => {
                  const reportId = String(item?.id || item?.dispute_id || "").trim();
                  return (
                    <article className="quickCard quickCardSplit" key={reportId}>
                      <div className="quickCardMain">
                        <strong>Report {reportId}</strong>
                        <span className="miniTag">{String(item?.stage || item?.status || "status unavailable")}</span>
                        <small>Target {String(item?.target_id || "unavailable")} · {source === "canonical_target_snapshot" ? "canonical group snapshot" : "returned group post"}</small>
                      </div>
                      <button className="btn" onClick={() => nav(`/reports/${encodeURIComponent(reportId)}`)}>Open public record</button>
                    </article>
                  );
                })}
                {!groupReports.length ? (
                  <div className="emptyState compactEmpty">
                    <div className="emptyTitle">No matching reports in the returned sample</div>
                    <div className="emptyText">Hidden content, older cases and unreturned pages may be missing. This does not establish that the group has never had reports.</div>
                  </div>
                ) : null}
              </>
            ) : null}
          </div>
        </section>
      ) : null}

      {activeTab === "moderation_review" ? (
        <section className="card" aria-label="Group moderator case routing">
          <div className="cardBody formStack">
            <div className="eyebrow">My group work · content oversight</div>
            <h2 className="cardTitle">Moderator case routing</h2>
            <p className="cardDesc">A group moderator's membership powers do not confer content dispute voting authority. Only a separately assigned, opted-in juror can issue a review verdict.</p>
            {!acct || !canSign ? (
              <div className="calloutInfo">Sign in with your local signer to open group responsibility routes.</div>
            ) : !canModerate ? (
              <div className="calloutInfo">No moderator assignment is present in the current group read model. No group-role action is available.</div>
            ) : (
              <>
                <div className="surfaceBoundaryList">
                  <span className="surfaceBoundaryTag">Group: {selected}</span>
                  <span className="surfaceBoundaryTag">Moderator listing: present</span>
                  <span className="surfaceBoundaryTag">Dispute jury: independently assigned</span>
                </div>
                <p className="cardDesc">Open the public group reports index for oversight. The separate Review Center verifies reviewer opt-in, case assignment and conflict rules before any signed dispute action.</p>
                <div className="buttonRow buttonRowWide">
                  <button className="btn" onClick={() => openGroupTab("reports")}>Public group reports</button>
                  <button className="btn" onClick={() => nav("/tasks/disputes")}>Assigned dispute reviews</button>
                  <button className="btn" onClick={() => nav(currentGroupRoute + "/manage/members")}>Membership approval desk</button>
                </div>
              </>
            )}
          </div>
        </section>
      ) : null}

      {activeTab === "emissary_work" ? (
        <section className="card" aria-label="Group emissary mandate status">
          <div className="cardBody formStack">
            <div className="eyebrow">Group responsibilities · emissary</div>
            <h2 className="cardTitle">Mandate execution unavailable</h2>
            <p className="cardDesc">
              The group governance endpoint exposes public active election summaries, not a verified
              elected-seat, mandate-scope, expiry, timelock or executable receipt contract.
              No signature or treasury action is authorized from this page.
            </p>
            <div className="calloutInfo">
              A candidate listing, election, group membership or moderator badge cannot establish an
              active executable mandate. Use the public records until the backend exposes a complete canonical authorization chain.
            </div>
            <div className="buttonRow buttonRowWide">
              <button className="btn" onClick={() => openGroupTab("emissaries")}>View public elections</button>
              <button className="btn" onClick={() => openGroupTab("decisions")}>View group decisions</button>
            </div>
          </div>
        </section>
      ) : null}

      {activeTab === "elections" || activeTab === "election_detail" ? (
        <section className="card" aria-label="Canonical group emissary elections">
          <div className="cardBody formStack">
            <div className="sectionHead">
              <div>
                <div className="eyebrow">Canonical group elections · public read</div>
                <h2 className="cardTitle">{activeTab === "election_detail" ? "Election record" : "Emissary election history"}</h2>
                <p className="cardDesc">
                  Public read-only election state. Active, finalized and no-decision outcomes are distinct.
                  Voter snapshot membership is visible only to an authenticated viewer and never grants ballot authorization.
                </p>
              </div>
              <button className="btn" onClick={() => openGroupTab("emissaries")}>Back to emissaries</button>
            </div>
            {electionsStatus === "loading" ? <p className="cardDesc">Reading canonical election records…</p> : null}
            {electionsStatus === "error" ? (
              <div className="calloutDanger">Canonical election records could not be verified for this group. No election, winner, or eligibility claim is made.</div>
            ) : null}
            {electionsStatus === "ready" && activeTab === "elections" ? (
              <>
                <div className="surfaceBoundaryList">
                  <span className="surfaceBoundaryTag">{electionRows.length} returned · {electionTotal ?? "?"} matching current-state records</span>
                  <span className="surfaceBoundaryTag">{electionNextOffset == null ? "This page includes all current indexed records" : "Additional pages available; this is a bounded sample"}</span>
                </div>
                {electionRows.map(election => (
                  <button type="button" className="quickCard quickCardMain" key={election.election_id}
                    onClick={() => nav(`${currentGroupRoute}/emissaries/elections/${encodeURIComponent(election.election_id)}`)}>
                    <strong className="mono">{election.election_id}</strong>
                    <span className="miniTag">{election.status} · {election.candidate_count ?? "unknown"} candidates · {election.seats ?? "unknown"} seats</span>
                    <small>{election.status === "no_decision" ? "No decision recorded" : election.status === "finalized" ? "Finalized outcome recorded" : "No finalized outcome claimed"}</small>
                  </button>
                ))}
                {!electionRows.length ? <p className="cardDesc">No elections are indexed in this group's current runtime snapshot; historical block archives may differ.</p> : null}
                {electionNextOffset != null ? <div className="calloutInfo">More current-state records exist beyond this bounded page. The index API supports pagination; this UI does not yet load additional pages.</div> : null}
              </>
            ) : null}
            {electionsStatus === "ready" && activeTab === "election_detail" && electionDetail ? (
              <>
                <div className="surfaceBoundaryList">
                  <span className="surfaceBoundaryTag">Group: {electionDetail.group_id}</span>
                  <span className="surfaceBoundaryTag">Status: {electionDetail.status}</span>
                  <span className="surfaceBoundaryTag">Observed height: {electionDetail.observed_height ?? "unavailable"}</span>
                </div>
                <div className="detailFocusStrip">
                  <article className="detailFocusCard">
                    <div className="detailFocusLabel">Election ID</div>
                    <div className="detailFocusValue mono">{electionDetail.election_id}</div>
                    <div className="detailFocusText">Seats: {electionDetail.seats ?? "not exposed"} · Candidates: {electionDetail.candidate_count ?? "not exposed"}</div>
                  </article>
                  <article className="detailFocusCard">
                    <div className="detailFocusLabel">Canonical height window</div>
                    <div className="detailFocusValue">{electionDetail.start_height ?? "unknown"} → {electionDetail.end_height ?? "unknown"}</div>
                    <div className="detailFocusText">Observed at height {electionDetail.observed_height ?? "unknown"}. Actual inclusion height may differ.</div>
                  </article>
                  <article className="detailFocusCard">
                    <div className="detailFocusLabel">Your voter snapshot membership</div>
                    <div className="detailFocusValue">{electionDetail.viewer_in_voter_snapshot == null ? "Not verified" : electionDetail.viewer_in_voter_snapshot ? "In snapshot" : "Not in snapshot"}</div>
                    <div className="detailFocusText">Snapshot size: {electionDetail.voter_snapshot_count ?? "unavailable"}. Membership is not final authorization to cast a ballot.</div>
                  </article>
                  <article className="detailFocusCard">
                    <div className="detailFocusLabel">Outcome</div>
                    <div className="detailFocusValue">{electionDetail.status === "no_decision" ? "No decision" : electionDetail.status === "finalized" ? "Finalized" : "Not finalized"}</div>
                    <div className="detailFocusText">Finalized at height: {electionDetail.finalized_at_height ?? "not recorded"}.</div>
                  </article>
                </div>
                <h3 className="cardTitle">Canonical candidate accounts</h3>
                {electionDetail.candidates === null
                  ? <p className="cardDesc">Candidate IDs are not present in the indexed record.</p>
                  : electionDetail.candidates.length
                    ? <div className="surfaceBoundaryList">{electionDetail.candidates.map(candidate => <span className="surfaceBoundaryTag mono" key={candidate}>{candidate}</span>)}</div>
                    : <p className="cardDesc">No candidates in the indexed record.</p>}
                {electionDetail.status === "finalized" ? (
                  <div className="formStack">
                    <h3 className="cardTitle">Recorded winners</h3>
                    {electionDetail.winners.length
                      ? <div className="surfaceBoundaryList">{electionDetail.winners.map(winner => <span className="surfaceBoundaryTag mono" key={winner}>{winner}</span>)}</div>
                      : <p className="cardDesc">The finalized record exposes no winners.</p>}
                  </div>
                ) : electionDetail.status === "no_decision"
                  ? <div className="calloutInfo">No decision was recorded. No emissary authority is inferred.</div>
                  : null}
                <GroupBallotPlanner
                  key={`${selected}:${electionDetail.election_id}`}
                  groupId={selected}
                  election={electionDetail}
                />
                <button className="btn" onClick={() => nav(`${currentGroupRoute}/emissaries/elections`)}>Back to election history</button>
              </>
            ) : null}
            <div className="calloutInfo">
              This election API is read-only. No ballots, finalization, emissary execution or treasury authority are
              available here. A public candidate list or authenticated snapshot hint does not authorize a signed vote.
            </div>
          </div>
        </section>
      ) : null}

      {activeTab === "emissaries" ? (
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
              <div className="buttonRow buttonRowWide">
                <button className="btn" onClick={() => nav(`${currentGroupRoute}/emissaries/elections`)}>Inspect active elections</button>
                <button className="btn" onClick={() => nav("/transactions")}>Track related transactions</button>
              </div>
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
      ) : null}

      {activeTab === "members" ? (
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
      ) : null}

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

      {activeTab === "membership_review" ? (
        <section className="card" aria-label="Group membership approvals">
          <div className="cardBody formStack">
            <div className="sectionHead">
              <div>
                <div className="eyebrow">Moderator task · {detailName}</div>
                <h2 className="cardTitle">Membership request decisions</h2>
                <p className="cardDesc">
                  Approval and rejection are separate signed transactions. Only an included
                  backend-authorized GROUP_MEMBERSHIP_DECIDE can change the canonical membership state.
                </p>
              </div>
              <button className="btn" onClick={() => openGroupTab("responsibilities")}>Back to my group work</button>
            </div>
            {!acct || !canSign ? (
              <div className="calloutInfo">
                This task requires an authenticated local signer. No membership request information is shown.
                <button className="btn" onClick={() => navWithReturn(acct ? "/session" : "/login", currentGroupRoute + "/manage/members")}>Restore signing session</button>
              </div>
            ) : !canModerate ? (
              <div className="calloutInfo">
                Moderator assignment is not present in this group's read model.
                No approval controls or pending applicant accounts are displayed.
              </div>
            ) : membershipMode !== "approval_required" ? (
              <div className="calloutInfo">This group has no approval-required membership queue. No decision can be submitted here.</div>
            ) : (
              <>
                <div className="surfaceBoundaryList">
                  <span className="surfaceBoundaryTag">Exact group: {selected}</span>
                  <span className="surfaceBoundaryTag">Pending in returned snapshot: {pendingMembershipAccounts.length}</span>
                  <span className="surfaceBoundaryTag">Moderator status: rechecked before every submission</span>
                </div>
                {pendingMembershipAccounts.length ? pendingMembershipAccounts.map((member) => (
                  <div className="buttonRow buttonRowWide" key={member}>
                    <span className="mono">{member}</span>
                    <button className="btn btnPrimary" disabled={busy || signerSubmission.busy} onClick={() => void decideMembership(member, "accept")}>Approve</button>
                    <button className="btn" disabled={busy || signerSubmission.busy} onClick={() => void decideMembership(member, "reject")}>Reject</button>
                  </div>
                )) : <div className="cardDesc">No pending membership requests are visible in this group snapshot. This is not a claim about prior requests.</div>}
                <p className="cardDesc">A successful submission alone is not finality. The receipt and refreshed canonical group state must confirm the decision.</p>
              </>
            )}
          </div>
        </section>
      ) : null}

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

      {activeTab === "about" || activeTab === "members" ? (
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
      ) : null}

      {activeTab === "posts" ? (
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
      ) : null}
    </div>
  );
}
