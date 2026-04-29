import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { api, getApiBaseUrl, weall } from "../api/weall";
import { getSession, type SessionHealth } from "../auth/session";
import { useAccount } from "../context/AccountContext";
import { getFrontendCapabilities } from "../lib/capabilities";
import { disputeJurorStatus } from "../lib/disputeSurface";
import { derivePendingWork, type PendingWorkItem, type PendingWorkSummary } from "../lib/pendingWork";
import { nav, type RouteMatch, type RouteMeta } from "../lib/router";
import { RAIL_REFRESH_INTERVAL_MS, refreshTouches, requestGlobalRefresh, subscribeGlobalRefresh } from "../lib/revalidation";
import { summarizeNodeConnection } from "../lib/status";

type ContextSummary = {
  title: string;
  body: string;
  actions?: Array<{ label: string; href: string }>;
};

function Panel({ title, children }: { title: string; children: React.ReactNode }): JSX.Element {
  return (
    <section className="rightRailPanel">
      <div className="rightRailPanelLabel">{title}</div>
      <div className="rightRailPanelBody">{children}</div>
    </section>
  );
}

function toArray<T>(value: unknown): T[] {
  return Array.isArray(value) ? (value as T[]) : [];
}

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
}

function asCountLabel(label: string, count: number): string {
  return `${count} ${label}${count === 1 ? "" : "s"}`;
}

function freshnessLabel(msAgo: number | null): string {
  if (msAgo == null) return "Awaiting refresh";
  if (msAgo < 15_000) return "Fresh";
  if (msAgo < 45_000) return "Aging";
  return "Refresh recommended";
}

function formatAgo(msAgo: number | null): string {
  if (msAgo == null) return "No rail refresh recorded yet.";
  if (msAgo < 1_000) return "Updated just now";
  const seconds = Math.round(msAgo / 1000);
  if (seconds < 60) return `Updated ${seconds}s ago`;
  const minutes = Math.round(seconds / 60);
  return `Updated ${minutes}m ago`;
}

function deriveContextSummary(args: {
  route: RouteMatch;
  meta: RouteMeta;
  proposalDetail: Record<string, unknown> | null;
  disputeDetail: Record<string, unknown> | null;
  groupDetail: Record<string, unknown> | null;
  account?: string;
  activeProposalCount: number;
  activeDisputeCount: number;
  groupCount: number;
}): ContextSummary {
  const { route, meta, proposalDetail, disputeDetail, groupDetail, activeProposalCount, activeDisputeCount, groupCount, account } = args;

  switch (meta.rightRail) {
    case "home":
      return {
        title: "Home context",
        body: `Quick posture for this session. ${asCountLabel("proposal action", activeProposalCount)} and ${asCountLabel("dispute action", activeDisputeCount)} are currently surfaced. Home stays content-first while governance and adjudication remain linked, not merged.`,
        actions: [
          { label: "Open feed", href: "/feed" },
          { label: "Open proposals", href: "/proposals" },
        ],
      };
    case "feed":
      return {
        title: "Feed context",
        body: `${asCountLabel("proposal action", activeProposalCount)} and ${asCountLabel("dispute action", activeDisputeCount)} remain visible elsewhere in the protocol. Keep the center column focused on browsing, not diagnostics.`,
        actions: [{ label: "Create post", href: "/post" }],
      };
    case "groups":
      return {
        title: "Groups context",
        body: `${asCountLabel("group", groupCount)} loaded into the discovery slice. Group creation remains a dedicated action flow, not an inline hub composer.`,
      };
    case "group_detail": {
      const routeGroupId = route.path === "/groups/:id" ? route.id : "";
      const groupName = String(groupDetail?.name || groupDetail?.title || routeGroupId || "Group");
      const policy = String(groupDetail?.policy || groupDetail?.membership_policy || "Policy not surfaced yet.");
      return {
        title: "Group context",
        body: `${groupName}. ${policy}`,
        actions: [{ label: "Back to groups", href: "/groups" }],
      };
    }
    case "proposals":
      return {
        title: "Governance context",
        body: `${asCountLabel("proposal action", activeProposalCount)} currently surfaced. The hub should remain list-first and defer deep inspection to detail routes.`,
      };
    case "proposal_detail": {
      const title = String(proposalDetail?.title || proposalDetail?.proposal_title || "Proposal detail");
      const stage = String(proposalDetail?.stage || proposalDetail?.status || "stage unknown");
      return {
        title: "Proposal context",
        body: `${title}. Current stage: ${stage}. Vote locking should derive from authoritative proposal state rather than button-local assumptions.`,
        actions: [{ label: "Back to proposals", href: "/proposals" }],
      };
    }
    case "disputes":
      return {
        title: "Dispute queue context",
        body: `${asCountLabel("dispute action", activeDisputeCount)} currently surfaced. Queue pages should list work, not embed review voting controls.`,
      };
    case "dispute_detail": {
      const stage = String(disputeDetail?.stage || disputeDetail?.status || "stage unknown");
      const reason = String(disputeDetail?.reason || disputeDetail?.summary || "Reason not surfaced yet.");
      return {
        title: "Dispute context",
        body: `Current stage: ${stage}. ${reason}`,
        actions: [{ label: "Back to disputes", href: "/disputes" }],
      };
    }
    case "dispute_review": {
      const stage = String(disputeDetail?.stage || disputeDetail?.status || "stage unknown");
      const jurorStatus = disputeJurorStatus(disputeDetail, account || "") || "status not surfaced";
      return {
        title: "Dispute review context",
        body: `Review workspace for a single case. Current stage: ${stage}. Juror posture: ${jurorStatus}. Final voting belongs here, not on the queue or detail surface.`,
        actions: [
          { label: "Open dispute detail", href: route.path === "/disputes/:id/review" ? `/disputes/${encodeURIComponent(String((route as any).id || ""))}` : "/disputes" },
          { label: "Back to disputes", href: "/disputes" },
        ],
      };
    }
    case "post_create":
      return {
        title: "Composer context",
        body: "Submission must progress through validating, submitting, recorded, refreshing, confirmed, or failed states. Committed is not the same as visible in the feed.",
        actions: [{ label: "Back to home", href: "/home" }],
      };
    case "messaging":
      return {
        title: "Messaging context",
        body: "Direct messages belong on a dedicated communication surface. Keep conversation state separate from content feeds, governance queues, and dispute review.",
        actions: [{ label: "Open profile", href: "/profile" }],
      };
    case "group_create":
      return {
        title: "Group creation context",
        body: "Creation stays separate from the groups directory so discovery and mutation do not compete in the same viewport.",
        actions: [{ label: "Back to groups", href: "/groups" }],
      };
    case "proposal_create":
      return {
        title: "Proposal creation context",
        body: "Governance authoring is separated from the proposals queue so the decision list stays deliberate and scanable.",
        actions: [{ label: "Back to proposals", href: "/proposals" }],
      };
    case "session_devices":
      return {
        title: "Session context",
        body: "Protected write controls should lock when session validity changes. This route should keep current, active, and revoked device states legible.",
      };
    case "settings":
      return {
        title: "Settings context",
        body: "Environment changes should not silently rewrite protocol posture. Keep diagnostics visible in the right rail while the center remains a control surface.",
      };
    case "tools":
      return {
        title: "Diagnostics context",
        body: "Operator-grade debugging can live here, but normal product behavior must not depend on the tools surface being open.",
      };
    case "account":
      return {
        title: "Account context",
        body: "Account standing, roles, and PoH posture belong in a stable profile utility surface rather than scattered inline across hubs.",
      };
    case "profile":
      return {
        title: "Profile context",
        body: "This is the current-account utility surface. It remains adjacent to the primary coordination domains without replacing them.",
        actions: [{ label: "Open home", href: "/home" }],
      };
    case "transactions":
      return {
        title: "Transaction context",
        body: "Recorded-but-not-yet-visible should remain distinct from failure so users do not accidentally resubmit signed actions.",
      };
    case "content_detail":
      return {
        title: "Content context",
        body: "Content detail should foreground the object and related moderation posture while keeping protocol awareness out of the center column.",
      };
    case "thread":
      return {
        title: "Thread context",
        body: "Thread inspection should preserve discussion continuity in the center and keep ambient protocol awareness in the rail.",
      };
    case "juror":
      return {
        title: "Juror context",
        body: "Role-gated review work should stay operational, narrow, and explicit about lock states and eligibility.",
      };
    case "poh":
      return {
        title: "PoH context",
        body: "PoH progression is one of the main protocol eligibility surfaces. Capability changes should become visible here without sending the user hunting across pages.",
      };
    default:
      return {
        title: meta.title,
        body: meta.description,
      };
  }
}

export default function AppRightRail({ route, meta, sessionHealth }: { route: RouteMatch; meta: RouteMeta; sessionHealth?: SessionHealth }): JSX.Element {
  const base = getApiBaseUrl();
  const session = getSession();
  const account = String(session?.account || "").trim();
  const { state: accountState, loading: accountLoading, lastUpdatedAt, refresh: refreshAccountState } = useAccount();
  const [statusView, setStatusView] = useState<Record<string, unknown> | null>(null);
  const [pendingWork, setPendingWork] = useState<PendingWorkSummary>({
    items: [],
    counts: { total: 0, assigned: 0, available: 0, proposals: 0, disputes: 0, memberships: 0 },
  });
  const [proposalDetail, setProposalDetail] = useState<Record<string, unknown> | null>(null);
  const [disputeDetail, setDisputeDetail] = useState<Record<string, unknown> | null>(null);
  const [groupDetail, setGroupDetail] = useState<Record<string, unknown> | null>(null);
  const [groupCount, setGroupCount] = useState<number>(0);
  const [refreshingRail, setRefreshingRail] = useState<boolean>(false);
  const [railRefreshedAt, setRailRefreshedAt] = useState<number | null>(null);
  const railRefreshInFlight = useRef<Promise<void> | null>(null);

  const refreshStatus = useCallback(async () => {
    try {
      const raw = await weall.status(base);
      setStatusView(asRecord(raw));
    } catch {
      setStatusView(null);
    }
  }, [base]);

  const refreshContext = useCallback(async () => {
    try {
      const [proposalRes, disputeRes, groupsRes] = await Promise.all([
        weall.proposals({ limit: 100, activeOnly: true, includeSummary: true }, base).catch(() => null),
        weall.disputes({ limit: 100, activeOnly: true, includeSummary: true } as any, base).catch(() => null),
        api.groups.list({ limit: 100 }, base).catch(() => null),
      ]);

      setPendingWork(
        derivePendingWork({
          account,
          proposalsRaw: proposalRes || { items: [] },
          disputesRaw: disputeRes || { items: [] },
          maxItems: 6,
        }),
      );
      setGroupCount(toArray<Record<string, unknown>>(groupsRes && asRecord(groupsRes).items).length);
    } catch {
      setPendingWork({
        items: [],
        counts: { total: 0, assigned: 0, available: 0, proposals: 0, disputes: 0, memberships: 0 },
      });
      setGroupCount(0);
    }
  }, [account, base]);

  const refreshRouteDetail = useCallback(async () => {
    if (route.path === "/proposal/:id" || route.path === "/proposals/:id") {
      const detail = await weall.proposal((route as any).id, base).catch(() => null);
      setProposalDetail(detail ? asRecord(asRecord(detail).proposal || detail) : null);
      setDisputeDetail(null);
      setGroupDetail(null);
      return;
    }
    if (route.path === "/disputes/:id" || route.path === "/disputes/:id/review") {
      const detail = await weall.dispute((route as any).id, base).catch(() => null);
      setDisputeDetail(detail ? asRecord(asRecord(detail).dispute || detail) : null);
      setProposalDetail(null);
      setGroupDetail(null);
      return;
    }
    if (route.path === "/groups/:id") {
      const detail = await api.groups.get((route as any).id, base).catch(() => null);
      setGroupDetail(detail ? asRecord(asRecord(detail).group || detail) : null);
      setProposalDetail(null);
      setDisputeDetail(null);
      return;
    }
    setProposalDetail(null);
    setDisputeDetail(null);
    setGroupDetail(null);
  }, [base, (route as any).id, route.path]);

  const refreshRail = useCallback(async () => {
    if (railRefreshInFlight.current) {
      await railRefreshInFlight.current;
      return;
    }
    const run = (async () => {
      setRefreshingRail(true);
      try {
        await Promise.all([refreshStatus(), refreshContext(), refreshRouteDetail(), refreshAccountState()]);
        setRailRefreshedAt(Date.now());
      } finally {
        setRefreshingRail(false);
        railRefreshInFlight.current = null;
      }
    })();
    railRefreshInFlight.current = run;
    await run;
  }, [refreshAccountState, refreshContext, refreshRouteDetail, refreshStatus]);

  useEffect(() => {
    let cancelled = false;

    const run = async () => {
      try {
        await refreshRail();
      } catch {
        if (!cancelled) setRailRefreshedAt(Date.now());
      }
    };

    void run();
    const timer = window.setInterval(() => {
      if (!document.hidden) void run();
    }, RAIL_REFRESH_INTERVAL_MS);
    const onFocus = () => {
      if (!document.hidden) void run();
    };
    const unsubscribe = subscribeGlobalRefresh((request) => {
      if (refreshTouches(request, ["node", "pending_work", "route", "account"])) {
        void run();
      }
    });

    window.addEventListener("focus", onFocus);
    document.addEventListener("visibilitychange", onFocus);

    return () => {
      cancelled = true;
      unsubscribe();
      window.clearInterval(timer);
      window.removeEventListener("focus", onFocus);
      document.removeEventListener("visibilitychange", onFocus);
    };
  }, [refreshRail]);

  const nodeSummary = useMemo(() => summarizeNodeConnection(statusView, base), [base, statusView]);
  const capabilities = getFrontendCapabilities();
  const capabilitySummary = useMemo(() => {
    const tier = Number(accountState?.poh_tier ?? 0);
    return [
      tier >= 3 ? "Can post" : "Posting locked",
      tier >= 2 ? "Can react/comment" : "Interaction limited",
      capabilities.bootstrapTier3Enabled ? "Bootstrap tier-3 dev path on" : "Bootstrap tier-3 dev path off",
    ];
  }, [accountState?.poh_tier, capabilities.bootstrapTier3Enabled]);

  const contextSummary = useMemo(
    () =>
      deriveContextSummary({
        route,
        meta,
        proposalDetail,
        disputeDetail,
        groupDetail,
        account,
        activeProposalCount: pendingWork.counts.proposals,
        activeDisputeCount: pendingWork.counts.disputes,
        groupCount,
      }),
    [account, disputeDetail, groupCount, groupDetail, meta, pendingWork.counts.disputes, pendingWork.counts.proposals, proposalDetail, route],
  );

  const chainId = String(nodeSummary.chainId || "unknown");
  const nodeHeight = typeof nodeSummary.height === "number" ? `h${nodeSummary.height}` : "height unknown";
  const accountHandle = account || "No account selected";
  const railAgeMs = railRefreshedAt ? Math.max(0, Date.now() - railRefreshedAt) : null;
  const freshnessText = freshnessLabel(railAgeMs);
  const sessionState = sessionHealth?.state || (account ? "active" : "anonymous");
  const tier = Number(accountState?.poh_tier ?? 0);
  const standingFlags = [
    tier ? `Tier ${tier}` : "Tier 0",
    accountState?.locked ? "Locked" : "Unlocked",
    accountState?.banned ? "Banned" : "Not banned",
  ];

  return (
    <aside id="protocol-awareness-rail" className="appShellRightRail" aria-label="Protocol awareness and route context">
      <Panel title="Protocol awareness">
        <div className="railPrimaryLine">
          <strong>{meta.title}</strong>
          <span className="railMetaPill railMetaPill-warn">{meta.mode}</span>
        </div>
        <div className="railSupportText">{meta.dataContract.contextPanelData}</div>
        <div className="railPillRow">
          <span className={`railMetaPill ${freshnessText === "Fresh" ? "railMetaPill-ok" : freshnessText === "Aging" ? "railMetaPill-warn" : "railMetaPill-ready"}`}>{freshnessText}</span>
          <span className="railMetaPill">Session {sessionState.replace(/_/g, " ")}</span>
        </div>
        <div className="railTimestamp">{formatAgo(railAgeMs)}</div>
        <div className="railActionRow">
          <button
            className="railSecondaryAction"
            onClick={() => {
              requestGlobalRefresh({ reason: "manual-awareness-refresh", scopes: ["account", "session", "node", "pending_work", "route"] });
              void refreshRail();
            }}
            disabled={refreshingRail}
          >
            {refreshingRail ? "Refreshing…" : "Refresh awareness"}
          </button>
          <button
            className="railSecondaryAction"
            onClick={() => {
              requestGlobalRefresh({ reason: "session-recovery-open", scopes: ["account", "session", "route"] });
              nav("/session");
            }}
          >
            Session recovery
          </button>
        </div>
      </Panel>

      <Panel title="Account state">
        <div className="railPrimaryLine">
          <strong>{accountHandle}</strong>
          <span className="railMetaPill">{tier ? `PoH ${tier}` : "PoH pending"}</span>
        </div>
        <div className="railSupportText">{accountLoading ? "Refreshing account posture…" : standingFlags.join(" · ")}</div>
        <div className="railPillRow">
          {capabilitySummary.map((entry: string) => (
            <span key={entry} className="railCapabilityPill">
              {entry}
            </span>
          ))}
        </div>
        <div className="railTimestamp">{lastUpdatedAt ? `Account refreshed ${new Date(lastUpdatedAt).toLocaleTimeString()}` : "Awaiting account snapshot"}</div>
        <div className="railActionRow">
          <button
            className="railSecondaryAction"
            onClick={() => {
              requestGlobalRefresh({ reason: "manual-account-refresh", scopes: ["account", "session", "pending_work", "route"] });
              void refreshRail();
            }}
            disabled={accountLoading || refreshingRail}
          >
            {accountLoading || refreshingRail ? "Refreshing account…" : "Refresh account"}
          </button>
          <button className="railSecondaryAction" onClick={() => nav(account ? `/account/${encodeURIComponent(account)}` : "/login")}>
            {account ? "Open account" : "Open login"}
          </button>
        </div>
      </Panel>

      <Panel title="Node state">
        <div className="railPrimaryLine">
          <strong>{nodeSummary.label}</strong>
          <span className={`railMetaPill railMetaPill-${nodeSummary.phase}`}>{nodeSummary.phase}</span>
        </div>
        <div className="railSupportText">{[chainId, nodeHeight, nodeSummary.profile || "profile unknown"].join(" · ")}</div>
        <div className="railSupportText">{nodeSummary.detail || base}</div>
        <div className="railActionRow">
          <button className="railSecondaryAction" onClick={() => void refreshRail()} disabled={refreshingRail}>
            {refreshingRail ? "Refreshing…" : "Refresh state"}
          </button>
        </div>
      </Panel>

      <Panel title="Pending work">
        {pendingWork.items.length ? (
          <div className="rightRailList">
            {pendingWork.items.map((item: PendingWorkItem) => (
              <button key={`${item.kind}:${item.id}`} className="rightRailListItem" onClick={() => nav(item.href)}>
                <div className="rightRailListTitleRow">
                  <strong>{item.label}</strong>
                  <span className="railListKind">{item.kind}</span>
                </div>
                <div className="railSupportText">{item.detail}</div>
                {item.emphasis ? <div className="railTimestamp">{item.emphasis === "assigned" ? "Assigned to you" : "Available to review"}</div> : null}
                <div className="railPendingMetaRow">
                  <span className={`railUrgencyPill railUrgencyPill-${item.urgency}`}>{item.urgency} urgency</span>
                  <span className="railSourceTag">{item.source.replace(/-/g, " ")}</span>
                </div>
              </button>
            ))}
          </div>
        ) : (
          <div className="railSupportText">No open protocol work is currently surfaced for this account context.</div>
        )}
        <div className="railPendingSummary">
          <span>{pendingWork.counts.assigned} assigned</span>
          <span>{pendingWork.counts.available} actionable</span>
          <span>{pendingWork.counts.proposals} proposals</span>
          <span>{pendingWork.counts.disputes} disputes</span>
          <span>{pendingWork.counts.memberships} memberships</span>
        </div>
        <div className="railActionRow railActionRow-compact">
          <button className="railSecondaryAction" onClick={() => nav('/proposals')}>Open proposals</button>
          <button className="railSecondaryAction" onClick={() => nav('/disputes')}>Open disputes</button>
          <button className="railSecondaryAction" onClick={() => nav('/groups')}>Open groups</button>
        </div>
      </Panel>

      <Panel title={contextSummary.title}>
        <div className="railSupportText">{contextSummary.body}</div>
        {contextSummary.actions?.length ? (
          <div className="railActionRow">
            {contextSummary.actions.map((action) => (
              <button key={`${contextSummary.title}:${action.href}`} className="railSecondaryAction" onClick={() => nav(action.href)}>
                {action.label}
              </button>
            ))}
          </div>
        ) : null}
      </Panel>
    </aside>
  );
}
