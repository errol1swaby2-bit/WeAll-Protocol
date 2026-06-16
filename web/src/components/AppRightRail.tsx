import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { api, getApiBaseUrl, weall } from "../api/weall";
import { getSession, type SessionHealth } from "../auth/session";
import { useAccount } from "../context/AccountContext";
import { pohTierLabel, v2PohTier } from "../lib/gates";
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
        body: `You have ${asCountLabel("decision", activeProposalCount)} and ${asCountLabel("report", activeDisputeCount)} currently surfaced. Home stays social-first while still pointing you to decisions and reviews when they matter.`,
        actions: [
          { label: "Open feed", href: "/feed" },
          { label: "Open decisions", href: "/decisions" },
        ],
      };
    case "feed":
      return {
        title: "Feed context",
        body: `${asCountLabel("decision", activeProposalCount)} and ${asCountLabel("report", activeDisputeCount)} are available in their own sections. This page stays focused on posts and conversations.`,
        actions: [{ label: "Create post", href: "/create" }],
      };
    case "groups":
      return {
        title: "Groups context",
        body: `${asCountLabel("group", groupCount)} loaded for discovery. Group creation stays in a focused action flow so browsing remains simple.`,
      };
    case "group_detail": {
      const routeGroupId = route.path === "/groups/:id" ? route.id : "";
      const groupName = String(groupDetail?.name || groupDetail?.title || routeGroupId || "Group");
      const policy = String(groupDetail?.policy || groupDetail?.membership_policy || "Membership status is not surfaced yet.");
      return {
        title: "Group context",
        body: `${groupName}. ${policy}`,
        actions: [{ label: "Back to groups", href: "/groups" }],
      };
    }
    case "decisions":
      return {
        title: "Decisions context",
        body: `${asCountLabel("decision", activeProposalCount)} currently surfaced. The hub should help users understand what is open, what they voted on, and what passed.`,
      };
    case "decision_detail": {
      const title = String(proposalDetail?.title || proposalDetail?.proposal_title || "Decision detail");
      const stage = String(proposalDetail?.stage || proposalDetail?.status || "status unknown");
      return {
        title: "Decision context",
        body: `${title}. Current status: ${stage}. Vote controls should derive from authoritative decision state rather than button-local assumptions.`,
        actions: [{ label: "Back to decisions", href: "/decisions" }],
      };
    }
    case "reports":
      return {
        title: "Reports context",
        body: `${asCountLabel("report", activeDisputeCount)} currently surfaced. Report pages should explain review status without exposing reviewer-only actions to everyone.`,
      };
    case "report_detail": {
      const stage = String(disputeDetail?.stage || disputeDetail?.status || "status unknown");
      const reason = String(disputeDetail?.reason || disputeDetail?.summary || "Reason not surfaced yet.");
      return {
        title: "Report context",
        body: `Current status: ${stage}. ${reason}`,
        actions: [{ label: "Back to reports", href: "/reports" }],
      };
    }
    case "review_item": {
      const stage = String(disputeDetail?.stage || disputeDetail?.status || "status unknown");
      const reviewerStatus = disputeJurorStatus(disputeDetail, account || "") || "assignment status not surfaced";
      return {
        title: "Review context",
        body: `This is one assigned review item. Current status: ${stage}. Reviewer posture: ${reviewerStatus}. Final choices belong here, not on the queue.`,
        actions: [
          { label: "Open report detail", href: route.path === "/reviews/:id" ? `/reports/${encodeURIComponent(String((route as any).id || ""))}` : "/reports" },
          { label: "Back to Review Center", href: "/reviews" },
        ],
      };
    }
    case "post_create":
      return {
        title: "Composer context",
        body: "Post creation should show saving, done, needs attention, or failed states. Do not show final success until the result is visible or confirmed.",
        actions: [{ label: "Back to feed", href: "/feed" }],
      };
    case "messaging":
      return {
        title: "Messaging context",
        body: "Messages belong on a dedicated communication surface. Keep conversation state separate from posts, decisions, and reports.",
        actions: [{ label: "Open profile", href: "/profile" }],
      };
    case "group_create":
      return {
        title: "Group creation context",
        body: "Creation stays separate from the groups directory so discovery and saving do not compete in the same viewport.",
        actions: [{ label: "Back to groups", href: "/groups" }],
      };
    case "decision_create":
      return {
        title: "Decision creation context",
        body: "Decision authoring is separated from the decisions queue so the list stays deliberate and scanable.",
        actions: [{ label: "Back to decisions", href: "/decisions" }],
      };
    case "session_devices":
      return {
        title: "Session context",
        body: "Action controls should lock when session validity changes. This route keeps current, active, and revoked device states legible.",
      };
    case "settings":
      return {
        title: "Settings context",
        body: "Settings should stay user-facing. Advanced network details belong behind the advanced mode toggle.",
      };
    case "advanced":
      return {
        title: "Advanced context",
        body: "Technical inspection can live here, but normal product behavior must not depend on this surface being open.",
      };
    case "account":
      return {
        title: "Account context",
        body: "Account status and trusted responsibilities belong in stable profile surfaces rather than scattered inline across hubs.",
      };
    case "profile":
      return {
        title: "Profile context",
        body: "This is the current-account profile surface. It remains adjacent to the primary social sections without replacing them.",
        actions: [{ label: "Open home", href: "/home" }],
      };
    case "transactions":
      return {
        title: "Technical history context",
        body: "Advanced action history separates recorded-but-not-yet-visible from failure so users do not accidentally resubmit actions.",
      };
    case "content_detail":
      return {
        title: "Post context",
        body: "Post detail should foreground the conversation and review status while keeping technical records collapsed by default.",
      };
    case "thread":
      return {
        title: "Thread context",
        body: "Thread inspection should preserve discussion continuity in the center and keep helpful account context in the panel.",
      };
    case "reviews":
      return {
        title: "Review Center context",
        body: "Review work stays lane-separated: content review, dispute juror review, PoH async review, and PoH live review each disclose assignment, opt-in, and lock states.",
      };
    case "verification":
      return {
        title: "Verification context",
        body: "Account Verification shows the current account level, next step, and trusted responsibilities without requiring users to understand protocol internals.",
      };
    default:
      return {
        title: meta.title,
        body: meta.description,
      };
  }
}

export default function AppRightRail({
  route,
  meta,
  sessionHealth,
  showAdvancedMode = false,
}: {
  route: RouteMatch;
  meta: RouteMeta;
  sessionHealth?: SessionHealth;
  showAdvancedMode?: boolean;
}): JSX.Element {
  const base = getApiBaseUrl();
  const session = getSession();
  const account = String(session?.account || "").trim();
  const { state: accountState, loading: accountLoading, lastUpdatedAt, refresh: refreshAccountState } = useAccount();
  const [statusView, setStatusView] = useState<Record<string, unknown> | null>(null);
  const [pendingWork, setPendingWork] = useState<PendingWorkSummary>({
    items: [],
    counts: { total: 0, assigned: 0, available: 0, decisions: 0, reports: 0, proposals: 0, disputes: 0, memberships: 0 },
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
        counts: { total: 0, assigned: 0, available: 0, decisions: 0, reports: 0, proposals: 0, disputes: 0, memberships: 0 },
      });
      setGroupCount(0);
    }
  }, [account, base]);

  const refreshRouteDetail = useCallback(async () => {
    if (route.path === "/decisions/:id") {
      const detail = await weall.proposal((route as any).id, base).catch(() => null);
      setProposalDetail(detail ? asRecord(asRecord(detail).proposal || detail) : null);
      setDisputeDetail(null);
      setGroupDetail(null);
      return;
    }
    if (route.path === "/reports/:id" || route.path === "/reviews/:id") {
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
  const capabilitySummary = useMemo(() => {
    const tier = v2PohTier(accountState?.poh_tier ?? 0);
    return [
      tier >= 2 ? "Can create posts" : "Posting locked",
      tier >= 2 ? "Can react and report" : "Interaction limited",
      accountState?.locked ? "Account locked" : accountState?.banned ? "Account banned" : "Account in good standing",
    ];
  }, [accountState?.poh_tier, accountState?.locked, accountState?.banned]);

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
  const tier = v2PohTier(accountState?.poh_tier ?? 0);
  const standingFlags = [
    pohTierLabel(tier),
    accountState?.locked ? "Locked" : "Unlocked",
    accountState?.banned ? "Banned" : "Not banned",
  ];

  return (
    <aside id="protocol-awareness-rail" className="appShellRightRail" aria-label="Helpful side panel">
      <Panel title="Helpful context">
        <div className="railPrimaryLine">
          <strong>{meta.title}</strong>
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
            {refreshingRail ? "Refreshing…" : "Refresh panel"}
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
          <span className="railMetaPill">{pohTierLabel(tier)}</span>
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

      {showAdvancedMode ? (
        <Panel title="Advanced network state">
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
      ) : null}

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
          <div className="railSupportText">No open review, decision, or group work is currently surfaced for this account.</div>
        )}
        <div className="railPendingSummary">
          <span>{pendingWork.counts.assigned} assigned</span>
          <span>{pendingWork.counts.available} actionable</span>
          <span>{pendingWork.counts.proposals} decisions</span>
          <span>{pendingWork.counts.disputes} reports</span>
          <span>{pendingWork.counts.memberships} memberships</span>
        </div>
        <div className="railActionRow railActionRow-compact">
          <button className="railSecondaryAction" onClick={() => nav('/decisions')}>Open decisions</button>
          <button className="railSecondaryAction" onClick={() => nav('/reports')}>Open reports</button>
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
