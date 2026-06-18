import React, { useEffect, useMemo, useState } from "react";

import { api, getApiBaseUrl, weall } from "../api/weall";
import { getSession } from "../auth/session";
import { useTxQueue } from "../hooks/useTxQueue";
import { nav } from "../lib/router";
import { refreshTouches, subscribeGlobalRefresh } from "../lib/revalidation";
import { derivePendingWork } from "../lib/pendingWork";

type PendingSummary = {
  activeProposals: number;
  assignedDisputes: number;
  availableDisputes: number;
};

function DirectoryCard({
  eyebrow,
  title,
  body,
  cta,
  href,
  tone,
}: {
  eyebrow: string;
  title: string;
  body: string;
  cta: string;
  href: string;
  tone?: "primary" | "neutral";
}): JSX.Element {
  return (
    <article className="card summaryTile socialHomeCard">
      <div className="cardBody formStack">
        <span className="statLabel">{eyebrow}</span>
        <strong className="summaryTileValue">{title}</strong>
        <span className="summaryTileHint">{body}</span>
        <div>
          <button className={`btn ${tone === "primary" ? "btnPrimary" : ""}`.trim()} onClick={() => nav(href)}>
            {cta}
          </button>
        </div>
      </div>
    </article>
  );
}

function HomeNotificationRow({ label, detail, href, open = false }: { label: string; detail: string; href: string; open?: boolean }): JSX.Element {
  return (
    <button className="missionChecklistRow missionActionCard" onClick={() => nav(href)}>
      <div>
        <div className="missionChecklistLabel">{label}</div>
        <div className="missionChecklistHint">{detail}</div>
      </div>
      <span className={`statusPill ${open ? "warning" : ""}`.trim()}>{open ? "Needs attention" : "Open"}</span>
    </button>
  );
}

export default function Home(): JSX.Element {
  const base = useMemo(() => getApiBaseUrl(), []);
  const session = getSession();
  const account = String(session?.account || "").trim();
  const { items: txItems } = useTxQueue();
  const [pending, setPending] = useState<PendingSummary>({
    activeProposals: 0,
    assignedDisputes: 0,
    availableDisputes: 0,
  });
  const [groupCount, setGroupCount] = useState(0);
  const [loading, setLoading] = useState(false);

  const pendingActions = txItems.filter((item) => ["validating", "submitting", "recorded", "refreshing"].includes(item.status)).length;
  const failedActions = txItems.filter((item) => item.status === "failed").length;

  async function loadHomeState(): Promise<void> {
    setLoading(true);
    try {
      const [proposalsRes, disputesRes, groupsRes] = await Promise.all([
        weall.proposals({ limit: 100, activeOnly: true, includeSummary: true }, base).catch(() => ({ items: [] })),
        weall.disputes({ limit: 100, activeOnly: true, includeSummary: true } as any, base).catch(() => ({ items: [] })),
        api.groups.list({ limit: 100 }, base).catch(() => ({ items: [] })),
      ]);
      const proposalItems = Array.isArray((proposalsRes as any)?.items) ? (proposalsRes as any).items : [];
      const disputeItems = Array.isArray((disputesRes as any)?.items) ? (disputesRes as any).items : [];
      const groups = Array.isArray((groupsRes as any)?.items) ? (groupsRes as any).items : [];
      const pendingWork = derivePendingWork({
        account,
        proposalsRaw: { items: proposalItems },
        disputesRaw: { items: disputeItems },
        maxItems: 100,
      });
      const assignedReviewReports = pendingWork.items.filter((item) => item.kind === "report" && item.assigned).length;
      const visibleReviewReports = pendingWork.items.filter((item) => item.kind === "report").length;
      setPending({
        activeProposals: pendingWork.counts.decisions,
        assignedDisputes: assignedReviewReports,
        availableDisputes: visibleReviewReports,
      });
      setGroupCount(groups.length);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void loadHomeState();
  }, [base, account]);

  useEffect(() => {
    const unsubscribe = subscribeGlobalRefresh((request) => {
      if (refreshTouches(request, ["pending_work", "route", "account"])) {
        void loadHomeState();
      }
    });
    return unsubscribe;
  }, [base, account]);

  const attentionCount = pending.activeProposals + pending.assignedDisputes + pendingActions + failedActions;
  const displayAccount = account ? `${account.slice(0, 10)}${account.length > 10 ? "…" : ""}` : "No active account";

  return (
    <div className="pageStack homeMissionControl socialHomePage">
      <section className="card heroCard missionHeroCard socialHomeHero">
        <div className="cardBody formStack">
          <div className="missionHeroTop">
            <div>
              <div className="eyebrow">Home</div>
              <h1 className="heroTitle heroTitleSm">Welcome back to WeAll</h1>
              <p className="heroText">
                Catch up on posts, find groups, vote on community decisions, and see anything that needs your attention.
              </p>
            </div>
            <div className="missionHeroBadges">
              <span className={`statusPill ${attentionCount ? "warning" : "ok"}`}>{attentionCount ? `${attentionCount} update${attentionCount === 1 ? "" : "s"}` : "All caught up"}</span>
              <span className="statusPill">{displayAccount}</span>
            </div>
          </div>

          <div className="socialHeroActions" aria-label="Primary social actions">
            <button className="btn btnPrimary" onClick={() => nav("/create")}>Create post</button>
            <button className="btn" onClick={() => nav("/feed")}>Open feed</button>
            <button className="btn" onClick={() => nav("/groups")}>Find groups</button>
            <button className="btn" onClick={() => nav("/verification")}>Account verification</button>
          </div>
        </div>
      </section>

      <section className="surfaceSummaryGrid socialShortcutGrid">
        <DirectoryCard eyebrow="Feed" title="Posts and conversations" body="Read what people are sharing and join the conversation when your account is ready." cta="Open feed" href="/feed" tone="primary" />
        <DirectoryCard eyebrow="Groups" title={`${groupCount} group${groupCount === 1 ? "" : "s"}`} body="Find communities, join the ones that fit, and see their latest activity." cta="Browse groups" href="/groups" />
        <DirectoryCard eyebrow="Decisions" title={`${pending.activeProposals} open`} body="Vote on community choices and review results in plain language." cta="Open decisions" href="/decisions" />
        <DirectoryCard eyebrow="Reviews" title={`${pending.availableDisputes} report${pending.availableDisputes === 1 ? "" : "s"}`} body="Help review community issues when you are selected and eligible." cta="Open Review Center" href="/reviews" />
      </section>

      <section className="card">
        <div className="cardBody formStack">
          <div className="sectionHead">
            <div>
              <div className="eyebrow">Updates</div>
              <h2 className="cardTitle">What needs attention</h2>
              <div className="cardDesc">A simple list of places worth checking now.</div>
            </div>
            <div className="statusSummary">
              <button className="btn" onClick={() => void loadHomeState()} disabled={loading}>{loading ? "Refreshing…" : "Refresh"}</button>
            </div>
          </div>

          <div className="formStack">
            <HomeNotificationRow label="Feed" detail="See recent public posts and conversations." href="/feed" />
            <HomeNotificationRow label="Open decisions" detail={pending.activeProposals ? `${pending.activeProposals} community decision${pending.activeProposals === 1 ? "" : "s"} may need votes.` : "No open decisions are surfaced right now."} href="/decisions" open={pending.activeProposals > 0} />
            <HomeNotificationRow label="Review work" detail={pending.assignedDisputes ? `${pending.assignedDisputes} review assignment${pending.assignedDisputes === 1 ? "" : "s"} appear tied to this account.` : pending.availableDisputes ? `${pending.availableDisputes} open report${pending.availableDisputes === 1 ? "" : "s"} are visible.` : "No active reports are visible right now."} href="/reviews" open={pending.assignedDisputes > 0} />
            <HomeNotificationRow label="Account and devices" detail={failedActions ? `${failedActions} recent action${failedActions === 1 ? "" : "s"} may need attention.` : pendingActions ? `${pendingActions} recent action${pendingActions === 1 ? "" : "s"} still finishing.` : "Your local action queue looks clear."} href="/session" open={failedActions > 0 || pendingActions > 0} />
          </div>
        </div>
      </section>
    </div>
  );
}
