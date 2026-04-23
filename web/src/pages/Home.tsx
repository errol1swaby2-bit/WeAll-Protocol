import React, { useEffect, useMemo, useState } from "react";

import { api, getApiBaseUrl, weall } from "../api/weall";
import { getSession } from "../auth/session";
import { useTxQueue } from "../hooks/useTxQueue";
import { nav } from "../lib/router";
import { refreshTouches, subscribeGlobalRefresh } from "../lib/revalidation";
import { summarizeNodeConnection } from "../lib/status";

type PendingSummary = {
  activeProposals: number;
  assignedDisputes: number;
  availableDisputes: number;
  unreadLikeItems: number;
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
    <article className="card summaryTile">
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

function HomeNotificationRow({ label, detail, href }: { label: string; detail: string; href: string }): JSX.Element {
  return (
    <button className="missionChecklistRow missionActionCard" onClick={() => nav(href)}>
      <div>
        <div className="missionChecklistLabel">{label}</div>
        <div className="missionChecklistHint">{detail}</div>
      </div>
      <span className="statusPill">Open</span>
    </button>
  );
}

export default function Home(): JSX.Element {
  const base = useMemo(() => getApiBaseUrl(), []);
  const session = getSession();
  const account = String(session?.account || "").trim();
  const { items: txItems } = useTxQueue();
  const [statusView, setStatusView] = useState<any>(null);
  const [pending, setPending] = useState<PendingSummary>({
    activeProposals: 0,
    assignedDisputes: 0,
    availableDisputes: 0,
    unreadLikeItems: 0,
  });
  const [groupCount, setGroupCount] = useState(0);
  const [loading, setLoading] = useState(false);

  const pendingTx = txItems.filter((item) => ["validating", "submitting", "recorded", "refreshing"].includes(item.status)).length;
  const failedTx = txItems.filter((item) => item.status === "failed").length;

  async function loadHomeState(): Promise<void> {
    setLoading(true);
    try {
      const [statusRes, proposalsRes, disputesRes, groupsRes] = await Promise.all([
        weall.status(base).catch(() => null),
        weall.proposals({ limit: 100, activeOnly: true, includeSummary: true }, base).catch(() => ({ items: [] })),
        weall.disputes({ limit: 100, activeOnly: true, includeSummary: true } as any, base).catch(() => ({ items: [] })),
        api.groups.list({ limit: 100 }, base).catch(() => ({ items: [] })),
      ]);
      setStatusView(statusRes);
      const proposalItems = Array.isArray((proposalsRes as any)?.items) ? (proposalsRes as any).items : [];
      const disputeItems = Array.isArray((disputesRes as any)?.items) ? (disputesRes as any).items : [];
      const groups = Array.isArray((groupsRes as any)?.items) ? (groupsRes as any).items : [];
      const accountLower = account.toLowerCase();
      const assignedDisputes = disputeItems.filter((item: any) => {
        const jurors = Array.isArray(item?.jurors) ? item.jurors : [];
        return jurors.some((juror: any) => String(juror?.account || juror?.juror || "").trim().toLowerCase() === accountLower);
      }).length;
      setPending({
        activeProposals: proposalItems.length,
        assignedDisputes,
        availableDisputes: disputeItems.length,
        unreadLikeItems: pendingTx + failedTx,
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
      if (refreshTouches(request, ["node", "pending_work", "route", "account"])) {
        void loadHomeState();
      }
    });
    return unsubscribe;
  }, [base, account]);

  const nodeSummary = summarizeNodeConnection(statusView, base);
  const notificationCount = pending.activeProposals + pending.assignedDisputes + pendingTx + failedTx;

  return (
    <div className="pageStack homeMissionControl">
      <section className="card heroCard missionHeroCard">
        <div className="cardBody formStack">
          <div className="missionHeroTop">
            <div>
              <div className="eyebrow">Home directory</div>
              <h1 className="heroTitle heroTitleSm">Protocol orientation and pending work</h1>
              <p className="heroText">
                Home is now a lightweight directory and notification hub. Use it to see what needs attention, then jump into the correct domain surface without mixing feeds, governance, and disputes in one center column.
              </p>
            </div>
            <div className="missionHeroBadges">
              <span className={`statusPill ${nodeSummary.phase === "online" ? "ok" : ""}`}>{nodeSummary.label}</span>
              <span className={`statusPill ${notificationCount ? "warning" : "ok"}`}>{notificationCount ? `${notificationCount} items need attention` : "No urgent items"}</span>
              <span className="statusPill mono">{account || "No active account"}</span>
            </div>
          </div>

          <section className="surfaceBoundaryBar" aria-label="Home route contract">
            <div className="surfaceBoundaryHeader">
              <div>
                <h2 className="surfaceBoundaryTitle">Home is not the content feed anymore.</h2>
                <p className="surfaceBoundaryText">
                  This route stays light: shortcuts, notifications, route directory, and transaction awareness. The dedicated content surface lives on Feed.
                </p>
              </div>
              <span className="statusPill">Hub surface</span>
            </div>
            <div className="surfaceBoundaryList">
              <span className="surfaceBoundaryTag">Center: directory and notification summary</span>
              <span className="surfaceBoundaryTag">Feed stays separate</span>
              <span className="surfaceBoundaryTag">Governance and disputes stay separate</span>
            </div>
          </section>
        </div>
      </section>

      <section className="surfaceSummaryGrid">
        <DirectoryCard eyebrow="Feed" title="Content" body="Open the dedicated content surface for posts, comments, likes, and flags." cta="Open feed" href="/feed" tone="primary" />
        <DirectoryCard eyebrow="Groups" title={`${groupCount} visible groups`} body="Group discovery and membership live on their own hub." cta="Open groups" href="/groups" />
        <DirectoryCard eyebrow="Governance" title={`${pending.activeProposals} active proposals`} body="Proposal review and voting stay structured and separate from social browsing." cta="Open governance" href="/proposals" />
        <DirectoryCard eyebrow="Disputes" title={`${pending.availableDisputes} open disputes`} body="Flagged-content adjudication remains a formal case workflow." cta="Open disputes" href="/disputes" />
      </section>

      <section className="card">
        <div className="cardBody formStack">
          <div className="sectionHead">
            <div>
              <div className="eyebrow">Notifications</div>
              <h2 className="cardTitle">What needs attention now</h2>
              <div className="cardDesc">This list is intentionally lightweight. It should route you to the correct surface instead of embedding the workflow here.</div>
            </div>
            <div className="statusSummary">
              <button className="btn" onClick={() => void loadHomeState()} disabled={loading}>{loading ? "Refreshing…" : "Refresh home"}</button>
            </div>
          </div>

          <div className="formStack">
            <HomeNotificationRow label="Feed route" detail="Browse or publish from the dedicated expression surface." href="/feed" />
            <HomeNotificationRow label="Pending governance work" detail={pending.activeProposals ? `${pending.activeProposals} active proposal${pending.activeProposals === 1 ? "" : "s"} may need review.` : "No active proposals are surfaced right now."} href="/proposals" />
            <HomeNotificationRow label="Juror work" detail={pending.assignedDisputes ? `${pending.assignedDisputes} dispute assignment${pending.assignedDisputes === 1 ? "" : "s"} appear tied to this account.` : pending.availableDisputes ? `${pending.availableDisputes} open dispute${pending.availableDisputes === 1 ? "" : "s"} are visible on the queue.` : "No active disputes are visible right now."} href="/disputes" />
            <HomeNotificationRow label="Transaction queue" detail={pendingTx ? `${pendingTx} signed action${pendingTx === 1 ? "" : "s"} still settling.` : failedTx ? `${failedTx} recent action${failedTx === 1 ? "" : "s"} failed and may need review.` : "No local transaction backlog is visible right now."} href="/transactions" />
            <HomeNotificationRow label="Session and devices" detail="Use the session utility page whenever write posture, signer posture, or device validity needs attention." href="/session" />
          </div>
        </div>
      </section>
    </div>
  );
}
