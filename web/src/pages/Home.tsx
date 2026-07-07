import React, { useEffect, useMemo, useState } from "react";

import { api, getApiBaseUrl, weall } from "../api/weall";
import ProtocolStatusSummary from "../components/ProtocolStatusSummary";
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


function FirstRunStepCard({
  step,
  title,
  body,
  href,
  cta,
  status,
}: {
  step: string;
  title: string;
  body: string;
  href: string;
  cta: string;
  status: string;
}): JSX.Element {
  return (
    <article className="summaryCard firstRunStepCard">
      <div className="summaryCardLabel">{step}</div>
      <div className="summaryCardValue">{title}</div>
      <div className="summaryCardText">{body}</div>
      <div className="buttonRow">
        <button className="btn" onClick={() => nav(href)}>{cta}</button>
        <span className="statusPill">{status}</span>
      </div>
    </article>
  );
}

function RoleBoundaryCard({
  role,
  authority,
  safeNextStep,
}: {
  role: string;
  authority: string;
  safeNextStep: string;
}): JSX.Element {
  return (
    <article className="summaryCard roleBoundaryCard">
      <div className="summaryCardLabel">Role</div>
      <div className="summaryCardValue">{role}</div>
      <div className="summaryCardText"><strong>Authority:</strong> {authority}</div>
      <div className="summaryCardText"><strong>Safe next step:</strong> {safeNextStep}</div>
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

      <ProtocolStatusSummary />

      <section className="card" aria-label="First 15 minutes guided tester journey">
        <div className="cardBody formStack">
          <div className="sectionHead">
            <div>
              <div className="eyebrow">First 15 minutes</div>
              <h2 className="cardTitle">Guided tester journey</h2>
              <div className="cardDesc">
                Start here when you are clean-cloning or opening WeAll for the first time. The path is intentionally safe: inspect node truth, create or restore an account, read public civic state, then track any submitted action through the transaction lifecycle.
              </div>
            </div>
            <button className="btn" onClick={() => nav("/transactions")}>Open transaction status</button>
          </div>
          <div className="summaryCardGrid">
            <FirstRunStepCard
              step="Step 1"
              title="Confirm node and chain"
              body="Check the current API node, chain_id, block height, finalized height, and authority level before trusting what the app shows."
              href="/node"
              cta="Check node"
              status="Read-only"
            />
            <FirstRunStepCard
              step="Step 2"
              title={account ? "Review your active account" : "Create or restore account"}
              body="Your browser-held signer lets you submit account-scoped actions, but local keys and UI state do not grant protocol authority."
              href={account ? `/account/${encodeURIComponent(account)}` : "/login"}
              cta={account ? "Open account" : "Open login"}
              status={account ? "Account selected" : "No account yet"}
            />
            <FirstRunStepCard
              step="Step 3"
              title="Verify participation level"
              body="PoH and account standing control which civic actions are available. The UI should explain locked actions without implying real-world identity certainty."
              href="/verification"
              cta="Open verification"
              status="Eligibility"
            />
            <FirstRunStepCard
              step="Step 4"
              title="Read the public civic loop"
              body="Browse feed, groups, decisions, reports, and reviews. Protocol-native social and civic activity is public-readable."
              href="/feed"
              cta="Open feed"
              status="Public"
            />
            <FirstRunStepCard
              step="Step 5"
              title="Submit carefully, then track status"
              body="After any mutation, use transaction status. Submitted, locally accepted, pending, included, finalized, and rejected are different states."
              href="/transactions"
              cta="Track actions"
              status="No confirmation shortcut"
            />
          </div>
        </div>
      </section>

      <section className="card" aria-label="Role and authority boundaries">
        <div className="cardBody formStack">
          <div className="sectionHead">
            <div>
              <div className="eyebrow">Role boundaries</div>
              <h2 className="cardTitle">Know what your current role can and cannot do</h2>
              <div className="cardDesc">
                These labels describe authority boundaries for testers. Browser state, frontend buttons, local scripts, seed hints, and node switching never create validator, economics, helper, storage, or upgrade authority by themselves.
              </div>
            </div>
          </div>
          <div className="summaryCardGrid">
            <RoleBoundaryCard role="Observer" authority="Read, sync, inspect, and forward where configured; cannot validate or finalize blocks." safeNextStep="Check chain identity, state sync, and public surfaces." />
            <RoleBoundaryCard role="User" authority="Submit signed account actions allowed by account standing and protocol rules." safeNextStep="Create/restore an account, verify eligibility, and track receipts." />
            <RoleBoundaryCard role="Node operator" authority="Operate local infrastructure and diagnostics; scripts remain read-only unless protocol state permits action." safeNextStep="Open Personal Node and follow safe diagnostics." />
            <RoleBoundaryCard role="Validator candidate" authority="Record readiness for controlled rehearsal; signing remains fail-closed until chain state authorizes it." safeNextStep="Use the validator rehearsal runbook only after operator setup." />
            <RoleBoundaryCard role="Validator" authority="Only active by protocol state in controlled rehearsal; public multi-validator BFT remains unclaimed." safeNextStep="Do not claim public validator readiness without external transcript evidence." />
          </div>
        </div>
      </section>

      <section className="surfaceSummaryGrid socialShortcutGrid">
        <DirectoryCard eyebrow="Feed" title="Posts and public replies" body="Read what people are sharing and join public replies when your account is ready." cta="Open feed" href="/feed" tone="primary" />
        <DirectoryCard eyebrow="Groups" title={`${groupCount} group${groupCount === 1 ? "" : "s"}`} body="Find communities, join the ones that fit, and see their latest activity." cta="Browse groups" href="/groups" />
        <DirectoryCard eyebrow="Decisions" title={`${pending.activeProposals} open`} body="Vote on community choices and review results in plain language." cta="Open decisions" href="/decisions" />
        <DirectoryCard eyebrow="Reviews" title={`${pending.availableDisputes} report${pending.availableDisputes === 1 ? "" : "s"}`} body="Help review community issues when you are selected and eligible." cta="Open Review Center" href="/reviews" />
        <DirectoryCard eyebrow="Economics" title="Locked" body="WeCoin and fees stay locked by default during public observer / closed-testnet review." cta="Check economics status" href="/economics" />
      </section>

      <section className="card" aria-label="Average-user launch-prep walkthrough">
        <div className="cardBody formStack">
          <div className="sectionHead">
            <div>
              <div className="eyebrow">Reviewer path</div>
              <h2 className="cardTitle">Average-user launch-prep walkthrough</h2>
              <div className="cardDesc">
                Use this public-only civic loop when reviewing the product experience: account state → verification state → public feed → groups → decisions → reports → reviews → activity → node → economics.
              </div>
            </div>
          </div>
          <div className="summaryCardGrid">
            <article className="summaryCard">
              <div className="summaryCardLabel">Visibility rule</div>
              <div className="summaryCardValue">Public-readable civic state</div>
              <div className="summaryCardText">Every protocol-native social and civic surface is publicly readable; membership gates participation, not visibility.</div>
            </article>
            <article className="summaryCard">
              <div className="summaryCardLabel">Governance rule</div>
              <div className="summaryCardValue">Same mechanics, scoped down</div>
              <div className="summaryCardText">Groups, emissary roles, and protocol decisions should read as governance records rather than admin-only shortcuts.</div>
            </article>
            <article className="summaryCard">
              <div className="summaryCardLabel">Safety rule</div>
              <div className="summaryCardValue">Evidence before claims</div>
              <div className="summaryCardText">Record-only upgrade and economics-locked surfaces remain last so reviewers cannot mistake them for live activation.</div>
            </article>
          </div>
        </div>
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
            <HomeNotificationRow label="Feed" detail="See recent public posts and replies." href="/feed" />
            <HomeNotificationRow label="Open decisions" detail={pending.activeProposals ? `${pending.activeProposals} community decision${pending.activeProposals === 1 ? "" : "s"} may need votes.` : "No open decisions are surfaced right now."} href="/decisions" open={pending.activeProposals > 0} />
            <HomeNotificationRow label="Review work" detail={pending.assignedDisputes ? `${pending.assignedDisputes} review assignment${pending.assignedDisputes === 1 ? "" : "s"} appear tied to this account.` : pending.availableDisputes ? `${pending.availableDisputes} open report${pending.availableDisputes === 1 ? "" : "s"} are visible.` : "No active reports are visible right now."} href="/reviews" open={pending.assignedDisputes > 0} />
            <HomeNotificationRow label="Account and devices" detail={failedActions ? `${failedActions} recent action${failedActions === 1 ? "" : "s"} may need attention.` : pendingActions ? `${pendingActions} recent action${pendingActions === 1 ? "" : "s"} still finishing.` : "Your local action queue looks clear."} href="/session" open={failedActions > 0 || pendingActions > 0} />
            <HomeNotificationRow label="Economics locked" detail="Public observer and closed-testnet flows do not activate live economics by default." href="/economics" />
          </div>
        </div>
      </section>
    </div>
  );
}
