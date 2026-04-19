import React, { useEffect, useMemo, useState } from "react";

import FeedView from "../components/FeedView";
import { getApiBaseUrl } from "../api/weall";
import { getKeypair, getSession } from "../auth/session";
import { resolveOnboardingSnapshot, summarizeNextRequirements } from "../lib/onboarding";
import { nav } from "../lib/router";
import { governanceProposalCountsOf, governanceProposalStageOf, loadActiveGovernanceProposals, type GovernanceProposal, type GovernanceProposalSummary } from "../lib/governance";

type FeedTab = "global" | "mine" | "governance";

function TabButton({
  active,
  children,
  onClick,
}: {
  active: boolean;
  children: React.ReactNode;
  onClick: () => void;
}): JSX.Element {
  return (
    <button className={`btn ${active ? "btnPrimary" : ""}`} onClick={onClick}>
      {children}
    </button>
  );
}


export default function Feed(): JSX.Element {
  const base = useMemo(() => getApiBaseUrl(), []);
  const session = getSession();
  const acct = session?.account || "";
  const kp = acct ? getKeypair(acct) : null;

  const [tab, setTab] = useState<FeedTab>("global");
  const [govItems, setGovItems] = useState<GovernanceProposal[]>([]);
  const [govLoading, setGovLoading] = useState(false);
  const [govErr, setGovErr] = useState<string | null>(null);
  const [govSummary, setGovSummary] = useState<GovernanceProposalSummary | null>(null);
  const [govReloadKey, setGovReloadKey] = useState(0);

  useEffect(() => {
    let cancelled = false;
    async function loadGovernance() {
      if (tab !== "governance") return;
      setGovLoading(true);
      setGovErr(null);
      try {
        const surface = await loadActiveGovernanceProposals(base, 200);
        if (!cancelled) {
          setGovItems(surface.items);
          setGovSummary(surface.summary);
        }
      } catch (e: any) {
        if (!cancelled) {
          setGovErr(String(e?.message || e?.payload?.message || "Failed to load proposals."));
          setGovItems([]);
          setGovSummary(null);
        }
      } finally {
        if (!cancelled) setGovLoading(false);
      }
    }
    void loadGovernance();
    return () => { cancelled = true; };
  }, [tab, base, govReloadKey]);

  const snapshot = resolveOnboardingSnapshot({
    account: acct,
    session,
    keypair: kp,
    accountView: null,
    registrationView: null,
  });

  const requirements = summarizeNextRequirements(snapshot);
  const unmet = requirements.filter((item) => !item.ok);

  const title =
    tab === "mine"
      ? acct
        ? "My public feed"
        : "Public feed"
      : tab === "governance"
        ? "Governance feed"
        : "Feed";

  const defaultFilters =
    tab === "governance"
      ? { visibility: "public" as const, tags: "governance" }
      : { visibility: "public" as const };

  const scope =
    tab === "mine" && acct
      ? ({ kind: "account", account: acct } as const)
      : ({ kind: "public" } as const);

  const stageText = !snapshot.hasSession
    ? "Read-only browsing is available now. Restore a device session when you want account-scoped actions."
    : !snapshot.hasLocalSigner
      ? "This device session exists, but signing is not ready on this machine yet."
      : !snapshot.registered
        ? "You can browse, but publishing and higher-trust actions still depend on account registration."
        : snapshot.tier < 2
          ? "The account is visible, but Tier 2 is still needed for broader feed interactions."
          : "This account can browse and participate in the visible feed surfaces from this device.";

  return (
    <div className="pageStack">
      <section className="card heroCard">
        <div className="cardBody heroBody compactHero">
          <div className="heroSplit">
            <div>
              <div className="eyebrow">Public activity</div>
              <h1 className="heroTitle heroTitleSm">Track visible protocol activity with clearer interaction truth</h1>
              <p className="heroText">
                Browse the public feed first, then move into account-scoped activity once a local session exists. Reactions, flags,
                and posting are treated as protocol actions rather than instant consumer-app gestures.
              </p>
            </div>

            <div className="heroInfoPanel">
              <div className="heroInfoTitle">Current account state</div>
              <div className="heroInfoList">
                <span className={`statusPill ${snapshot.hasSession ? "ok" : ""}`}>
                  {snapshot.hasSession ? "Session present" : "No session"}
                </span>
                <span className={`statusPill ${snapshot.hasLocalSigner ? "ok" : ""}`}>
                  {snapshot.hasLocalSigner ? "Signing ready" : "No local signer"}
                </span>
                <span className={`statusPill ${snapshot.registered ? "ok" : ""}`}>
                  {snapshot.registered ? "Registered" : "Registration needed"}
                </span>
                <span className={`statusPill ${snapshot.tier >= 2 ? "ok" : ""}`}>
                  Tier {snapshot.tier}
                </span>
              </div>
            </div>
          </div>

          <div className="surfaceSummaryGrid">
            <div className="surfaceSummaryCard">
              <span className="surfaceSummaryLabel">Browsing mode</span>
              <strong className="surfaceSummaryValue">{tab === "mine" ? "Account scoped" : tab === "governance" ? "Active proposals" : "Public"}</strong>
              <span className="surfaceSummaryHint">Switching tabs changes what the frontend asks the backend to return. It does not change chain truth.</span>
            </div>
            <div className="surfaceSummaryCard">
              <span className="surfaceSummaryLabel">Current blocker</span>
              <strong className="surfaceSummaryValue">{unmet.length ? unmet[0]?.label || "Needs attention" : "Feed participation unlocked"}</strong>
              <span className="surfaceSummaryHint">{unmet.length ? unmet[0]?.hint : stageText}</span>
            </div>
            <div className="surfaceSummaryCard">
              <span className="surfaceSummaryLabel">Interaction model</span>
              <strong className="surfaceSummaryValue">Protocol-backed</strong>
              <span className="surfaceSummaryHint">Like, flag, and post actions submit transactions and may finalize after initial submission succeeds.</span>
            </div>
            <div className="surfaceSummaryCard">
              <span className="surfaceSummaryLabel">Next best move</span>
              <strong className="surfaceSummaryValue">{snapshot.canPost ? "Create or inspect content" : snapshot.next.label}</strong>
              <span className="surfaceSummaryHint">{snapshot.canPost ? "You can publish now or inspect thread and account surfaces." : snapshot.next.note}</span>
            </div>
          </div>

          <div className="heroActions">
            <TabButton active={tab === "global"} onClick={() => setTab("global")}>Global</TabButton>
            <TabButton active={tab === "mine"} onClick={() => setTab("mine")}>My feed</TabButton>
            <TabButton active={tab === "governance"} onClick={() => setTab("governance")}>Governance</TabButton>

            {!snapshot.canPost ? (
              <button className="btn" onClick={() => nav(snapshot.next.route)}>
                {snapshot.next.label}
              </button>
            ) : (
              <button className="btn btnPrimary" onClick={() => nav("/post")}>Create post</button>
            )}
            <button className="btn" onClick={() => nav("/proposals")}>Open governance</button>
          </div>

          {!snapshot.canPost && unmet.length ? (
            <div className="calloutInfo">
              <strong>Feed browsing is available, but participation is still gated.</strong>
              <div style={{ marginTop: 6 }}>{unmet[0]?.hint || snapshot.next.note}</div>
            </div>
          ) : null}

          {tab === "mine" && !acct ? (
            <div className="calloutInfo">
              <strong>No local session is active.</strong>
              <div style={{ marginTop: 6 }}>
                Open Login to restore your device session, then return to inspect your account feed and transaction-backed actions.
              </div>
            </div>
          ) : null}
        </div>
      </section>

      {tab === "governance" ? (
        <section className="pageStack">
          <section className="card">
            <div className="cardBody formStack">
              <div className="sectionHead">
                <div>
                  <div className="eyebrow">Governance</div>
                  <h2 className="cardTitle">Active proposals</h2>
                </div>
                <div className="statusSummary">
                  <button className="btn" onClick={() => setGovReloadKey((v) => v + 1)} disabled={govLoading}>{govLoading ? "Refreshing…" : "Refresh"}</button>
                  <button className="btn btnPrimary" onClick={() => nav("/proposals")}>Open full governance surface</button>
                </div>
              </div>
              <div className="cardDesc">Governance mode now shows active proposals instead of reusing the social content feed. Proposal detail remains the authoritative place to inspect execution payloads and final tallies.</div>
              {govSummary ? (
                <div className="surfaceSummaryGrid">
                  <div className="surfaceSummaryCard">
                    <span className="surfaceSummaryLabel">Visible active proposals</span>
                    <strong className="surfaceSummaryValue">{govItems.length}</strong>
                    <span className="surfaceSummaryHint">This feed only renders proposals the backend marks active.</span>
                  </div>
                  <div className="surfaceSummaryCard">
                    <span className="surfaceSummaryLabel">All proposals</span>
                    <strong className="surfaceSummaryValue">{govSummary.total}</strong>
                    <span className="surfaceSummaryHint">The full governance surface includes drafts, finalized, and withdrawn items too.</span>
                  </div>
                  <div className="surfaceSummaryCard">
                    <span className="surfaceSummaryLabel">Active by backend summary</span>
                    <strong className="surfaceSummaryValue">{govSummary.active}</strong>
                    <span className="surfaceSummaryHint">This count comes directly from the governance API summary.</span>
                  </div>
                </div>
              ) : null}
              {govErr ? <div className="inlineError">{govErr}</div> : null}
            </div>
          </section>
          {govLoading && !govItems.length ? (
            <section className="card"><div className="cardBody"><div className="cardDesc">Loading active proposals…</div></div></section>
          ) : null}
          {!govLoading && !govItems.length ? (
            <section className="card"><div className="cardBody"><div className="cardDesc">No active proposals are visible right now.</div></div></section>
          ) : null}
          {govItems.map((p: any) => {
            const counts = governanceProposalCountsOf(p);
            const total = counts.yes + counts.no + counts.abstain;
            const proposalId = String(p?.proposal_id || p?.id || "");
            return (
              <article key={proposalId} className="card">
                <div className="cardBody formStack">
                  <div className="sectionHead">
                    <div>
                      <div className="eyebrow">{String(p?.stage || "draft").toUpperCase()}</div>
                      <h3 className="cardTitle">{String(p?.title || proposalId || "Untitled proposal")}</h3>
                    </div>
                    <div className="statusSummary">
                      {proposalId ? <span className="statusPill mono">{proposalId}</span> : null}
                      <span className="statusPill">Votes {total}</span>
                    </div>
                  </div>
                  {p?.summary ? <div className="feedBodyText">{String(p.summary)}</div> : p?.description ? <div className="feedBodyText">{String(p.description)}</div> : null}
                  <div className="surfaceSummaryGrid">
                    <div className="surfaceSummaryCard"><span className="surfaceSummaryLabel">YES</span><strong className="surfaceSummaryValue">{counts.yes}</strong></div>
                    <div className="surfaceSummaryCard"><span className="surfaceSummaryLabel">NO</span><strong className="surfaceSummaryValue">{counts.no}</strong></div>
                    <div className="surfaceSummaryCard"><span className="surfaceSummaryLabel">ABSTAIN</span><strong className="surfaceSummaryValue">{counts.abstain}</strong></div>
                    <div className="surfaceSummaryCard"><span className="surfaceSummaryLabel">Author</span><strong className="surfaceSummaryValue mono">{String(p?.proposer || p?.author || p?.created_by || "unknown")}</strong></div>
                  </div>
                  <div className="buttonRow buttonRowWide">
                    <button className="btn btnPrimary" onClick={() => nav(`/proposal/${encodeURIComponent(proposalId)}`)} disabled={!proposalId}>Open proposal</button>
                    <button className="btn" onClick={() => nav("/proposals")}>View all proposals</button>
                  </div>
                </div>
              </article>
            );
          })}
        </section>
      ) : (
        <FeedView
          base={base}
          title={title}
          scope={scope}
          defaultSort="new"
          defaultFilters={defaultFilters}
        />
      )}
    </div>
  );
}
