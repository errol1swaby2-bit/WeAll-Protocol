import React, { useMemo, useState } from "react";

import FeedView from "../components/FeedView";
import { getApiBaseUrl } from "../api/weall";
import { getKeypair, getSession } from "../auth/session";
import { resolveOnboardingSnapshot, summarizeNextRequirements } from "../lib/onboarding";
import { nav } from "../lib/router";

type FeedTab = "global" | "mine";

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

  const [tab, setTab] = useState<FeedTab>(acct ? "mine" : "global");

  const snapshot = resolveOnboardingSnapshot({
    account: acct,
    session,
    keypair: kp,
    accountView: null,
    registrationView: null,
  });

  const requirements = summarizeNextRequirements(snapshot);
  const unmet = requirements.filter((item) => !item.ok);

  const title = tab === "mine" && acct ? "My content feed" : "Feed";
  const defaultFilters = { visibility: "public" as const };
  const scope = tab === "mine" && acct ? ({ kind: "account", account: acct } as const) : ({ kind: "public" } as const);

  const stageText = !snapshot.hasSession
    ? "Read-only browsing is available now. Restore a device session when you want account-scoped actions."
    : !snapshot.hasLocalSigner
      ? "This device session exists, but signing is not ready on this machine yet."
      : !snapshot.registered
        ? "You can browse, but publishing still depends on account registration."
        : snapshot.tier < 2
          ? "The account is visible, but Tier 2 is still needed for broader interactions like flags and comments."
          : "This account can browse and participate in the visible content surfaces from this device.";

  return (
    <div className="pageStack">
      <section className="card heroCard">
        <div className="cardBody heroBody compactHero">
          <div className="heroSplit">
            <div>
              <div className="eyebrow">Content</div>
              <h1 className="heroTitle heroTitleSm">{title}</h1>
              <p className="heroText">
                This is the dedicated content surface. Posts, comments, likes, and flags belong here. Governance and dispute work stay on their own routes so the feed remains cognitively equivalent to a standard social surface.
              </p>
            </div>

            <div className="heroInfoPanel">
              <div className="heroInfoTitle">Current account state</div>
              <div className="heroInfoList">
                <span className={`statusPill ${snapshot.hasSession ? "ok" : ""}`}>{snapshot.hasSession ? "Session present" : "No session"}</span>
                <span className={`statusPill ${snapshot.hasLocalSigner ? "ok" : ""}`}>{snapshot.hasLocalSigner ? "Signing ready" : "No local signer"}</span>
                <span className={`statusPill ${snapshot.registered ? "ok" : ""}`}>{snapshot.registered ? "Registered" : "Registration needed"}</span>
                <span className={`statusPill ${snapshot.tier >= 2 ? "ok" : ""}`}>Tier {snapshot.tier}</span>
              </div>
            </div>
          </div>

          <div className="surfaceSummaryGrid">
            <div className="surfaceSummaryCard">
              <span className="surfaceSummaryLabel">Surface boundary</span>
              <strong className="surfaceSummaryValue">Content only</strong>
              <span className="surfaceSummaryHint">Proposal voting and dispute review are linked routes, not inline feed widgets.</span>
            </div>
            <div className="surfaceSummaryCard">
              <span className="surfaceSummaryLabel">Current blocker</span>
              <strong className="surfaceSummaryValue">{unmet.length ? unmet[0]?.label || "Needs attention" : "Participation unlocked"}</strong>
              <span className="surfaceSummaryHint">{unmet.length ? unmet[0]?.hint : stageText}</span>
            </div>
            <div className="surfaceSummaryCard">
              <span className="surfaceSummaryLabel">Interaction model</span>
              <strong className="surfaceSummaryValue">Transaction-backed</strong>
              <span className="surfaceSummaryHint">Like, flag, and post actions submit transactions and may settle after initial submission succeeds.</span>
            </div>
            <div className="surfaceSummaryCard">
              <span className="surfaceSummaryLabel">Next best move</span>
              <strong className="surfaceSummaryValue">{snapshot.canPost ? "Create a post" : snapshot.next.label}</strong>
              <span className="surfaceSummaryHint">{snapshot.canPost ? "Use the centered action button to publish." : snapshot.next.note}</span>
            </div>
          </div>

          <div className="heroActions">
            <TabButton active={tab === "global"} onClick={() => setTab("global")}>Global</TabButton>
            <TabButton active={tab === "mine"} onClick={() => setTab("mine")}>My feed</TabButton>
            <button className="btn" onClick={() => nav("/home")}>Open home</button>
            {!snapshot.canPost ? (
              <button className="btn" onClick={() => nav(snapshot.next.route)}>
                {snapshot.next.label}
              </button>
            ) : null}
            <button className="btn" onClick={() => nav("/proposals")}>Open governance</button>
            <button className="btn" onClick={() => nav("/disputes")}>Open disputes</button>
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

      <section className="surfaceBoundaryBar" aria-label="Feed route contract">
        <div className="surfaceBoundaryHeader">
          <div>
            <h2 className="surfaceBoundaryTitle">This hub stays content-only.</h2>
            <p className="surfaceBoundaryText">
              Posting, reactions, comments, and flags belong here. Governance tallying and dispute voting are linked routes so the main feed does not become a mixed coordination surface.
            </p>
          </div>
          <span className="statusPill">Hub surface</span>
        </div>
        <div className="surfaceBoundaryList">
          <span className="surfaceBoundaryTag">Allowed: posts, comments, likes, flags</span>
          <span className="surfaceBoundaryTag">Disallowed: proposal voting UI</span>
          <span className="surfaceBoundaryTag">Disallowed: dispute voting UI</span>
        </div>
      </section>

      <FeedView
        title={title}
        base={base}
        scope={scope}
        defaultFilters={defaultFilters}
      />
    </div>
  );
}
