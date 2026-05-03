import React, { useMemo, useState } from "react";

import FeedView from "../components/FeedView";
import { getApiBaseUrl } from "../api/weall";
import { getKeypair, getSession } from "../auth/session";
import { resolveOnboardingSnapshot, summarizeNextRequirements } from "../lib/onboarding";
import { nav } from "../lib/router";
import { verificationLabel } from "../lib/userLanguage";

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

  const title = tab === "mine" && acct ? "My posts" : "Feed";
  const defaultFilters = { visibility: "public" as const };
  const scope = tab === "mine" && acct ? ({ kind: "account", account: acct } as const) : ({ kind: "public" } as const);

  const stageText = !snapshot.hasSession
    ? "You can read public posts now. Sign in when you want to create posts or join conversations."
    : !snapshot.hasLocalSigner
      ? "This device needs your local signer before it can save actions."
      : !snapshot.registered
        ? "You can browse now. Finish account setup before posting."
        : snapshot.tier < 2
          ? "Complete live verification to create public posts, comment, react, or report harmful content."
          : "Your account is ready to participate from this device.";

  return (
    <div className="pageStack socialFeedPage">
      <section className="card heroCard socialFeedHero">
        <div className="cardBody heroBody compactHero">
          <div className="heroSplit">
            <div>
              <div className="eyebrow">Feed</div>
              <h1 className="heroTitle heroTitleSm">See what people are sharing</h1>
              <p className="heroText">
                Read posts, open conversations, react, and report harmful content when your account is ready.
              </p>
            </div>

            <div className="heroInfoPanel">
              <div className="heroInfoTitle">Your account</div>
              <div className="heroInfoList">
                <span className={`statusPill ${snapshot.hasSession ? "ok" : ""}`}>{snapshot.hasSession ? "Signed in" : "Read-only"}</span>
                <span className={`statusPill ${snapshot.hasLocalSigner ? "ok" : ""}`}>{snapshot.hasLocalSigner ? "Device ready" : "Device needs setup"}</span>
                <span className={`statusPill ${snapshot.tier >= 2 ? "ok" : ""}`}>{verificationLabel(snapshot.tier)}</span>
              </div>
            </div>
          </div>

          <div className="socialHeroActions">
            <TabButton active={tab === "global"} onClick={() => setTab("global")}>All posts</TabButton>
            <TabButton active={tab === "mine"} onClick={() => setTab("mine")}>My posts</TabButton>
            <button className="btn btnPrimary" onClick={() => nav("/create")}>Create post</button>
            {!snapshot.canPost ? (
              <button className="btn" onClick={() => nav(snapshot.next.route)}>
                {snapshot.next.label}
              </button>
            ) : null}
            <button className="btn" onClick={() => nav("/decisions")}>Decisions</button>
            <button className="btn" onClick={() => nav("/reports")}>Reports</button>
          </div>

          <div className={`calloutInfo ${snapshot.canPost ? "calloutSuccess" : ""}`}>
            <strong>{snapshot.canPost ? "Posting is available" : "Some actions may need verification"}</strong>
            <div style={{ marginTop: 6 }}>{unmet.length ? unmet[0]?.hint || stageText : stageText}</div>
          </div>

          {tab === "mine" && !acct ? (
            <div className="calloutInfo">
              <strong>No local session is active.</strong>
              <div style={{ marginTop: 6 }}>Sign in or restore your device session to see your own posts.</div>
            </div>
          ) : null}
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
