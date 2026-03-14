import React, { useMemo, useState } from "react";

import FeedView from "../components/FeedView";
import { getApiBaseUrl } from "../api/weall";
import { getKeypair, getSession } from "../auth/session";
import { resolveOnboardingSnapshot, summarizeNextRequirements } from "../lib/onboarding";
import { nav } from "../lib/router";

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

  return (
    <div className="pageStack">
      <section className="card heroCard">
        <div className="cardBody heroBody compactHero">
          <div className="heroSplit">
            <div>
              <div className="eyebrow">Public activity</div>
              <h1 className="heroTitle heroTitleSm">Follow what the network is doing</h1>
              <p className="heroText">
                Browse public content first. Your account-scoped feed only loads after a local
                session exists on this device.
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
                <span className={`statusPill ${snapshot.tier >= 1 ? "ok" : ""}`}>
                  Tier {snapshot.tier}
                </span>
              </div>
            </div>
          </div>

          <div className="heroActions">
            <TabButton active={tab === "global"} onClick={() => setTab("global")}>
              Global
            </TabButton>
            <TabButton active={tab === "mine"} onClick={() => setTab("mine")}>
              My feed
            </TabButton>
            <TabButton active={tab === "governance"} onClick={() => setTab("governance")}>
              Governance
            </TabButton>

            {!snapshot.canPost ? (
              <button className="btn" onClick={() => nav(snapshot.next.route)}>
                {snapshot.next.label}
              </button>
            ) : (
              <button className="btn btnPrimary" onClick={() => nav("/post")}>
                Create post
              </button>
            )}
          </div>

          {!snapshot.canPost && unmet.length ? (
            <div className="calloutInfo">
              <strong>Posting is still gated.</strong>
              <div style={{ marginTop: 6 }}>{unmet[0]?.hint || snapshot.next.note}</div>
            </div>
          ) : null}

          {tab === "mine" && !acct ? (
            <div className="calloutInfo">
              <strong>No local session is active.</strong>
              <div style={{ marginTop: 6 }}>
                Open Login to restore your device session, then return to inspect your account feed.
              </div>
            </div>
          ) : null}
        </div>
      </section>

      <FeedView
        base={base}
        title={title}
        scope={scope}
        defaultSort="new"
        defaultFilters={defaultFilters}
      />
    </div>
  );
}
