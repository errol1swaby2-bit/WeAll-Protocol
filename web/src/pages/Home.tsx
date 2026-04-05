import React, { useEffect, useMemo, useState } from "react";

import { weall } from "../api/weall";
import { getKeypair, getSession } from "../auth/session";
import { config } from "../lib/config";
import {
  POSTING_MIN_TIER,
  resolveOnboardingSnapshot,
  summarizeNextRequirements,
} from "../lib/onboarding";
import { nav } from "../lib/router";

function StepBadge({ ok }: { ok: boolean }): JSX.Element {
  return <span className={`statusPill ${ok ? "ok" : ""}`}>{ok ? "Ready" : "Needed"}</span>;
}

function QuickAction({
  icon,
  title,
  subtitle,
  onClick,
}: {
  icon: string;
  title: string;
  subtitle: string;
  onClick: () => void;
}): JSX.Element {
  return (
    <button className="quickActionCard" onClick={onClick}>
      <div className="quickActionIcon">{icon}</div>
      <div className="quickActionBody">
        <strong>{title}</strong>
        <span>{subtitle}</span>
      </div>
    </button>
  );
}

export default function Home(): JSX.Element {
  const [health, setHealth] = useState<any>(null);
  const [acctState, setAcctState] = useState<any>(null);
  const [registration, setRegistration] = useState<any>(null);
  const [acctErr, setAcctErr] = useState<string>("");
  const [showNodeDetails, setShowNodeDetails] = useState(false);

  const session = getSession();
  const acct = session?.account || "";
  const kp = useMemo(() => (acct ? getKeypair(acct) : null), [acct]);

  useEffect(() => {
    (async () => {
      try {
        setHealth(await weall.health());
      } catch (e: any) {
        setHealth({ ok: false, error: String(e?.message || e) });
      }
    })();
  }, []);

  useEffect(() => {
    (async () => {
      if (!acct) {
        setAcctState(null);
        setRegistration(null);
        setAcctErr("");
        return;
      }
      try {
        const [accountView, registrationView] = await Promise.all([
          weall.account(acct),
          weall.accountRegistered(acct),
        ]);
        setAcctState(accountView);
        setRegistration(registrationView);
        setAcctErr("");
      } catch (e: any) {
        setAcctErr(String(e?.message || e));
      }
    })();
  }, [acct]);

  const snapshot = resolveOnboardingSnapshot({
    account: acct,
    session,
    keypair: kp,
    accountView: acctState,
    registrationView: registration,
  });

  const requirements = summarizeNextRequirements(snapshot);
  const ready = !!health?.ok;
  const step1Done = snapshot.hasSession && snapshot.hasLocalSigner;
  const step2Done = snapshot.registered && snapshot.tier >= 1;
  const step3Done = snapshot.canPost;
  const accountSummary = acct
    ? `${acct} on this device ${snapshot.hasLocalSigner ? "has" : "does not have"} a local signer.`
    : "No local account is active on this device.";

  return (
    <div className="pageStack">
      <section className="card heroCard">
        <div className="cardBody heroBody compactHero">
          <div className="heroSplit">
            <div>
              <div className="eyebrow">{config.envLabel}</div>
              <h1 className="heroTitle heroTitleSm">Home</h1>
              <p className="heroText">
                This is the post-login dashboard. It should feel simple: check readiness, complete
                Proof of Humanity, and move directly toward the first successful public action.
              </p>
            </div>

            <div className="heroInfoPanel">
              <div className="heroInfoTitle">Current readiness</div>
              <div className="heroInfoList">
                <span className={`statusPill ${ready ? "ok" : ""}`}>
                  {ready ? "Connected" : "Offline"}
                </span>
                <span className={`statusPill ${snapshot.registered ? "ok" : ""}`}>
                  {snapshot.registered ? "Registered" : "Registration needed"}
                </span>
                <span className={`statusPill ${snapshot.tier >= 1 ? "ok" : ""}`}>
                  Tier {snapshot.tier}
                </span>
                <span className={`statusPill ${snapshot.canPost ? "ok" : ""}`}>
                  {snapshot.canPost ? "Posting unlocked" : `Tier ${POSTING_MIN_TIER} required`}
                </span>
              </div>
            </div>
          </div>

          <div className="heroActions">
            <button className="btn btnPrimary" onClick={() => nav(snapshot.next.route)}>
              {snapshot.next.label}
            </button>
            <button className="btn" onClick={() => nav("/feed")}>
              Browse feed
            </button>
            {acct ? (
              <button className="btn" onClick={() => nav(`/account/${encodeURIComponent(acct)}`)}>
                My account
              </button>
            ) : (
              <button className="btn" onClick={() => nav("/login")}>
                Open login
              </button>
            )}
          </div>

          <div className="feedMediaCard">
            <div className="feedMediaTitle">Recommended next step</div>
            <div className="feedMediaMeta">{snapshot.next.note}</div>
          </div>

          <div className="statsGrid">
            <div className="statCard">
              <span className="statLabel">Connection</span>
              <span className={`statusPill ${ready ? "ok" : ""}`}>
                {ready ? "Connected" : "Offline"}
              </span>
            </div>
            <div className="statCard">
              <span className="statLabel">Account</span>
              <span className="statValue mono">{acct || "Not signed in"}</span>
            </div>
            <div className="statCard">
              <span className="statLabel">PoH tier</span>
              <span className="statValue">{snapshot.tier}</span>
            </div>
            <div className="statCard">
              <span className="statLabel">Posting</span>
              <span className="statValue">
                {snapshot.canPost ? "Unlocked" : `Tier ${POSTING_MIN_TIER} required`}
              </span>
            </div>
          </div>

          {(snapshot.banned || snapshot.locked) && (
            <div className="calloutDanger">
              This account is currently {snapshot.banned ? "banned" : "locked"}. Some actions
              will stay unavailable until the account is restored through protocol rules.
            </div>
          )}
        </div>
      </section>

      <section className="gridCards grid3">
        <article className="card featureCard">
          <div className="cardBody formStack">
            <div className="stepHeader">
              <h2 className="cardTitle">1. Device identity</h2>
              <StepBadge ok={step1Done} />
            </div>
            <p className="cardDesc">
              {acct
                ? accountSummary
                : "Create or restore your account locally first so the client can sign actions from this device."}
            </p>
            <div className="buttonRow">
              <button className="btn btnPrimary" onClick={() => nav("/login")}>
                Device session
              </button>
              <button className="btn" onClick={() => nav("/poh")}>
                Identity &amp; PoH
              </button>
            </div>
            {acctErr ? <div className="inlineError">{acctErr}</div> : null}
          </div>
        </article>

        <article className="card featureCard">
          <div className="cardBody formStack">
            <div className="stepHeader">
              <h2 className="cardTitle">2. Registration and PoH</h2>
              <StepBadge ok={step2Done} />
            </div>
            <p className="cardDesc">
              Registration needs to exist on-chain before creator actions can succeed. After that,
              Tier 1 begins verified access and higher tiers continue the onboarding path.
            </p>
            <div className="milestoneList">
              <span className="miniTag">Registration · required</span>
              <span className="miniTag">Tier 1 · email verification</span>
              <span className="miniTag">Tier 2 · async review</span>
              <span className="miniTag">Tier 3 · creator gate</span>
            </div>
            <div className="buttonRow">
              <button
                className="btn btnPrimary"
                onClick={() => nav(snapshot.registered ? "/poh" : "/login")}
              >
                {snapshot.registered ? "Manage PoH" : "Finish login"}
              </button>
              {snapshot.tier >= 3 ? (
                <button className="btn" onClick={() => nav("/juror")}>
                  Juror area
                </button>
              ) : (
                <button className="btn" onClick={() => nav("/poh")}>
                  Continue PoH
                </button>
              )}
            </div>
          </div>
        </article>

        <article className="card featureCard">
          <div className="cardBody formStack">
            <div className="stepHeader">
              <h2 className="cardTitle">3. First public contribution</h2>
              <StepBadge ok={step3Done} />
            </div>
            <p className="cardDesc">
              The current creator path still requires registration, a healthy device signer, and
              Tier {POSTING_MIN_TIER} before posting unlocks.
            </p>
            <div className="buttonRow">
              <button
                className="btn btnPrimary"
                onClick={() => nav(step3Done ? "/post" : snapshot.next.route)}
              >
                {step3Done ? "Open composer" : snapshot.next.label}
              </button>
              <button className="btn" onClick={() => nav("/feed")}>
                Review content
              </button>
            </div>
          </div>
        </article>
      </section>

      <section className="card">
        <div className="cardBody formStack">
          <div className="sectionHead">
            <div>
              <div className="eyebrow">Onboarding audit view</div>
              <h2 className="cardTitle">Backend-aligned readiness checklist</h2>
            </div>
          </div>

          <div className="progressList">
            {requirements.map((item) => (
              <div className="progressRow" key={item.label}>
                <span>{item.label}</span>
                <span className={`statusPill ${item.ok ? "ok" : ""}`}>
                  {item.ok ? "Ready" : "Needed"}
                </span>
              </div>
            ))}
          </div>

          <div className="infoCard">
            <div className="feedMediaTitle">Current path summary</div>
            <div className="feedMediaMeta">
              {snapshot.account ? `${snapshot.account} · ` : ""}
              stage {snapshot.stage.replaceAll("_", " ")} · tier {snapshot.tier} · reputation{" "}
              {snapshot.reputation}
            </div>
          </div>
        </div>
      </section>

      <section className="gridCards grid2">
        <article className="card featureCard">
          <div className="cardBody formStack">
            <div className="sectionHead">
              <div>
                <div className="eyebrow">Quick actions</div>
                <h2 className="cardTitle">Move directly to the right surface</h2>
              </div>
            </div>
            <div className="quickGrid">
              <QuickAction
                icon="◉"
                title="Login"
                subtitle="Create, restore, and register"
                onClick={() => nav("/login")}
              />
              <QuickAction
                icon="🪪"
                title="Proof of Humanity"
                subtitle="Email, video, and live review"
                onClick={() => nav("/poh")}
              />
              <QuickAction
                icon="📝"
                title="Create post"
                subtitle={snapshot.canPost ? "Ready to publish" : `Blocked until Tier ${POSTING_MIN_TIER}`}
                onClick={() => nav(snapshot.canPost ? "/post" : snapshot.next.route)}
              />
              <QuickAction
                icon="👤"
                title="Account"
                subtitle="Inspect registration and readiness"
                onClick={() =>
                  nav(acct ? `/account/${encodeURIComponent(acct)}` : "/login")
                }
              />
            </div>
          </div>
        </article>

        <article className="card featureCard">
          <div className="cardBody formStack">
            <div className="sectionHead">
              <div>
                <div className="eyebrow">Node diagnostics</div>
                <h2 className="cardTitle">Connection details</h2>
              </div>
              <button className="btn" onClick={() => setShowNodeDetails((v) => !v)}>
                {showNodeDetails ? "Hide details" : "Show details"}
              </button>
            </div>
            <div className="statsGrid statsGridCompact">
              <div className="statCard">
                <span className="statLabel">Health</span>
                <span className={`statusPill ${ready ? "ok" : ""}`}>
                  {ready ? "Healthy" : "Unavailable"}
                </span>
              </div>
              <div className="statCard">
                <span className="statLabel">Session</span>
                <span className={`statusPill ${snapshot.hasSession ? "ok" : ""}`}>
                  {snapshot.hasSession ? "Present" : "Missing"}
                </span>
              </div>
              <div className="statCard">
                <span className="statLabel">Signer</span>
                <span className={`statusPill ${snapshot.hasLocalSigner ? "ok" : ""}`}>
                  {snapshot.hasLocalSigner ? "Present" : "Missing"}
                </span>
              </div>
              <div className="statCard">
                <span className="statLabel">Registration</span>
                <span className={`statusPill ${snapshot.registered ? "ok" : ""}`}>
                  {snapshot.registered ? "Complete" : "Needed"}
                </span>
              </div>
            </div>

            {showNodeDetails ? (
              <pre style={{ whiteSpace: "pre-wrap", margin: 0 }}>
                {JSON.stringify({ health, acctState, registration, snapshot }, null, 2)}
              </pre>
            ) : null}
          </div>
        </article>
      </section>
    </div>
  );
}
