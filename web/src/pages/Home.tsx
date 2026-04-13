import React, { useEffect, useMemo, useState } from "react";

import { weall } from "../api/weall";
import { getKeypair, getSession } from "../auth/session";
import { useTxQueue } from "../hooks/useTxQueue";
import { config } from "../lib/config";
import {
  POSTING_MIN_TIER,
  resolveOnboardingSnapshot,
  summarizeNextRequirements,
} from "../lib/onboarding";
import { nav } from "../lib/router";
import {
  summarizeAccountStanding,
  summarizeNodeConnection,
  summarizeSessionState,
} from "../lib/status";

type ChecklistItem = {
  label: string;
  ok: boolean;
  hint: string;
};

function statusTone(ok: boolean): string {
  return ok ? "ok" : "";
}

function SummaryTile({
  label,
  value,
  hint,
  tone,
}: {
  label: string;
  value: string;
  hint: string;
  tone?: "ok" | "warn" | "danger";
}): JSX.Element {
  return (
    <article className={`card summaryTile ${tone ? `summaryTile${tone[0].toUpperCase()}${tone.slice(1)}` : ""}`}>
      <div className="cardBody formStack">
        <span className="statLabel">{label}</span>
        <strong className="summaryTileValue">{value}</strong>
        <span className="summaryTileHint">{hint}</span>
      </div>
    </article>
  );
}

function ReadinessItem({ item }: { item: ChecklistItem }): JSX.Element {
  return (
    <div className="missionChecklistRow">
      <div>
        <div className="missionChecklistLabel">{item.label}</div>
        <div className="missionChecklistHint">{item.hint}</div>
      </div>
      <span className={`statusPill ${statusTone(item.ok)}`}>{item.ok ? "Ready" : "Needed"}</span>
    </div>
  );
}

function MissionAction({
  title,
  detail,
  cta,
  onClick,
  tone,
}: {
  title: string;
  detail: string;
  cta: string;
  onClick: () => void;
  tone?: "primary" | "neutral";
}): JSX.Element {
  return (
    <div className="missionActionCard">
      <div className="missionActionBody">
        <strong>{title}</strong>
        <span>{detail}</span>
      </div>
      <button className={`btn ${tone === "primary" ? "btnPrimary" : ""}`} onClick={onClick}>
        {cta}
      </button>
    </div>
  );
}

export default function Home(): JSX.Element {
  const [status, setStatus] = useState<any>(null);
  const [readyz, setReadyz] = useState<any>(null);
  const [acctState, setAcctState] = useState<any>(null);
  const [registration, setRegistration] = useState<any>(null);
  const [acctErr, setAcctErr] = useState<string>("");
  const [loadingAccount, setLoadingAccount] = useState(false);
  const [showDiagnostics, setShowDiagnostics] = useState(false);

  const session = getSession();
  const account = session?.account || "";
  const keypair = useMemo(() => (account ? getKeypair(account) : null), [account]);
  const { items: txItems } = useTxQueue();

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const [statusView, readyzView] = await Promise.allSettled([weall.status(), weall.readyz()]);
        if (cancelled) return;
        setStatus(statusView.status === "fulfilled" ? statusView.value : { ok: false });
        setReadyz(readyzView.status === "fulfilled" ? readyzView.value : { ok: false });
      } catch {
        if (cancelled) return;
        setStatus({ ok: false });
        setReadyz({ ok: false });
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      if (!account) {
        setAcctState(null);
        setRegistration(null);
        setAcctErr("");
        return;
      }

      setLoadingAccount(true);
      try {
        const [accountView, registrationView] = await Promise.all([
          weall.account(account),
          weall.accountRegistered(account),
        ]);
        if (cancelled) return;
        setAcctState(accountView);
        setRegistration(registrationView);
        setAcctErr("");
      } catch (e: any) {
        if (cancelled) return;
        setAcctErr(String(e?.message || e));
      } finally {
        if (!cancelled) setLoadingAccount(false);
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [account]);

  const snapshot = resolveOnboardingSnapshot({
    account,
    session,
    keypair,
    accountView: acctState,
    registrationView: registration,
  });

  const checklist = summarizeNextRequirements(snapshot);
  const nodeSummary = summarizeNodeConnection(status, config.defaultApiBase);
  const sessionSummary = summarizeSessionState({ accountView: acctState, registrationView: registration });
  const standingSummary = summarizeAccountStanding({ accountView: acctState, registrationView: registration });

  const pendingTxCount = txItems.filter((item) => item.status === "preparing" || item.status === "submitted").length;
  const unresolvedTxCount = txItems.filter((item) => item.status === "unknown" || item.status === "error").length;

  const nextSteps: ChecklistItem[] = [
    {
      label: "Node connection",
      ok: nodeSummary.phase === "online",
      hint:
        nodeSummary.phase === "online"
          ? `Backend reachable${nodeSummary.detail ? ` · ${nodeSummary.detail}` : ""}`
          : "The frontend cannot safely assume protocol state while the backend is unreachable.",
    },
    {
      label: "Device session",
      ok: snapshot.hasSession,
      hint: snapshot.hasSession
        ? "A browser session is active for the current account."
        : "Create or restore a browser session before attempting signed actions.",
    },
    ...checklist,
  ];

  const authorityLabel = status?.node_lifecycle || status?.mode || readyz?.node_lifecycle || "unknown";
  const nextPrimaryRoute = snapshot.canPost ? "/post" : snapshot.next.route;
  const nextPrimaryLabel = snapshot.canPost ? "Create your first post" : snapshot.next.label;
  const nextPrimaryNote = snapshot.canPost
    ? "This account currently satisfies the frontend creator gate and can move into the signed posting flow."
    : snapshot.next.note;

  return (
    <div className="pageStack homeMissionControl">
      <section className="card heroCard missionHeroCard">
        <div className="cardBody formStack">
          <div className="missionHeroTop">
            <div>
              <div className="eyebrow">{config.envLabel} · mission control</div>
              <h1 className="heroTitle heroTitleSm">Home</h1>
              <p className="heroText">
                This dashboard should tell the truth about the current device, the current account,
                and the current node. It is the place to verify readiness before moving into PoH,
                governance, content, or other signed protocol actions.
              </p>
            </div>
            <div className="missionHeroBadges">
              <span className={`statusPill ${statusTone(nodeSummary.phase === "online")}`}>{nodeSummary.label}</span>
              <span className={`statusPill ${statusTone(snapshot.registered)}`}>
                {snapshot.registered ? "On-chain account visible" : "On-chain account not visible"}
              </span>
              <span className={`statusPill ${statusTone(snapshot.tier >= POSTING_MIN_TIER)}`}>
                Tier {snapshot.tier}
              </span>
              <span className={`statusPill ${statusTone(snapshot.canPost)}`}>
                {snapshot.canPost ? "Creator path ready" : `Posting requires Tier ${POSTING_MIN_TIER}`}
              </span>
            </div>
          </div>

          <div className="missionHeroMain">
            <div className="missionHeroPrimary">
              <div className="eyebrow">Recommended next action</div>
              <h2 className="missionHeroTitle">{nextPrimaryLabel}</h2>
              <p className="missionHeroNote">{nextPrimaryNote}</p>
              <div className="buttonRow">
                <button className="btn btnPrimary" onClick={() => nav(nextPrimaryRoute)}>
                  {nextPrimaryLabel}
                </button>
                <button className="btn" onClick={() => nav("/feed")}>Browse feed</button>
                <button className="btn" onClick={() => nav("/proposals")}>Open governance</button>
                <button className="btn" onClick={() => nav(account ? `/account/${encodeURIComponent(account)}` : "/login")}>
                  {account ? "Open my account" : "Open login"}
                </button>
              </div>
            </div>

            <div className="missionHeroAside">
              <div className="missionInfoCard">
                <span className="statLabel">Authority posture</span>
                <strong>{String(authorityLabel).replaceAll("_", " ")}</strong>
                <span className="summaryTileHint">
                  The frontend should distinguish general backend reachability from the node lifecycle
                  and production authority posture.
                </span>
              </div>
              <div className="missionInfoCard">
                <span className="statLabel">Account summary</span>
                <strong className="mono">{account || "No active account"}</strong>
                <span className="summaryTileHint">{standingSummary.detail}</span>
              </div>
            </div>
          </div>
        </div>
      </section>

      <section className="summaryGrid4">
        <SummaryTile
          label="Backend"
          value={nodeSummary.label}
          hint={nodeSummary.detail || config.defaultApiBase}
          tone={nodeSummary.phase === "online" ? "ok" : "warn"}
        />
        <SummaryTile
          label="Local session"
          value={sessionSummary.account || "Missing"}
          hint={sessionSummary.detail}
          tone={snapshot.hasSession && snapshot.hasLocalSigner ? "ok" : "warn"}
        />
        <SummaryTile
          label="On-chain standing"
          value={standingSummary.label}
          hint={standingSummary.detail}
          tone={snapshot.banned || snapshot.locked ? "danger" : snapshot.registered ? "ok" : "warn"}
        />
        <SummaryTile
          label="Pending activity"
          value={pendingTxCount > 0 ? `${pendingTxCount} pending` : "No pending tx"}
          hint={
            unresolvedTxCount > 0
              ? `${unresolvedTxCount} transaction result${unresolvedTxCount === 1 ? "" : "s"} still need review.`
              : "Use this area to distinguish submission from confirmed protocol outcome."
          }
          tone={pendingTxCount === 0 && unresolvedTxCount === 0 ? "ok" : "warn"}
        />
      </section>

      {(snapshot.banned || snapshot.locked || acctErr) && (
        <section className="card">
          <div className="cardBody formStack">
            <div className={snapshot.banned || snapshot.locked ? "calloutDanger" : "inlineError"}>
              {acctErr ||
                `This account is currently ${snapshot.banned ? "banned" : "locked"}. Some actions will remain unavailable until protocol rules restore standing.`}
            </div>
          </div>
        </section>
      )}

      <section className="gridCards grid2">
        <article className="card">
          <div className="cardBody formStack">
            <div className="sectionHead">
              <div>
                <div className="eyebrow">Readiness checklist</div>
                <h2 className="cardTitle">Backend-aligned next requirements</h2>
              </div>
              {loadingAccount ? <span className="statusPill">Refreshing…</span> : null}
            </div>
            <div className="missionChecklist">
              {nextSteps.map((item, idx) => (
                <ReadinessItem key={`${item.label}-${idx}`} item={item} />
              ))}
            </div>
          </div>
        </article>

        <article className="card">
          <div className="cardBody formStack">
            <div className="sectionHead">
              <div>
                <div className="eyebrow">Protocol meaning</div>
                <h2 className="cardTitle">Current progression</h2>
              </div>
            </div>
            <div className="missionStageCard">
              <div className="missionStageRow">
                <span className="statLabel">Current stage</span>
                <strong>{snapshot.stage.replaceAll("_", " ")}</strong>
              </div>
              <div className="missionStageRow">
                <span className="statLabel">PoH tier</span>
                <strong>{snapshot.tier}</strong>
              </div>
              <div className="missionStageRow">
                <span className="statLabel">Reputation</span>
                <strong>{snapshot.reputation}</strong>
              </div>
              <div className="missionStageRow">
                <span className="statLabel">Creator gate</span>
                <strong>{snapshot.canPost ? "Unlocked" : `Blocked until Tier ${POSTING_MIN_TIER}`}</strong>
              </div>
            </div>
            <p className="cardDesc">
              This panel should explain protocol state in plain language. It should never force the
              user to infer the difference between local preparation and authoritative on-chain state.
            </p>
          </div>
        </article>
      </section>

      <section className="card">
        <div className="cardBody formStack">
          <div className="sectionHead">
            <div>
              <div className="eyebrow">Recommended actions</div>
              <h2 className="cardTitle">Move directly to the correct surface</h2>
            </div>
          </div>
          <div className="missionActionsGrid">
            <MissionAction
              title="Continue onboarding"
              detail="Use the staged login and onboarding surface for device/session restoration and Tier 1 entry."
              cta="Open login"
              onClick={() => nav("/login")}
              tone="primary"
            />
            <MissionAction
              title="Continue PoH"
              detail="Progress through the current PoH gate without mixing it up with general account setup."
              cta="Open PoH"
              onClick={() => nav("/poh")}
            />
            <MissionAction
              title="Inspect account standing"
              detail="Open the account surface to compare public-facing profile data with on-chain standing."
              cta={account ? "Open account" : "Sign in first"}
              onClick={() => nav(account ? `/account/${encodeURIComponent(account)}` : "/login")}
            />
            <MissionAction
              title="Create public content"
              detail={snapshot.canPost ? "The current account can move into the signed create-post flow." : `Posting remains blocked until the current creator gate is satisfied.`}
              cta={snapshot.canPost ? "Open composer" : snapshot.next.label}
              onClick={() => nav(snapshot.canPost ? "/post" : snapshot.next.route)}
            />
          </div>
        </div>
      </section>

      <section className="card">
        <div className="cardBody formStack">
          <div className="sectionHead">
            <div>
              <div className="eyebrow">Protocol diagnostics</div>
              <h2 className="cardTitle">Advanced details</h2>
            </div>
            <button className="btn" onClick={() => setShowDiagnostics((value) => !value)}>
              {showDiagnostics ? "Hide diagnostics" : "Show diagnostics"}
            </button>
          </div>
          <p className="cardDesc">
            This section is intentionally secondary. Advanced state is useful, but it should not crowd
            out plain-language readiness guidance.
          </p>
          {showDiagnostics ? (
            <pre className="missionDiagnostics">{JSON.stringify({ status, readyz, acctState, registration, snapshot, txQueue: txItems }, null, 2)}</pre>
          ) : null}
        </div>
      </section>
    </div>
  );
}
