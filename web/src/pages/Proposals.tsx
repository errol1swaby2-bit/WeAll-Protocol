import React, { useEffect, useMemo, useState } from "react";

import { getApiBaseUrl, weall } from "../api/weall";
import ErrorBanner from "../components/ErrorBanner";
import RequirementList from "../components/RequirementList";
import { getKeypair, getSession } from "../auth/session";
import { normalizeAccount } from "../auth/keys";
import { useMutationRefresh } from "../hooks/useMutationRefresh";
import { useAccount } from "../context/AccountContext";
import { checkGates, summarizeAccountState } from "../lib/gates";
import { decisionStageHelp, decisionStageLabel } from "../lib/userLanguage";
import { canShowAdvancedMode } from "../lib/config";
import { nav } from "../lib/router";
import { refreshMutationSlices } from "../lib/revalidation";
import { actionableTxError } from "../lib/txAction";
import {
  governanceProposalBodyOf,
  governanceProposalCountsOf,
  governanceProposalIdOf,
  governanceProposalStageOf,
  governanceProposalTitleOf,
  loadGovernanceProposalSurface,
  sortGovernanceProposals,
  type GovernanceProposal,
} from "../lib/governance";

function prettyErr(e: any): { msg: string; details: any } {
  return actionableTxError(e, "Decision action failed.");
}

function stageBadgeClass(stage: string): string {
  if (["finalized", "executed"].includes(stage)) return "statusPill ok";
  if (["voting", "vote", "poll", "validation", "revision", "draft"].includes(stage)) return "statusPill";
  if (["withdrawn", "failed", "expired", "canceled", "closed"].includes(stage)) return "statusPill warn";
  return "statusPill";
}



function decisionIsOpenForVote(stageRaw: string): boolean {
  const stage = String(stageRaw || "").trim().toLowerCase();
  return ["poll", "voting", "vote"].includes(stage);
}

function decisionIsResultStage(stageRaw: string): boolean {
  const stage = String(stageRaw || "").trim().toLowerCase();
  return ["closed", "tallied", "executed", "finalized"].includes(stage);
}

function decisionOutcomeLabel(stageRaw: string, counts: { yes: number; no: number; abstain: number }): string {
  const total = counts.yes + counts.no + counts.abstain;
  if (total <= 0) return decisionIsResultStage(stageRaw) ? "No votes recorded" : "Voting not complete";
  if (counts.yes > counts.no) return "Approved";
  if (counts.no > counts.yes) return "Not approved";
  return "No clear majority";
}

function decisionOutcomeText(stageRaw: string, counts: { yes: number; no: number; abstain: number }): string {
  const total = counts.yes + counts.no + counts.abstain;
  if (total <= 0) return decisionIsResultStage(stageRaw) ? "The decision is closed, but no votes are recorded." : "Votes appear here while the decision is open and after it closes.";
  return `Yes ${counts.yes} · No ${counts.no} · Abstain ${counts.abstain}`;
}

function primaryActionLabel(stage: string): string {
  if (stage === "poll" || stage === "voting" || stage === "vote") return "Open and vote";
  if (stage === "draft" || stage === "revision" || stage === "validation") return "Open and review";
  if (stage === "tallied" || stage === "executed") return "Open and inspect";
  if (stage === "finalized") return "Open finalized result";
  if (stage === "withdrawn") return "Open withdrawn record";
  return "Open decision";
}

export default function Proposals(): JSX.Element {
  const base = useMemo(() => getApiBaseUrl(), []);
  const [items, setItems] = useState<GovernanceProposal[]>([]);
  const [summary, setSummary] = useState<{ total: number; active: number; by_stage: Record<string, number> } | null>(null);
  const [err, setErr] = useState<{ msg: string; details: any } | null>(null);
  const [acctState, setAcctState] = useState<any | null>(null);
  const [query, setQuery] = useState("");
  const [scopeFilter, setScopeFilter] = useState<"active" | "all">("all");
  const [stageFilter, setStageFilter] = useState("all");
  const [sortMode, setSortMode] = useState("created_desc");


  const session = getSession();
  const { refresh: refreshAccountContext } = useAccount();
  const acct = session ? normalizeAccount(session.account) : null;
  const canSign = acct ? !!getKeypair(acct)?.secretKeyB64 : false;
  const showAdvancedMode = canShowAdvancedMode();


  const gate = checkGates({ loggedIn: !!acct, canSign, accountState: acctState, requireTier: 2 });

  const gateNextStep = !acct
    ? { label: "Sign in first", detail: "Create or restore a device session before you create decisions." }
    : !canSign
      ? { label: "Restore device session", detail: "This browser needs an active device session before it can create decisions." }
      : Number(acctState?.poh_tier ?? 0) < 2
        ? { label: "Complete live verification", detail: "Decision creation unlocks after live verification. Open Account Verification to see the next required step." }
        : null;

  async function load(): Promise<void> {
    setErr(null);
    try {
      const surface = await loadGovernanceProposalSurface(base, { limit: 200, includeSummary: true });
      setItems(surface.items);
      setSummary(surface.summary);
    } catch (e: any) {
      setErr(prettyErr(e));
      setItems([]);
      setSummary(null);
    }
  }

  async function loadAccountState(): Promise<void> {
    if (!acct) {
      setAcctState(null);
      return;
    }
    try {
      const r: any = await weall.account(acct, base);
      setAcctState(r?.state ?? null);
    } catch {
      setAcctState(null);
    }
  }

  useEffect(() => {
    void load();
    void loadAccountState();
  }, [acct, base]);

  useMutationRefresh({
    entityTypes: ["proposal"],
    account: acct,
    onRefresh: async () => {
      await load();
      await loadAccountState();

    },
  });

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    const stageNeedle = stageFilter.trim().toLowerCase();
    const subset = items.filter((p) => {
      const stage = governanceProposalStageOf(p);
      if (scopeFilter === "active" && !decisionIsOpenForVote(stage)) return false;
      if (stageNeedle !== "all" && stage !== stageNeedle) return false;
      if (!q) return true;
      const id = governanceProposalIdOf(p).toLowerCase();
      const titleText = governanceProposalTitleOf(p).toLowerCase();
      const bodyText = governanceProposalBodyOf(p).toLowerCase();
      const creator = String((p as any)?.creator || "").toLowerCase();
      return [id, titleText, bodyText, creator, stage].some((x) => x.includes(q));
    });
    return sortGovernanceProposals(subset as GovernanceProposal[], sortMode);
  }, [items, query, scopeFilter, stageFilter, sortMode]);

  const stageSummary = useMemo(() => summary?.by_stage || {}, [summary]);
  const totalOpenProposals = useMemo(() => items.filter((p) => decisionIsOpenForVote(governanceProposalStageOf(p))).length, [items]);
  const totalResultProposals = useMemo(() => items.filter((p) => decisionIsResultStage(governanceProposalStageOf(p))).length, [items]);


  return (
    <div className="pageStack pageNarrow">
      <section className="card heroCard">
        <div className="cardBody heroBody compactHero">
          <div className="heroSplit">
            <div>
              <div className="eyebrow">Decisions</div>
              <h1 className="heroTitle heroTitleSm">Decision queue</h1>
              <p className="heroText">
                Browse community decisions, understand what is open, and vote when eligible. Creation stays on its own page so this list remains easy to scan.
              </p>
            </div>
            <div className="heroInfoPanel">
              <div className="heroInfoTitle">Overview</div>
              <div className="heroInfoList">
                <span className="statusPill">Total {items.length}</span>
                <span className="statusPill">Open {totalOpenProposals}</span>
                <span className="statusPill">Results {totalResultProposals}</span>
                <span className={`statusPill ${gate.ok ? "ok" : ""}`}>{gate.ok ? "Trusted Verified Person" : "Live verification required"}</span>
                <span className="statusPill">{acctState ? summarizeAccountState(acctState) : "(state unknown)"}</span>
              </div>
            </div>
          </div>
        </div>
      </section>

      <section className="surfaceBoundaryBar" aria-label="How decisions work">
        <div className="surfaceBoundaryHeader">
          <div>
            <h2 className="surfaceBoundaryTitle">Decisions are easier when each step has one clear place.</h2>
            <p className="surfaceBoundaryText">
              Use this page to browse what communities are deciding. Open a decision to vote, read results, or see what changed.
            </p>
          </div>
          <span className="statusPill">Browse</span>
        </div>
        <div className="surfaceBoundaryList">
          <span className="surfaceBoundaryTag">Browse decisions</span>
          <span className="surfaceBoundaryTag">Create separately</span>
          <span className="surfaceBoundaryTag">Vote on detail pages</span>
        </div>
      </section>

      <section className="surfaceBoundaryBar" aria-label="Governance lifecycle guide">
        <div className="surfaceBoundaryHeader">
          <div>
            <h2 className="surfaceBoundaryTitle">Decision lifecycle is protocol state, not a browser timer.</h2>
            <p className="surfaceBoundaryText">
              Canonical stage ladder: draft → poll → revision → validation → voting → closed → tallied → executed → finalized.
              Block-height deadlines determine movement; wall-clock estimates only help humans orient themselves.
            </p>
          </div>
          <span className="statusPill">Governance journey</span>
        </div>
        <div className="surfaceBoundaryList">
          <span className="surfaceBoundaryTag">block-height deadlines</span>
          <span className="surfaceBoundaryTag">multi-option proposals supported</span>
          <span className="surfaceBoundaryTag">Transactions confirms submissions</span>
          <span className="surfaceBoundaryTag">upgrade records are non-activating</span>
        </div>
      </section>

      <ErrorBanner message={err?.msg} details={err?.details} onRetry={() => void refreshMutationSlices(load, loadAccountState, refreshAccountContext)} onDismiss={() => setErr(null)} />

      {!gate.ok && gateNextStep ? (
        <section className="card">
          <div className="cardBody formStack">
            <div className="eyebrow">Authoring unlock</div>
            <h2 className="cardTitle">What needs to happen before you can create decisions</h2>
            <div className="summaryCardGrid">
              <article className="summaryCard">
                <div className="summaryCardLabel">Current blocker</div>
                <div className="summaryCardValue" style={{ fontSize: "1.2rem" }}>{gateNextStep.label}</div>
                <div className="summaryCardText">{gate.reason || gateNextStep.detail}</div>
              </article>
              <article className="summaryCard">
                <div className="summaryCardLabel">Next step</div>
                <div className="summaryCardValue" style={{ fontSize: "1.2rem" }}>{!acct ? "Login" : !canSign ? "Session" : "Verification"}</div>
                <div className="summaryCardText">{gateNextStep.detail}</div>
              </article>
            </div>
            <RequirementList requirements={gate.requirements} />
            <div className="buttonRow">
              {!acct ? <button className="btn btnPrimary" onClick={() => nav("/login")}>Open login</button> : null}
              {acct && !canSign ? <button className="btn btnPrimary" onClick={() => nav("/session")}>Open devices & sessions</button> : null}
              {acct && canSign && Number(acctState?.poh_tier ?? 0) < 2 ? <button className="btn btnPrimary" onClick={() => nav("/verification")}>Open Account Verification</button> : null}
            </div>
          </div>
        </section>
      ) : null}

          <section className="card">
            <div className="cardBody formStack">
              <div className="sectionHead">
                <div>
                  <div className="eyebrow">Browse</div>
                  <h2 className="cardTitle">Current decisions</h2>
                </div>
                <div className="statusSummary">
                  <button className="btn" onClick={() => void refreshMutationSlices(load, loadAccountState, refreshAccountContext)}>Refresh</button>
                  <button className="btn btnPrimary" onClick={() => nav("/decisions/create")}>Create decision</button>
                </div>
              </div>

              <div className="grid2">
                <label className="fieldLabel">
                  Search
                  <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search by title, description, creator, or status…" />
                </label>
                <div className="grid2">
                  <label className="fieldLabel">
                    Queue scope
                    <select value={scopeFilter} onChange={(e) => setScopeFilter(e.target.value as "active" | "all") }>
                      <option value="active">open votes only</option>
                      <option value="all">all decisions</option>
                    </select>
                  </label>
                  <label className="fieldLabel">
                    Status filter
                    <select value={stageFilter} onChange={(e) => setStageFilter(e.target.value)}>
                      <option value="all">all</option>
                      <option value="poll">open for early input</option>
                      <option value="draft">draft</option>
                      <option value="revision">being revised</option>
                      <option value="validation">being checked</option>
                      <option value="voting">open for voting</option>
                      <option value="closed">voting closed</option>
                      <option value="tallied">results counted</option>
                      <option value="executed">approved changes applied</option>
                      <option value="finalized">final result</option>
                      <option value="withdrawn">withdrawn</option>
                    </select>
                  </label>
                  <label className="fieldLabel">
                    Sort
                    <select value={sortMode} onChange={(e) => setSortMode(e.target.value)}>
                      <option value="created_desc">newest created</option>
                      <option value="updated_desc">most recently updated</option>
                      <option value="votes_desc">most votes</option>
                      <option value="stage">status</option>
                    </select>
                  </label>
                </div>
              </div>

              <div className="summaryCardGrid">
                {Object.keys(stageSummary).length === 0 ? (
                  <article className="summaryCard">
                    <div className="summaryCardLabel">Lifecycle</div>
                    <div className="summaryCardValue">No decisions yet</div>
                    <div className="summaryCardText">Once decisions exist, this summary groups them by current status.</div>
                  </article>
                ) : (
                  Object.entries(stageSummary).sort((a, b) => a[0].localeCompare(b[0])).map(([stage, count]) => (
                    <article key={stage} className="summaryCard">
                      <div className="summaryCardLabel">Status</div>
                      <div className="summaryCardValue">{decisionStageLabel(stage)}</div>
                      <div className="summaryCardText">{count} decision{count === 1 ? "" : "s"}</div>
                    </article>
                  ))
                )}
              </div>

              <div className="pageStack">
                {filtered.length === 0 ? (
                  <div className="cardDesc">{scopeFilter === "active" ? "No open votes right now. Switch queue scope to all decisions to see closed decisions and final results." : "No decisions returned yet. A normal tester should still see the lifecycle guide above and can create a low-risk test decision only after eligibility checks pass."}</div>
                ) : (
                  filtered.map((p) => {
                    const id = governanceProposalIdOf(p);
                    const titleText = governanceProposalTitleOf(p);
                    const bodyText = governanceProposalBodyOf(p);
                    const stage = governanceProposalStageOf(p);
                    const counts = governanceProposalCountsOf(p);
                    const totalVotes = counts.yes + counts.no + counts.abstain;
                    const resultReady = decisionIsResultStage(stage);

                    return (
                      <article key={id || titleText} className="card">
                        <div className="cardBody formStack">
                          <div className="sectionHead">
                            <div>
                              <div className="eyebrow">Decision</div>
                              <h3 className="cardTitle">{titleText}</h3>
                            </div>
                            <div className="statusSummary">
                              {showAdvancedMode && id ? <span className="statusPill mono">{id}</span> : null}
                              <span className={stageBadgeClass(stage)}>{decisionStageLabel(stage)}</span>
                            </div>
                          </div>
                          <div className="summaryCardGrid">
                            <article className="summaryCard"><div className="summaryCardLabel">Creator</div><div className="summaryCardValue mono">{String((p as any)?.creator || "(unknown)")}</div></article>
                            <article className="summaryCard"><div className="summaryCardLabel">Status note</div><div className="summaryCardValue">{decisionStageLabel(stage)}</div><div className="summaryCardText">{decisionStageHelp(stage)}</div></article>
                            <article className="summaryCard"><div className="summaryCardLabel">Vote tally</div><div className="summaryCardValue">{totalVotes}</div><div className="summaryCardText">Yes {counts.yes} · No {counts.no} · Abstain {counts.abstain}</div></article>
                            <article className="summaryCard"><div className="summaryCardLabel">Outcome</div><div className="summaryCardValue">{decisionOutcomeLabel(stage, counts)}</div><div className="summaryCardText">{resultReady ? "Final result · " : "Current tally · "}{decisionOutcomeText(stage, counts)}</div></article>
                          </div>
                          {bodyText ? <div className="feedBodyText">{bodyText}</div> : <div className="cardDesc">No description provided.</div>}
                          <div className="buttonRow">
                            <button className="btn btnPrimary" onClick={() => nav(`/decisions/${encodeURIComponent(id)}`)} disabled={!id}>{primaryActionLabel(stage)}</button>
                          </div>
                        </div>
                      </article>
                    );
                  })
                )}
              </div>
            </div>
          </section>

          <section className="summaryCardGrid">
            <article className="summaryCard">
              <div className="summaryCardLabel">Decision principle</div>
              <div className="summaryCardValue">Voting is direct and personal</div>
              <div className="summaryCardText">Civic voting power should remain personal and legible.</div>
            </article>
            <article className="summaryCard">
              <div className="summaryCardLabel">Outcome clarity</div>
              <div className="summaryCardValue">Creating is not approval</div>
              <div className="summaryCardText">Creation, voting, and final results are separate authoritative state changes.</div>
            </article>
          </section>
    </div>
  );
}
