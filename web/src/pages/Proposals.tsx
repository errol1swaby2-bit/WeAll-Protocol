import React, { useEffect, useMemo, useState } from "react";

import { getApiBaseUrl, weall } from "../api/weall";
import ErrorBanner from "../components/ErrorBanner";
import { getKeypair, getSession } from "../auth/session";
import { normalizeAccount } from "../auth/keys";
import { useMutationRefresh } from "../hooks/useMutationRefresh";
import { useAccount } from "../context/AccountContext";
import { checkGates, summarizeAccountState } from "../lib/gates";
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
  return actionableTxError(e, "Governance action failed.");
}

function stageBadgeClass(stage: string): string {
  if (["finalized", "executed"].includes(stage)) return "statusPill ok";
  if (["voting", "vote", "poll", "validation", "revision", "draft"].includes(stage)) return "statusPill";
  if (["withdrawn", "failed", "expired", "canceled", "closed"].includes(stage)) return "statusPill warn";
  return "statusPill";
}


function primaryActionLabel(stage: string): string {
  if (stage === "poll" || stage === "voting" || stage === "vote") return "Open and vote";
  if (stage === "draft" || stage === "revision" || stage === "validation") return "Open and review";
  if (stage === "tallied" || stage === "executed") return "Open and inspect";
  if (stage === "finalized") return "Open finalized result";
  if (stage === "withdrawn") return "Open withdrawn record";
  return "Open proposal";
}

export default function Proposals(): JSX.Element {
  const base = useMemo(() => getApiBaseUrl(), []);
  const [items, setItems] = useState<GovernanceProposal[]>([]);
  const [summary, setSummary] = useState<{ total: number; active: number; by_stage: Record<string, number> } | null>(null);
  const [err, setErr] = useState<{ msg: string; details: any } | null>(null);
  const [acctState, setAcctState] = useState<any | null>(null);
  const [query, setQuery] = useState("");
  const [scopeFilter, setScopeFilter] = useState<"active" | "all">("active");
  const [stageFilter, setStageFilter] = useState("all");
  const [sortMode, setSortMode] = useState("created_desc");


  const session = getSession();
  const { refresh: refreshAccountContext } = useAccount();
  const acct = session ? normalizeAccount(session.account) : null;
  const canSign = acct ? !!getKeypair(acct)?.secretKeyB64 : false;


  const gate = checkGates({ loggedIn: !!acct, canSign, accountState: acctState, requireTier: 3 });

  const gateNextStep = !acct
    ? { label: "Sign in first", detail: "Create or restore a device session from Login before you try to author governance actions." }
    : !canSign
      ? { label: "Restore local signer", detail: "This browser needs the account signer before it can author or sign governance proposals." }
      : Number(acctState?.poh_tier ?? 0) < 3
        ? { label: "Finish PoH progression", detail: "Governance authoring unlocks at Tier 3. Open PoH to see the next required step." }
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
      const isActive = !["finalized", "withdrawn", "closed", "executed"].includes(stage);
      if (scopeFilter === "active" && !isActive) return false;
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
  const totalOpenProposals = useMemo(() => (summary ? Number(summary.active || 0) : items.filter((p) => !["finalized", "withdrawn"].includes(governanceProposalStageOf(p))).length), [items, summary]);


  return (
    <div className="pageStack pageNarrow">
      <section className="card heroCard">
        <div className="cardBody heroBody compactHero">
          <div className="heroSplit">
            <div>
              <div className="eyebrow">Governance</div>
              <h1 className="heroTitle heroTitleSm">Proposal queue</h1>
              <p className="heroText">
                Browse live governance items and open a proposal to inspect stage, tally, and vote state. Creation now routes to its own action page so the queue stays scanable and decision-focused.
              </p>
            </div>
            <div className="heroInfoPanel">
              <div className="heroInfoTitle">Overview</div>
              <div className="heroInfoList">
                <span className="statusPill">Total {items.length}</span>
                <span className="statusPill">Open {totalOpenProposals}</span>
                <span className={`statusPill ${gate.ok ? "ok" : ""}`}>{gate.ok ? "Tier 3 ready" : "Tier 3 required"}</span>
                <span className="statusPill">{acctState ? summarizeAccountState(acctState) : "(state unknown)"}</span>
              </div>
            </div>
          </div>
        </div>
      </section>

      <section className="surfaceBoundaryBar" aria-label="Governance route contract">
        <div className="surfaceBoundaryHeader">
          <div>
            <h2 className="surfaceBoundaryTitle">Governance stays list-first on the hub.</h2>
            <p className="surfaceBoundaryText">
              The queue is for scanning live proposals and routing into focused detail pages. Authoring lives on its own action route, and voting stays on the individual proposal surface.
            </p>
          </div>
          <span className="statusPill">Hub surface</span>
        </div>
        <div className="surfaceBoundaryList">
          <span className="surfaceBoundaryTag">Queue only</span>
          <span className="surfaceBoundaryTag">Dedicated creation route</span>
          <span className="surfaceBoundaryTag">Vote on proposal detail</span>
        </div>
      </section>

      <ErrorBanner message={err?.msg} details={err?.details} onRetry={() => void refreshMutationSlices(load, loadAccountState, refreshAccountContext)} onDismiss={() => setErr(null)} />

      {!gate.ok && gateNextStep ? (
        <section className="card">
          <div className="cardBody formStack">
            <div className="eyebrow">Authoring unlock</div>
            <h2 className="cardTitle">What needs to happen before you can create proposals</h2>
            <div className="summaryCardGrid">
              <article className="summaryCard">
                <div className="summaryCardLabel">Current blocker</div>
                <div className="summaryCardValue" style={{ fontSize: "1.2rem" }}>{gateNextStep.label}</div>
                <div className="summaryCardText">{gate.reason || gateNextStep.detail}</div>
              </article>
              <article className="summaryCard">
                <div className="summaryCardLabel">Next route</div>
                <div className="summaryCardValue" style={{ fontSize: "1.2rem" }}>{!acct ? "Login" : !canSign ? "Session" : "PoH"}</div>
                <div className="summaryCardText">{gateNextStep.detail}</div>
              </article>
            </div>
            <div className="buttonRow">
              {!acct ? <button className="btn btnPrimary" onClick={() => nav("/login")}>Open login</button> : null}
              {acct && !canSign ? <button className="btn btnPrimary" onClick={() => nav("/session")}>Open session & devices</button> : null}
              {acct && canSign && Number(acctState?.poh_tier ?? 0) < 3 ? <button className="btn btnPrimary" onClick={() => nav("/poh")}>Open PoH</button> : null}
            </div>
          </div>
        </section>
      ) : null}

          <section className="card">
            <div className="cardBody formStack">
              <div className="sectionHead">
                <div>
                  <div className="eyebrow">Browse</div>
                  <h2 className="cardTitle">Current proposals</h2>
                </div>
                <div className="statusSummary">
                  <button className="btn" onClick={() => void refreshMutationSlices(load, loadAccountState, refreshAccountContext)}>Refresh</button>
                  <button className="btn btnPrimary" onClick={() => nav("/proposals/create")}>Create proposal</button>
                </div>
              </div>

              <div className="grid2">
                <label className="fieldLabel">
                  Search
                  <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search by id, title, body, creator, or stage…" />
                </label>
                <div className="grid2">
                  <label className="fieldLabel">
                    Queue scope
                    <select value={scopeFilter} onChange={(e) => setScopeFilter(e.target.value as "active" | "all") }>
                      <option value="active">active proposals only</option>
                      <option value="all">all proposals</option>
                    </select>
                  </label>
                  <label className="fieldLabel">
                    Stage filter
                    <select value={stageFilter} onChange={(e) => setStageFilter(e.target.value)}>
                      <option value="all">all</option>
                      <option value="poll">poll</option>
                      <option value="draft">draft</option>
                      <option value="revision">revision</option>
                      <option value="validation">validation</option>
                      <option value="voting">voting</option>
                      <option value="closed">closed</option>
                      <option value="tallied">tallied</option>
                      <option value="executed">executed</option>
                      <option value="finalized">finalized</option>
                      <option value="withdrawn">withdrawn</option>
                    </select>
                  </label>
                  <label className="fieldLabel">
                    Sort
                    <select value={sortMode} onChange={(e) => setSortMode(e.target.value)}>
                      <option value="created_desc">newest created</option>
                      <option value="updated_desc">most recently updated</option>
                      <option value="votes_desc">most votes</option>
                      <option value="stage">stage</option>
                    </select>
                  </label>
                </div>
              </div>

              <div className="summaryCardGrid">
                {Object.keys(stageSummary).length === 0 ? (
                  <article className="summaryCard">
                    <div className="summaryCardLabel">Lifecycle</div>
                    <div className="summaryCardValue">No proposals yet</div>
                    <div className="summaryCardText">Once proposals exist, this summary groups them by authoritative stage.</div>
                  </article>
                ) : (
                  Object.entries(stageSummary).sort((a, b) => a[0].localeCompare(b[0])).map(([stage, count]) => (
                    <article key={stage} className="summaryCard">
                      <div className="summaryCardLabel">Stage</div>
                      <div className="summaryCardValue">{stage}</div>
                      <div className="summaryCardText">{count} proposal{count === 1 ? "" : "s"}</div>
                    </article>
                  ))
                )}
              </div>

              <div className="pageStack">
                {filtered.length === 0 ? (
                  <div className="cardDesc">No proposals returned yet.</div>
                ) : (
                  filtered.map((p) => {
                    const id = governanceProposalIdOf(p);
                    const titleText = governanceProposalTitleOf(p);
                    const bodyText = governanceProposalBodyOf(p);
                    const stage = governanceProposalStageOf(p);
                    const counts = governanceProposalCountsOf(p);
                    const totalVotes = counts.yes + counts.no + counts.abstain;

                    return (
                      <article key={id || titleText} className="card">
                        <div className="cardBody formStack">
                          <div className="sectionHead">
                            <div>
                              <div className="eyebrow">Proposal</div>
                              <h3 className="cardTitle">{titleText}</h3>
                            </div>
                            <div className="statusSummary">
                              {id ? <span className="statusPill mono">{id}</span> : null}
                              <span className={stageBadgeClass(stage)}>{stage}</span>
                            </div>
                          </div>
                          <div className="summaryCardGrid">
                            <article className="summaryCard"><div className="summaryCardLabel">Creator</div><div className="summaryCardValue mono">{String((p as any)?.creator || "(unknown)")}</div></article>
                            <article className="summaryCard"><div className="summaryCardLabel">Created height</div><div className="summaryCardValue">{Number((p as any)?.created_at_height || 0)}</div></article>
                            <article className="summaryCard"><div className="summaryCardLabel">Vote tally</div><div className="summaryCardValue">{totalVotes}</div><div className="summaryCardText">YES {counts.yes} · NO {counts.no} · ABSTAIN {counts.abstain}</div></article>
                          </div>
                          {bodyText ? <div className="feedBodyText">{bodyText}</div> : <div className="cardDesc">No description provided.</div>}
                          <div className="buttonRow">
                            <button className="btn btnPrimary" onClick={() => nav(`/proposal/${encodeURIComponent(id)}`)} disabled={!id}>{primaryActionLabel(stage)}</button>
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
              <div className="summaryCardLabel">Governance doctrine</div>
              <div className="summaryCardValue">Voting is direct and non-delegable</div>
              <div className="summaryCardText">Civic voting power should remain personal and legible.</div>
            </article>
            <article className="summaryCard">
              <div className="summaryCardLabel">Execution honesty</div>
              <div className="summaryCardValue">Submission ≠ execution</div>
              <div className="summaryCardText">Creation, tallies, and execution receipts are separate authoritative state transitions.</div>
            </article>
          </section>
    </div>
  );
}
