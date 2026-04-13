import React, { useEffect, useMemo, useState } from "react";

import { getApiBaseUrl, weall } from "../api/weall";
import ErrorBanner from "../components/ErrorBanner";
import { getKeypair, getSession, submitSignedTx } from "../auth/session";
import { normalizeAccount } from "../auth/keys";
import { useAccount } from "../context/AccountContext";
import { useTxQueue } from "../hooks/useTxQueue";
import { checkGates, summarizeAccountState } from "../lib/gates";
import { nav } from "../lib/router";

function prettyErr(e: any): { msg: string; details: any } {
  const details = e?.body || e?.data || e;
  const msg = details?.message || details?.error?.message || e?.message || "error";
  return { msg, details };
}

function asStage(value: any): string {
  return String(value || "unknown").trim().toLowerCase() || "unknown";
}

function proposalIdOf(p: any): string {
  return String(p?.proposal_id || p?.id || "").trim();
}

function proposalTitleOf(p: any): string {
  return String(p?.title || proposalIdOf(p) || "Untitled proposal").trim();
}

function proposalBodyOf(p: any): string {
  return String(p?.body || p?.description || "").trim();
}

function countMapOf(p: any): Record<string, number> {
  const raw = p?.counts;
  if (!raw || typeof raw !== "object") return { yes: 0, no: 0, abstain: 0 };
  return {
    yes: Number((raw as any).yes || 0),
    no: Number((raw as any).no || 0),
    abstain: Number((raw as any).abstain || 0),
  };
}

function stageBadgeClass(stage: string): string {
  if (["finalized", "executed"].includes(stage)) return "statusPill ok";
  if (["voting", "vote", "poll", "validation", "revision", "draft"].includes(stage)) return "statusPill";
  if (["withdrawn", "failed", "expired", "canceled"].includes(stage)) return "statusPill warn";
  return "statusPill";
}

function slugifyProposalPart(value: string): string {
  return value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 48);
}

function buildGeneratedProposalId(account: string | null | undefined, title: string, body: string): string {
  const acct = String(account || "anon").trim().toLowerCase().replace(/[^a-z0-9@:_-]+/g, "-") || "anon";
  const slug = slugifyProposalPart(title) || slugifyProposalPart(body) || "proposal";
  const stamp = new Date().toISOString().replace(/[^0-9]/g, "").slice(0, 14);
  return `proposal:${acct}:${slug}:${stamp}`;
}

function normalizeCreatePayload(input: {
  proposalId: string;
  title: string;
  body: string;
  actionTxType: string;
  actionPayloadJson: string;
  startStage: string;
  account: string | null;
}): any {
  const proposal_id = input.proposalId.trim() || buildGeneratedProposalId(input.account, input.title, input.body);
  const title = input.title.trim();
  const body = input.body.trim();
  const startStage = input.startStage.trim().toLowerCase();
  const actionTxType = input.actionTxType.trim().toUpperCase();

  const payload: any = {
    proposal_id,
    title: title || undefined,
    body: body || undefined,
  };

  if (startStage) {
    payload.rules = { start_stage: startStage };
  }

  if (actionTxType) {
    let actionPayload: any = {};
    if (input.actionPayloadJson.trim()) {
      actionPayload = JSON.parse(input.actionPayloadJson);
    }
    payload.actions = [{ tx_type: actionTxType, payload: actionPayload }];
  }

  return payload;
}

function sortItems(items: any[], mode: string): any[] {
  const copy = [...items];
  if (mode === "updated_desc") {
    copy.sort((a, b) => Number(b?.updated_at_height || 0) - Number(a?.updated_at_height || 0));
    return copy;
  }
  if (mode === "votes_desc") {
    copy.sort((a, b) => {
      const ac = countMapOf(a);
      const bc = countMapOf(b);
      return (bc.yes + bc.no + bc.abstain) - (ac.yes + ac.no + ac.abstain);
    });
    return copy;
  }
  if (mode === "stage") {
    copy.sort((a, b) => asStage(a?.stage || a?.status).localeCompare(asStage(b?.stage || b?.status)));
    return copy;
  }
  copy.sort((a, b) => Number(b?.created_at_height || 0) - Number(a?.created_at_height || 0));
  return copy;
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
  const [items, setItems] = useState<any[]>([]);
  const [err, setErr] = useState<{ msg: string; details: any } | null>(null);
  const [acctState, setAcctState] = useState<any | null>(null);
  const [query, setQuery] = useState("");
  const [stageFilter, setStageFilter] = useState("all");
  const [sortMode, setSortMode] = useState("created_desc");
  const [refreshTick, setRefreshTick] = useState(0);

  const [proposalId, setProposalId] = useState("");
  const [title, setTitle] = useState("");
  const [body, setBody] = useState("");
  const [startStage, setStartStage] = useState("poll");
  const [actionTxType, setActionTxType] = useState("");
  const [actionPayloadJson, setActionPayloadJson] = useState("{}");
  const [useAdvancedPayload, setUseAdvancedPayload] = useState(false);
  const [payloadJson, setPayloadJson] = useState(
    JSON.stringify({ proposal_id: "", title: "", body: "", rules: { start_stage: "poll" } }, null, 2),
  );

  const [createErr, setCreateErr] = useState<{ msg: string; details: any } | null>(null);
  const [createRes, setCreateRes] = useState<any>(null);

  const session = getSession();
  const acct = session ? normalizeAccount(session.account) : null;
  const canSign = acct ? !!getKeypair(acct)?.secretKeyB64 : false;
  const resolvedProposalId = useMemo(
    () => proposalId.trim() || buildGeneratedProposalId(acct, title, body),
    [acct, body, proposalId, title],
  );

  const { refresh: refreshAccountContext } = useAccount();
  const tx = useTxQueue();

  const gate = checkGates({
    loggedIn: !!acct,
    canSign,
    accountState: acctState,
    requireTier: 3,
  });

  async function load(): Promise<void> {
    setErr(null);
    try {
      const r: any = await weall.proposals({ limit: 200 }, base);
      setItems(Array.isArray(r?.items) ? r.items : []);
    } catch (e: any) {
      setErr(prettyErr(e));
      setItems([]);
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

  useEffect(() => {
    if (!refreshTick) return undefined;
    let remaining = 8;
    const timer = window.setInterval(() => {
      void load();
      remaining -= 1;
      if (remaining <= 0) {
        window.clearInterval(timer);
        setRefreshTick(0);
      }
    }, 1500);
    return () => window.clearInterval(timer);
  }, [refreshTick]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    const stageNeedle = stageFilter.trim().toLowerCase();
    const subset = items.filter((p) => {
      const stage = asStage(p?.stage || p?.status);
      if (stageNeedle !== "all" && stage !== stageNeedle) return false;
      if (!q) return true;
      const id = proposalIdOf(p).toLowerCase();
      const titleText = proposalTitleOf(p).toLowerCase();
      const bodyText = proposalBodyOf(p).toLowerCase();
      const creator = String(p?.creator || "").toLowerCase();
      return [id, titleText, bodyText, creator, stage].some((x) => x.includes(q));
    });
    return sortItems(subset, sortMode);
  }, [items, query, stageFilter, sortMode]);

  const stageSummary = useMemo(() => {
    const summary: Record<string, number> = {};
    for (const p of items) {
      const s = asStage(p?.stage || p?.status);
      summary[s] = (summary[s] || 0) + 1;
    }
    return summary;
  }, [items]);

  const totalOpenProposals = useMemo(() => {
    return items.filter((p) => !["finalized", "withdrawn"].includes(asStage(p?.stage || p?.status))).length;
  }, [items]);

  async function createProposal(): Promise<void> {
    setCreateErr(null);
    setCreateRes(null);

    try {
      if (!gate.ok) throw new Error(gate.reason || "gated");

      const payload = useAdvancedPayload
        ? JSON.parse(payloadJson)
        : normalizeCreatePayload({
            proposalId,
            title,
            body,
            actionTxType,
            actionPayloadJson,
            startStage,
            account: acct,
          });

      const response = await tx.runTx({
        title: "Create governance proposal",
        pendingMessage: "Submitting proposal…",
        successMessage: "Proposal submitted.",
        errorMessage: (e) => prettyErr(e).msg,
        getTxId: (res: any) => res?.result?.tx_id,
        task: async () =>
          submitSignedTx({
            account: acct!,
            tx_type: "GOV_PROPOSAL_CREATE",
            payload,
            parent: null,
            base,
          }),
      });

      setCreateRes(response);
      setRefreshTick(Date.now());
      await load();
      await loadAccountState();
      await refreshAccountContext();
      const createdProposalId = String(payload?.proposal_id || resolvedProposalId || "").trim();
      if (createdProposalId) {
        window.setTimeout(() => nav(`/proposal/${encodeURIComponent(createdProposalId)}`), 150);
      }
    } catch (e: any) {
      setCreateErr(prettyErr(e));
      setCreateRes(e?.data || e?.body || null);
    }
  }

  return (
    <div className="pageStack pageNarrow">
      <section className="card heroCard">
        <div className="cardBody heroBody compactHero">
          <div className="heroSplit">
            <div>
              <div className="eyebrow">Governance</div>
              <h1 className="heroTitle heroTitleSm">Proposal queue</h1>
              <p className="heroText">
                Browse live governance items, open a proposal to vote, and create new proposals from the same signer-aware civic surface. In the dev tester flow, new proposals should usually start in Poll so voting can begin immediately.
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

      <ErrorBanner message={err?.msg} details={err?.details} onRetry={load} onDismiss={() => setErr(null)} />
      <ErrorBanner
        message={createErr?.msg}
        details={createErr?.details}
        onRetry={() => void createProposal()}
        onDismiss={() => setCreateErr(null)}
      />

      <section className="card">
        <div className="cardBody formStack">
          <div className="sectionHead">
            <div>
              <div className="eyebrow">Browse</div>
              <h2 className="cardTitle">Current proposals</h2>
            </div>
            <div className="statusSummary">
              {refreshTick ? <span className="statusPill ok">Auto-refreshing</span> : null}
              <button className="btn" onClick={() => void load()}>
                Refresh
              </button>
              <button className="btn" onClick={() => nav("/home")}>
                Home
              </button>
            </div>
          </div>

          <div className="grid2">
            <label className="fieldLabel">
              Search
              <input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Search by id, title, body, creator, or stage…"
              />
            </label>

            <div className="grid2">
              <label className="fieldLabel">
                Stage filter
                <select value={stageFilter} onChange={(e) => setStageFilter(e.target.value)}>
                  <option value="all">all</option>
                  <option value="poll">poll</option>
                  <option value="draft">draft (compose only)</option>
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
              Object.entries(stageSummary)
                .sort((a, b) => a[0].localeCompare(b[0]))
                .map(([stage, count]) => (
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
                const id = proposalIdOf(p);
                const titleText = proposalTitleOf(p);
                const bodyText = proposalBodyOf(p);
                const stage = asStage(p?.stage || p?.status);
                const counts = countMapOf(p);
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
                        <article className="summaryCard">
                          <div className="summaryCardLabel">Creator</div>
                          <div className="summaryCardValue mono">{String(p?.creator || "(unknown)")}</div>
                        </article>
                        <article className="summaryCard">
                          <div className="summaryCardLabel">Created height</div>
                          <div className="summaryCardValue">{Number(p?.created_at_height || 0)}</div>
                        </article>
                        <article className="summaryCard">
                          <div className="summaryCardLabel">Vote tally</div>
                          <div className="summaryCardValue">{totalVotes}</div>
                          <div className="summaryCardText">
                            YES {counts.yes} · NO {counts.no} · ABSTAIN {counts.abstain}
                          </div>
                        </article>
                        <article className="summaryCard">
                          <div className="summaryCardLabel">Execution</div>
                          <div className="summaryCardValue">{p?.execution_count || 0}</div>
                          <div className="summaryCardText">
                            {p?.has_actions ? "Contains executable action set" : "Text / lifecycle only"}
                          </div>
                        </article>
                      </div>

                      {bodyText ? (
                        <div className="feedBodyText">{bodyText}</div>
                      ) : (
                        <div className="cardDesc">No description provided.</div>
                      )}

                      <div className="buttonRow">
                        <button className="btn btnPrimary" onClick={() => nav(`/proposal/${encodeURIComponent(id)}`)} disabled={!id}>
                          {primaryActionLabel(stage)}
                        </button>
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
          <div className="summaryCardText">
            This surface intentionally treats civic voting power as personal and non-transferable. Emissaries belong to implementation and treasury flows, not civic vote proxying.
          </div>
        </article>
        <article className="summaryCard">
          <div className="summaryCardLabel">Execution honesty</div>
          <div className="summaryCardValue">Submission ≠ execution</div>
          <div className="summaryCardText">
            A signed proposal creation transaction only creates the proposal. Later lifecycle transitions, tallies, and execution receipts remain authoritative protocol state.
          </div>
        </article>
      </section>

      <section className="card">
        <div className="cardBody formStack">
          <div className="sectionHead">
            <div>
              <div className="eyebrow">Author</div>
              <h2 className="cardTitle">Create governance proposal</h2>
            </div>
            <div className="statusSummary">
              <span className={`statusPill ${gate.ok ? "ok" : ""}`}>{gate.ok ? "Ready" : "Locked"}</span>
            </div>
          </div>

          <label className="fieldLabel">
            <input
              type="checkbox"
              checked={useAdvancedPayload}
              onChange={(e) => setUseAdvancedPayload(e.target.checked)}
            />
            Use advanced payload JSON
          </label>

          {useAdvancedPayload ? (
            <label className="fieldLabel">
              Proposal payload JSON
              <textarea
                rows={16}
                value={payloadJson}
                onChange={(e) => setPayloadJson(e.target.value)}
                placeholder='{"proposal_id":"proposal:alice:1","title":"Example","body":"Body"}'
              />
            </label>
          ) : (
            <>
              <label className="fieldLabel">
                Proposal id
                <input
                  value={proposalId}
                  onChange={(e) => setProposalId(e.target.value)}
                  placeholder="Leave blank to auto-generate"
                />
                <span className="fieldHint">Resolved id: <span className="mono">{resolvedProposalId}</span></span>
              </label>

              <label className="fieldLabel">
                Title
                <input value={title} onChange={(e) => setTitle(e.target.value)} placeholder="Proposal title" />
              </label>

              <label className="fieldLabel">
                Body
                <textarea value={body} onChange={(e) => setBody(e.target.value)} rows={6} placeholder="Describe the proposal clearly." />
              </label>

              <label className="fieldLabel">
                Start stage
                <select value={startStage} onChange={(e) => setStartStage(e.target.value)}>
                  <option value="poll">poll (vote-ready demo)</option>
                  <option value="voting">voting (binding vote now)</option>
                  <option value="revision">revision</option>
                  <option value="validation">validation</option>
                  <option value="draft">draft (compose only)</option>
                </select>
              </label>

              <div className="cardDesc">
                For tester-facing governance flows, keep this at <span className="mono">poll</span>. That makes the proposal immediately openable and voteable after creation. Use <span className="mono">draft</span> only when you intentionally want a non-voteable proposal.
              </div>
              <label className="fieldLabel">
                Optional action tx type
                <input
                  value={actionTxType}
                  onChange={(e) => setActionTxType(e.target.value)}
                  placeholder="GOV_RULES_SET, GOV_QUORUM_SET, VALIDATOR_CANDIDATE_APPROVE, ..."
                />
              </label>

              <label className="fieldLabel">
                Optional action payload JSON
                <textarea
                  rows={8}
                  value={actionPayloadJson}
                  onChange={(e) => setActionPayloadJson(e.target.value)}
                  placeholder='{"params":{"poh":{"tier2_n_jurors":7}}}'
                />
              </label>
            </>
          )}

          <div className="buttonRow">
            <button className="btn btnPrimary" onClick={() => void createProposal()} disabled={!gate.ok}>
              Create proposal and open it
            </button>
            <button className="btn" onClick={() => void load()}>
              Reload proposals
            </button>
          </div>

          {createRes ? (
            <div className="cardDesc mono" style={{ whiteSpace: "pre-wrap" }}>
              {JSON.stringify(createRes, null, 2)}
            </div>
          ) : null}
        </div>
      </section>
    </div>
  );
}
