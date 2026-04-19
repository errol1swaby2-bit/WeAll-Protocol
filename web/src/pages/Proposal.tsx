import React, { useEffect, useMemo, useState } from "react";

import { getApiBaseUrl, weall } from "../api/weall";
import ErrorBanner from "../components/ErrorBanner";
import { getKeypair, getSession, submitSignedTx } from "../auth/session";
import { normalizeAccount } from "../auth/keys";
import { useAccount } from "../context/AccountContext";
import { useTxQueue } from "../hooks/useTxQueue";
import { useSignerSubmissionBusy } from "../hooks/useSignerSubmissionBusy";
import { checkGates, summarizeAccountState } from "../lib/gates";
import { nav } from "../lib/router";
import { actionableTxError, txPendingKey } from "../lib/txAction";
import {
  governanceProposalStageOf,
  normalizeGovernanceProposal,
  reconcileProposalEdit,
  reconcileProposalVote,
  reconcileProposalWithdrawal,
} from "../lib/governance";

function prettyErr(e: any): { msg: string; details: any } {
  return actionableTxError(e, "Governance action failed.");
}

type Props = { id: string };

type VoteMap = Record<string, { vote?: string; height?: number }>;

function asVoteMap(value: any): VoteMap {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};
  return value as VoteMap;
}

function countFromMap(votes: VoteMap): { yes: number; no: number; abstain: number; total: number } {
  let yes = 0;
  let no = 0;
  let abstain = 0;

  for (const signer of Object.keys(votes).sort()) {
    const choice = String(votes[signer]?.vote || "").trim().toLowerCase();
    if (choice === "yes") yes += 1;
    else if (choice === "no") no += 1;
    else if (choice) abstain += 1;
  }

  return { yes, no, abstain, total: yes + no + abstain };
}

function pct(part: number, whole: number): string {
  if (!whole) return "0%";
  return `${Math.round((part / whole) * 100)}%`;
}

function lifecycleSteps(stageRaw: string): Array<{ label: string; state: "done" | "active" | "todo" }> {
  const stage = String(stageRaw || "").toLowerCase();
  const labels = ["Draft", "Poll", "Revision", "Validation", "Voting", "Tallied", "Executed", "Finalized"];
  const activeIndexByStage: Record<string, number> = {
    draft: 0,
    poll: 1,
    revision: 2,
    validation: 3,
    vote: 4,
    voting: 4,
    closed: 5,
    tallied: 5,
    executed: 6,
    finalized: 7,
    withdrawn: 0,
  };
  const active = activeIndexByStage[stage] ?? 0;
  return labels.map((label, idx) => ({
    label,
    state: idx < active ? "done" : idx === active ? "active" : "todo",
  }));
}

function stageBadgeClass(stage: string): string {
  if (["executed", "finalized"].includes(stage)) return "statusPill ok";
  if (["withdrawn", "failed", "expired", "canceled"].includes(stage)) return "statusPill warn";
  return "statusPill";
}

function votingWindowLabel(stage: string): string {
  if (stage === "poll") return "Poll vote";
  if (stage === "voting" || stage === "vote") return "Binding vote";
  return "Voting unavailable";
}

function votingHelpText(params: {
  stage: string;
  gateOk: boolean;
  gateReason: string;
  canVote: boolean;
  currentChoice: string;
}): string {
  const { stage, gateOk, gateReason, canVote, currentChoice } = params;
  if (!gateOk) return gateReason || "Tier 3 and a local signer are required to vote.";
  if (canVote && currentChoice) {
    return `Your current recorded vote is ${currentChoice.toUpperCase()}. This surface now treats proposal voting as one signer, one recorded vote.`;
  }
  if (canVote) {
    return stage === "poll"
      ? "Poll voting is open. Use this to register early sentiment before final validation and binding voting."
      : "Binding voting is open. Your signer-recorded vote is counted directly from the proposal vote map.";
  }
  if (stage === "draft") return "Voting is not open during Draft. Move the proposal into Poll or let the lifecycle progress first.";
  if (stage === "revision") return "Revision is for proposal edits after early sentiment. Voting is paused until the lifecycle reaches Voting.";
  if (stage === "validation") return "Validation is for proposal checks before binding voting begins.";
  if (stage === "closed") return "Voting is closed. The next canonical step is tally publication.";
  if (stage === "tallied") return "Voting has ended and tally publication is recorded.";
  if (stage === "executed") return "Execution has already occurred. Voting is complete.";
  if (stage === "finalized") return "This proposal is finalized. Vote state is frozen.";
  if (stage === "withdrawn") return "Withdrawn proposals cannot accept votes.";
  return "Voting is not open on this proposal right now.";
}


function accountVariants(value: string): string[] {
  const raw = String(value || "").trim();
  if (!raw) return [];
  const normalized = normalizeAccount(raw);
  const base = normalized.startsWith("@") ? normalized.slice(1) : normalized;
  const out = [normalized, base ? `@${base}` : "", base, raw].filter(Boolean);
  return Array.from(new Set(out));
}

function voteForAccount(votes: VoteMap, account: string): { vote?: string; height?: number } | null {
  for (const variant of accountVariants(account)) {
    const rec = votes[variant];
    if (rec && typeof rec === "object") return rec;
  }
  return null;
}
function sortedVoteEntries(votes: VoteMap): Array<[string, { vote?: string; height?: number }]> {
  return Object.entries(votes).sort((a, b) => a[0].localeCompare(b[0]));
}

function nextLifecycleHint(stage: string): string {
  switch (stage) {
    case "draft":
      return "Next expected move: Poll or direct fast-forward into a later canonical stage.";
    case "poll":
      return "Next expected move: Revision, Validation, or direct move into binding voting.";
    case "revision":
      return "Next expected move: Validation before voting.";
    case "validation":
      return "Next expected move: Voting.";
    case "voting":
    case "vote":
      return "Next expected move: Close voting, then publish tally.";
    case "closed":
      return "Next expected move: Publish tally.";
    case "tallied":
      return "Next expected move: Execute proposal actions or finalize as appropriate.";
    case "executed":
      return "Next expected move: Finalize.";
    case "finalized":
      return "Lifecycle complete.";
    case "withdrawn":
      return "Lifecycle ended by proposer withdrawal.";
    default:
      return "Stage is unknown. Refresh from chain state.";
  }
}

function actionReadinessLabel(params: { stage: string; canVote: boolean; canEdit: boolean; canWithdraw: boolean }): string {
  const { stage, canVote, canEdit, canWithdraw } = params;
  if (canVote) return "Voting action available";
  if (canEdit) return "Author edit available";
  if (canWithdraw) return "Author withdrawal available";
  if (["executed", "finalized", "withdrawn"].includes(stage)) return "Read-only stage";
  return "No signer action available";
}


function lifecycleActionHint(stage: string, isCreator: boolean): string {
  if (stage === "draft") {
    return isCreator
      ? "This proposal is still in Draft, so voting is intentionally unavailable. In the current dev flow, create proposals with start_stage=poll to make them vote-ready immediately."
      : "This proposal is still in Draft. Voting begins once the lifecycle reaches Poll or Voting.";
  }
  if (stage === "poll") return "Poll voting is open now. Signers can already register direct sentiment on-chain.";
  if (stage === "voting" || stage === "vote") return "Binding voting is open now.";
  return nextLifecycleHint(stage);
}

export default function Proposal({ id }: Props): JSX.Element {
  const base = useMemo(() => getApiBaseUrl(), []);
  const [proposal, setProposal] = useState<any | null>(null);
  const [proposalVotes, setProposalVotes] = useState<any | null>(null);
  const [err, setErr] = useState<{ msg: string; details: any } | null>(null);

  const [acctState, setAcctState] = useState<any | null>(null);

  const [voteRes, setVoteRes] = useState<any>(null);
  const [voteErr, setVoteErr] = useState<{ msg: string; details: any } | null>(null);

  const [adminRes, setAdminRes] = useState<any>(null);
  const [adminErr, setAdminErr] = useState<{ msg: string; details: any } | null>(null);

  const [editTitle, setEditTitle] = useState("");
  const [editBody, setEditBody] = useState("");
  const [refreshTick, setRefreshTick] = useState(0);

  const session = getSession();
  const acct = session ? normalizeAccount(session.account) : null;
  const canSign = acct ? !!getKeypair(acct)?.secretKeyB64 : false;
  const { refresh: refreshAccountContext } = useAccount();
  const tx = useTxQueue();

  async function load(): Promise<void> {
    setErr(null);
    try {
      const [r, vr] = await Promise.all([weall.proposal(id, base), weall.proposalVotes(id, base)]);
      const p = normalizeGovernanceProposal((r as any)?.proposal || r || null);
      setProposal(p);
      setProposalVotes(vr);
      setEditTitle(String(p?.title || ""));
      setEditBody(String(p?.body || ""));
    } catch (e: any) {
      setErr(prettyErr(e));
      setProposal(null);
      setProposalVotes(null);
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
  }, [id, acct, base]);

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

  const pid = String(proposal?.proposal_id || proposal?.id || id || "");
  const title = String(proposal?.title || pid || "(proposal)");
  const stage = governanceProposalStageOf(proposal);

  const gate = checkGates({
    loggedIn: !!acct,
    canSign,
    accountState: acctState,
    requireTier: 3,
  });

  async function doTx(
    tx_type: string,
    payload: any,
    toastTitle: string,
    successMessage: string,
  ): Promise<void> {
    setAdminErr(null);
    setAdminRes(null);

    try {
      if (!gate.ok) throw new Error(gate.reason || "gated");
      if (signerBusy) throw new Error("signer_submission_busy");

      const r = await tx.runTx({
        title: toastTitle,
        pendingKey: txPendingKey(["proposal", tx_type, pid, acct]),
        pendingMessage: "Submitting governance action…",
        successMessage,
        errorMessage: (e) => prettyErr(e).msg,
        getTxId: (res: any) => res?.result?.tx_id,
        finality: {
          timeoutMs: 16000,
          reconcile: async () => {
            if (tx_type === "GOV_PROPOSAL_WITHDRAW") return reconcileProposalWithdrawal({ proposalId: pid, base });
            if (tx_type === "GOV_PROPOSAL_EDIT") return reconcileProposalEdit({ proposalId: pid, title: payload?.title, body: payload?.body, base });
            return null;
          },
        },
        task: async () =>
          submitSignedTx({
            account: acct!,
            tx_type,
            payload,
            parent: null,
            base,
          }),
      });

      setAdminRes(r);
      setRefreshTick(Date.now());
      await load();
      await loadAccountState();
      await refreshAccountContext();
    } catch (e: any) {
      setAdminErr(prettyErr(e));
      setAdminRes(e?.data || e?.body || null);
    }
  }

  async function castVote(choice: "yes" | "no" | "abstain"): Promise<void> {
    setVoteErr(null);
    setVoteRes(null);

    try {
      if (!gate.ok) throw new Error(gate.reason || "gated");
      if (signerBusy) throw new Error("signer_submission_busy");

      const r = await tx.runTx({
        title: "Cast vote",
        pendingKey: txPendingKey(["proposal-vote", pid, acct, choice]),
        pendingMessage: `Submitting ${choice} vote…`,
        successMessage: `Vote recorded: ${choice}.`,
        errorMessage: (e) => prettyErr(e).msg,
        getTxId: (res: any) => res?.result?.tx_id,
        finality: {
          timeoutMs: 16000,
          reconcile: async () => reconcileProposalVote({ proposalId: pid, account: acct!, choice, base }),
        },
        task: async () =>
          submitSignedTx({
            account: acct!,
            tx_type: "GOV_VOTE_CAST",
            payload: { proposal_id: pid, choice },
            parent: null,
            base,
          }),
      });

      setVoteRes(r);
      setRefreshTick(Date.now());
      await load();
      await loadAccountState();
      await refreshAccountContext();
    } catch (e: any) {
      setVoteErr(prettyErr(e));
      setVoteRes(e?.data || e?.body || null);
    }
  }

  async function revokeVote(): Promise<void> {
    await doTx("GOV_VOTE_REVOKE", { proposal_id: pid }, "Revoke vote", "Vote revoked.");
  }

  async function editProposal(): Promise<void> {
    await doTx(
      "GOV_PROPOSAL_EDIT",
      {
        proposal_id: pid,
        title: editTitle.trim(),
        body: editBody.trim(),
      },
      "Edit proposal",
      "Proposal edit submitted.",
    );
  }

  async function withdrawProposal(): Promise<void> {
    await doTx("GOV_PROPOSAL_WITHDRAW", { proposal_id: pid }, "Withdraw proposal", "Proposal withdrawn.");
  }

  const pollVotes = asVoteMap(proposalVotes?.poll_votes ?? proposal?.poll_votes);
  const finalVotes = asVoteMap(proposalVotes?.votes ?? proposal?.votes);

  const pollCount = countFromMap(pollVotes);
  const finalCount = countFromMap(finalVotes);
  const displayedVoteMap = stage === "poll"
    ? pollVotes
    : finalCount.total > 0
      ? finalVotes
      : pollCount.total > 0
        ? pollVotes
        : finalVotes;
  const activeCount = countFromMap(displayedVoteMap);

  const yesPct = pct(activeCount.yes, activeCount.total);
  const noPct = pct(activeCount.no, activeCount.total);
  const abstainPct = pct(activeCount.abstain, activeCount.total);
  const life = lifecycleSteps(stage);
  const accountSummary = acctState ? summarizeAccountState(acctState) : "(state unknown)";
  const signerSubmission = useSignerSubmissionBusy(acct);
  const signerBusy = signerSubmission.busy;
  const voteWindowOpen = ["poll", "voting", "vote"].includes(stage);
  const activeVoteMap = stage === "poll" ? pollVotes : displayedVoteMap;
  const currentVoteRecord = acct ? (voteForAccount(activeVoteMap, acct) || voteForAccount(finalVotes, acct) || voteForAccount(pollVotes, acct)) : null;
  const currentChoice = String(currentVoteRecord?.vote || "").trim().toLowerCase();
  const canVote = gate.ok && voteWindowOpen && !currentChoice;
  const isCreator = gate.ok && acct === String(proposal?.creator || "");
  const canEdit = isCreator && ["draft", "poll", "revision", "validation", "voting", "vote"].includes(stage);
  const canWithdraw = isCreator && !["withdrawn", "executed", "finalized"].includes(stage);
  const voteModeLabel = votingWindowLabel(stage);
  const voteHelp = votingHelpText({
    stage,
    gateOk: gate.ok,
    gateReason: gate.reason || "",
    canVote,
    currentChoice,
  });
  const readiness = actionReadinessLabel({ stage, canVote, canEdit, canWithdraw });
  const canRevoke = gate.ok && !signerBusy && !!currentChoice && !["closed", "tallied", "executed", "finalized", "withdrawn"].includes(stage);

  return (
    <div className="pageStack pageNarrow">
      <section className="card heroCard">
        <div className="cardBody heroBody compactHero">
          <div className="heroSplit">
            <div>
              <div className="eyebrow">Governance</div>
              <h1 className="heroTitle heroTitleSm">{title}</h1>
              <p className="heroText">
                Proposal detail keeps lifecycle state, direct vote activity, and proposer controls in one place. It is designed to show the difference between submitting an action and the chain later recognizing a stage change or execution outcome.
              </p>
            </div>
            <div className="heroInfoPanel">
              <div className="heroInfoTitle">Status</div>
              <div className="heroInfoList">
                <span className={stageBadgeClass(stage)}>{stage}</span>
                <span className="statusPill">Votes {activeCount.total}</span>
                <span className={`statusPill ${gate.ok ? "ok" : ""}`}>
                  {gate.ok ? "Tier 3 eligible" : "Tier 3 required"}
                </span>
                <span className="statusPill">{accountSummary}</span>
              </div>
            </div>
          </div>

          <div className="heroActions">
            <button className="btn" onClick={() => nav("/proposals")}>
              Back to proposals
            </button>
            <button className="btn" onClick={() => void load()}>
              Refresh detail
            </button>
          </div>

          <div className="statsGrid statsGridCompact">
            <div className="statCard">
              <span className="statLabel">YES</span>
              <span className="statValue">{activeCount.yes}</span>
            </div>
            <div className="statCard">
              <span className="statLabel">NO</span>
              <span className="statValue">{activeCount.no}</span>
            </div>
            <div className="statCard">
              <span className="statLabel">ABSTAIN</span>
              <span className="statValue">{activeCount.abstain}</span>
            </div>
            <div className="statCard">
              <span className="statLabel">Proposal id</span>
              <span className="statValue mono">{pid || "(unknown)"}</span>
            </div>
          </div>
        </div>
      </section>

      <ErrorBanner message={err?.msg} details={err?.details} onRetry={load} onDismiss={() => setErr(null)} />
      <ErrorBanner message={voteErr?.msg} details={voteErr?.details} onDismiss={() => setVoteErr(null)} />
      <ErrorBanner message={adminErr?.msg} details={adminErr?.details} onDismiss={() => setAdminErr(null)} />

      {stage === "draft" ? (
        <section className="card">
          <div className="cardBody formStack">
            <div className="sectionHead">
              <div>
                <div className="eyebrow">Draft-only status</div>
                <h2 className="cardTitle">This proposal is not vote-ready yet</h2>
              </div>
              <div className="statusSummary">
                <span className="statusPill warn">Draft only</span>
              </div>
            </div>
            <div className="cardDesc">
              Draft should normally end on the create surface. For tester-facing governance runs, create proposals with <span className="mono">start_stage=poll</span> so direct voting is available immediately after creation.
            </div>
            <div className="buttonRow">
              <button className="btn btnPrimary" onClick={() => nav("/proposals")}>Back to create flow</button>
            </div>
          </div>
        </section>
      ) : null}

      <section className="summaryCardGrid">
        <article className="summaryCard">
          <div className="summaryCardLabel">Voting model</div>
          <div className="summaryCardValue">Direct civic voting only</div>
          <div className="summaryCardText">
            This proposal uses direct voter records keyed by signer. Governance participation is personal and non-delegable.
          </div>
        </article>
        <article className="summaryCard">
          <div className="summaryCardLabel">Execution honesty</div>
          <div className="summaryCardValue">Submission ≠ protocol effect</div>
          <div className="summaryCardText">
            Proposal edits, withdrawals, and votes are submitted as transactions. Later lifecycle transitions and execution receipts remain authoritative protocol state.
          </div>
        </article>
      </section>

      <section className="card">
        <div className="cardBody formStack">
          <div className="sectionHead">
            <div>
              <div className="eyebrow">Participation</div>
              <h2 className="cardTitle">Vote on this proposal</h2>
            </div>
            <div className="statusSummary">
              <span className={`statusPill ${canVote ? "ok" : ""}`}>{voteModeLabel}</span>
              {currentChoice ? <span className="statusPill">Current: {currentChoice}</span> : null}
            </div>
          </div>

          <div className="cardDesc">{voteHelp}</div>

          <div className="summaryCardGrid">
            <article className="summaryCard">
              <div className="summaryCardLabel">Window</div>
              <div className="summaryCardValue">{voteWindowOpen ? "Open" : "Closed"}</div>
              <div className="summaryCardText">{stage}</div>
            </article>
            <article className="summaryCard">
              <div className="summaryCardLabel">Eligibility</div>
              <div className="summaryCardValue">{gate.ok ? "Eligible" : "Not ready"}</div>
              <div className="summaryCardText">{accountSummary}</div>
            </article>
            <article className="summaryCard">
              <div className="summaryCardLabel">Your vote</div>
              <div className="summaryCardValue">{currentChoice ? currentChoice.toUpperCase() : "None"}</div>
              <div className="summaryCardText">Signer-keyed direct vote</div>
            </article>
          </div>

          <div className="buttonRow">
            <button className="btn btnPrimary" onClick={() => void castVote("yes")} disabled={!canVote || signerBusy}>
              Vote yes
            </button>
            <button className="btn" onClick={() => void castVote("no")} disabled={!canVote || signerBusy}>
              Vote no
            </button>
            <button className="btn" onClick={() => void castVote("abstain")} disabled={!canVote || signerBusy}>
              Abstain
            </button>
            <button className="btn" onClick={() => void revokeVote()} disabled={!canRevoke}>
              Revoke vote
            </button>
          </div>
        </div>
      </section>

      <section className="card">
        <div className="cardBody formStack">
          <div className="sectionHead">
            <div>
              <div className="eyebrow">Lifecycle</div>
              <h2 className="cardTitle">Proposal path</h2>
            </div>
            <div className="statusSummary">
              <span className="statusPill">{readiness}</span>
            </div>
          </div>

          <div className="statsGrid" style={{ gridTemplateColumns: "repeat(8, minmax(0, 1fr))" }}>
            {life.map((step) => (
              <div
                key={step.label}
                className="statCard"
                style={{
                  borderColor:
                    step.state === "done"
                      ? "rgba(134, 239, 172, 0.35)"
                      : step.state === "active"
                        ? "rgba(111, 231, 255, 0.32)"
                        : undefined,
                }}
              >
                <span className="statLabel">
                  {step.state === "done" ? "Done" : step.state === "active" ? "Current" : "Next"}
                </span>
                <span className="statValue">{step.label}</span>
              </div>
            ))}
          </div>

          <div className="summaryCardGrid">
            <article className="summaryCard">
              <div className="summaryCardLabel">Creator</div>
              <div className="summaryCardValue mono">{String(proposal?.creator || "(unknown)")}</div>
            </article>
            <article className="summaryCard">
              <div className="summaryCardLabel">Created height</div>
              <div className="summaryCardValue">{Number(proposal?.created_at_height || 0)}</div>
            </article>
            <article className="summaryCard">
              <div className="summaryCardLabel">Updated height</div>
              <div className="summaryCardValue">{Number(proposal?.updated_at_height || 0)}</div>
            </article>
            <article className="summaryCard">
              <div className="summaryCardLabel">Execution count</div>
              <div className="summaryCardValue">{Number(proposal?.execution_count || proposal?.executions?.length || 0)}</div>
            </article>
          </div>

          <div className="cardDesc">{lifecycleActionHint(stage, isCreator)}</div>

          <div className="buttonRow">
            {canVote ? (
              <button className="btn btnPrimary" onClick={() => void castVote("yes")}>
                Quick vote yes
              </button>
            ) : currentChoice ? (
              <span className="statusPill ok">Vote already recorded</span>
            ) : null}
            {canEdit ? (
              <button className="btn" onClick={() => window.scrollTo({ top: document.body.scrollHeight, behavior: "smooth" })}>
                Jump to author controls
              </button>
            ) : null}
            <button className="btn" onClick={() => void load()}>
              Reload chain state
            </button>
          </div>
        </div>
      </section>

      <section className="grid2">
        <article className="card">
          <div className="cardBody formStack">
            <div className="sectionHead">
              <div>
                <div className="eyebrow">Description</div>
                <h2 className="cardTitle">Proposal body</h2>
              </div>
            </div>

            {proposal?.body ? (
              <div className="feedBodyText">{String(proposal.body)}</div>
            ) : (
              <div className="cardDesc">No proposal body provided.</div>
            )}

            {Array.isArray(proposal?.actions) && proposal.actions.length > 0 ? (
              <>
                <div className="eyebrow">Action set</div>
                <div className="cardDesc mono" style={{ whiteSpace: "pre-wrap" }}>
                  {JSON.stringify(proposal.actions, null, 2)}
                </div>
              </>
            ) : null}
          </div>
        </article>

        <article className="card">
          <div className="cardBody formStack">
            <div className="sectionHead">
              <div>
                <div className="eyebrow">Vote summary</div>
                <h2 className="cardTitle">
                  {displayedVoteMap === pollVotes ? "Poll votes" : "Final votes"}
                </h2>
              </div>
            </div>

            <div className="summaryCardGrid">
              <article className="summaryCard">
                <div className="summaryCardLabel">YES</div>
                <div className="summaryCardValue">{activeCount.yes}</div>
                <div className="summaryCardText">{yesPct}</div>
              </article>
              <article className="summaryCard">
                <div className="summaryCardLabel">NO</div>
                <div className="summaryCardValue">{activeCount.no}</div>
                <div className="summaryCardText">{noPct}</div>
              </article>
              <article className="summaryCard">
                <div className="summaryCardLabel">ABSTAIN</div>
                <div className="summaryCardValue">{activeCount.abstain}</div>
                <div className="summaryCardText">{abstainPct}</div>
              </article>
              <article className="summaryCard">
                <div className="summaryCardLabel">Total</div>
                <div className="summaryCardValue">{activeCount.total}</div>
                <div className="summaryCardText">Counted from signer map</div>
              </article>
            </div>

            {sortedVoteEntries(activeCount.total > 0 ? (stage === "poll" ? pollVotes : finalVotes) : {}).length > 0 ? (
              <div className="pageStack">
                {sortedVoteEntries(stage === "poll" ? pollVotes : finalVotes).map(([signer, rec]) => (
                  <article key={signer} className="summaryCard">
                    <div className="summaryCardLabel mono">{signer}</div>
                    <div className="summaryCardValue">{String(rec?.vote || "").toUpperCase()}</div>
                    <div className="summaryCardText">Height {Number(rec?.height || 0)}</div>
                  </article>
                ))}
              </div>
            ) : (
              <div className="cardDesc">No direct votes recorded for the current stage yet.</div>
            )}
          </div>
        </article>
      </section>

      {(canEdit || canWithdraw) ? (
        <section className="grid2">
          <article className="card">
            <div className="cardBody formStack">
              <div className="sectionHead">
                <div>
                  <div className="eyebrow">Author control</div>
                  <h2 className="cardTitle">Edit proposal</h2>
                </div>
              </div>

              <label className="fieldLabel">
                Title
                <input value={editTitle} onChange={(e) => setEditTitle(e.target.value)} />
              </label>

              <label className="fieldLabel">
                Body
                <textarea rows={8} value={editBody} onChange={(e) => setEditBody(e.target.value)} />
              </label>

              <div className="buttonRow">
                <button className="btn btnPrimary" onClick={() => void editProposal()} disabled={!canEdit}>
                  Submit edit
                </button>
              </div>
            </div>
          </article>

          <article className="card">
            <div className="cardBody formStack">
              <div className="sectionHead">
                <div>
                  <div className="eyebrow">Author control</div>
                  <h2 className="cardTitle">Withdraw proposal</h2>
                </div>
              </div>

              <div className="cardDesc">
                Withdrawal is only available while the proposal is still in a mutable, non-terminal stage and only to the original creator.
              </div>

              <div className="buttonRow">
                <button className="btn" onClick={() => void withdrawProposal()} disabled={!canWithdraw || signerBusy}>
                  Withdraw proposal
                </button>
              </div>
            </div>
          </article>
        </section>
      ) : null}

      {voteRes || adminRes ? (
        <section className="card">
          <div className="cardBody formStack">
            <div className="sectionHead">
              <div>
                <div className="eyebrow">Latest result</div>
                <h2 className="cardTitle">Submission response</h2>
              </div>
              {refreshTick ? (
                <div className="statusSummary">
                  <span className="statusPill ok">Auto-refreshing</span>
                </div>
              ) : null}
            </div>

            <div className="cardDesc mono" style={{ whiteSpace: "pre-wrap" }}>
              {JSON.stringify(voteRes || adminRes, null, 2)}
            </div>
          </div>
        </section>
      ) : null}
    </div>
  );
}
