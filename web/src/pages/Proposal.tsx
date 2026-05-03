import React, { useEffect, useMemo, useState } from "react";

import { getApiBaseUrl, weall } from "../api/weall";
import ErrorBanner from "../components/ErrorBanner";
import { getKeypair, getSession, submitSignedTx } from "../auth/session";
import { normalizeAccount } from "../auth/keys";
import { useAccount } from "../context/AccountContext";
import { useTxQueue } from "../hooks/useTxQueue";
import { useMutationRefresh } from "../hooks/useMutationRefresh";
import { useSignerSubmissionBusy } from "../hooks/useSignerSubmissionBusy";
import { checkGates, summarizeAccountState } from "../lib/gates";
import { decisionStageHelp, decisionStageLabel, decisionVoteChoiceLabel } from "../lib/userLanguage";
import { nav } from "../lib/router";
import { voteForAccount } from "../lib/accountSurface";
import { refreshMutationSlices } from "../lib/revalidation";
import { actionableTxError, txPendingKey } from "../lib/txAction";
import {
  governanceProposalStageOf,
  normalizeGovernanceProposal,
  reconcileProposalEdit,
  reconcileProposalVote,
  reconcileProposalWithdrawal,
} from "../lib/governance";

function prettyErr(e: any): { msg: string; details: any } {
  return actionableTxError(e, "Decision action failed.");
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
  const labels = ["Draft", "Early input", "Revision", "Readiness check", "Voting", "Results counted", "Changes applied", "Final result"];
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
  if (stage === "poll") return "Early input open";
  if (stage === "voting" || stage === "vote") return "Voting open";
  return "Voting closed";
}

function votingHelpText(params: {
  stage: string;
  gateOk: boolean;
  gateReason: string;
  canVote: boolean;
  currentChoice: string;
}): string {
  const { stage, gateOk, gateReason, canVote, currentChoice } = params;
  if (!gateOk) return gateReason || "Complete live verification and keep this device signed in before voting.";
  if (canVote && currentChoice) {
    return `Your current recorded vote is ${decisionVoteChoiceLabel(currentChoice)}. Each signed-in person has one recorded vote on this decision.`;
  }
  if (canVote) {
    return stage === "poll"
      ? "Early input is open. Use this to share where you stand before the final vote."
      : "Voting is open. Your vote will be recorded for this decision.";
  }
  if (stage === "draft") return "Voting is not open while this decision is still a draft.";
  if (stage === "revision") return "This decision is being revised. Voting is paused until voting opens again.";
  if (stage === "validation") return "This decision is being checked before voting opens.";
  if (stage === "closed") return "Voting is closed. The next canonical step is tally publication.";
  if (stage === "tallied") return "Voting has ended and tally publication is recorded.";
  if (stage === "executed") return "Approved changes have already been applied. Voting is complete.";
  if (stage === "finalized") return "This decision is finalized. Votes can no longer change.";
  if (stage === "withdrawn") return "Withdrawn decisions cannot accept votes.";
  return "Voting is not open on this decision right now.";
}


function sortedVoteEntries(votes: VoteMap): Array<[string, { vote?: string; height?: number }]> {
  return Object.entries(votes).sort((a, b) => a[0].localeCompare(b[0]));
}

function nextLifecycleHint(stage: string): string {
  switch (stage) {
    case "draft":
      return "Next expected step: open for early input or move to a later status.";
    case "poll":
      return "Next expected step: revision, checking, or voting.";
    case "revision":
      return "Next expected step: readiness check before voting.";
    case "validation":
      return "Next expected step: open voting.";
    case "voting":
    case "vote":
      return "Next expected step: close voting, then publish the result.";
    case "closed":
      return "Next expected step: publish results.";
    case "tallied":
      return "Next expected step: apply approved changes or publish the final result.";
    case "executed":
      return "Next expected step: publish final result.";
    case "finalized":
      return "Decision complete.";
    case "withdrawn":
      return "Lifecycle ended by proposer withdrawal.";
    default:
      return "Status is unknown. Refresh and try again.";
  }
}

function actionReadinessLabel(params: { stage: string; canVote: boolean; canEdit: boolean; canWithdraw: boolean }): string {
  const { stage, canVote, canEdit, canWithdraw } = params;
  if (canVote) return "Voting action available";
  if (canEdit) return "Author edit available";
  if (canWithdraw) return "Author withdrawal available";
  if (["executed", "finalized", "withdrawn"].includes(stage)) return "Read-only status";
  return "No action available";
}


function lifecycleActionHint(stage: string, isCreator: boolean): string {
  if (stage === "draft") {
    return isCreator
      ? "This decision is still a draft, so voting is intentionally unavailable. In test flows, start decisions in poll status when they should be vote-ready immediately."
      : "This decision is still a draft. Voting begins once it moves to poll or voting status.";
  }
  if (stage === "poll") return "Early input is open now. Eligible people can record where they stand.";
  if (stage === "voting" || stage === "vote") return "Voting is open now.";
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


  const pid = String(proposal?.proposal_id || proposal?.id || id || "");

  useMutationRefresh({
    entityTypes: ["proposal"],
    entityIds: [pid],
    account: acct,
    onRefresh: async () => {
      await load();
      await loadAccountState();
    },
  });
  const title = String(proposal?.title || pid || "(decision)");
  const stage = governanceProposalStageOf(proposal);

  const gate = checkGates({
    loggedIn: !!acct,
    canSign,
    accountState: acctState,
    requireTier: 2,
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
      if (signerBusy) throw new Error("another_action_is_saving");

      const r = await tx.runTx({
        title: toastTitle,
        pendingKey: txPendingKey(["proposal", tx_type, pid, acct]),
        pendingMessage: "Saving decision action…",
        successMessage,
        errorMessage: (e) => prettyErr(e).msg,
        getTxId: (res: any) => res?.result?.tx_id,
        finality: {
          timeoutMs: 16000,
          mutation: { entityType: "proposal", entityId: pid, account: acct || undefined, routeHint: `/decisions/${encodeURIComponent(pid)}`, txType: "GOV_VOTE_CAST" },
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
      await refreshMutationSlices(load, loadAccountState, refreshAccountContext);
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
      if (signerBusy) throw new Error("another_action_is_saving");

      const r = await tx.runTx({
        title: "Cast vote",
        pendingKey: txPendingKey(["proposal-vote", pid, acct, choice]),
        pendingMessage: `Recording ${decisionVoteChoiceLabel(choice)} vote…`,
        successMessage: `Vote recorded: ${decisionVoteChoiceLabel(choice)}.`,
        errorMessage: (e) => prettyErr(e).msg,
        getTxId: (res: any) => res?.result?.tx_id,
        finality: {
          timeoutMs: 16000,
          mutation: { entityType: "proposal", entityId: pid, account: acct || undefined, routeHint: `/decisions/${encodeURIComponent(pid)}`, txType: "GOV_VOTE_CAST" },
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
      await refreshMutationSlices(load, loadAccountState, refreshAccountContext);
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
      "Edit decision",
      "Decision edit saved.",
    );
  }

  async function withdrawProposal(): Promise<void> {
    await doTx("GOV_PROPOSAL_WITHDRAW", { proposal_id: pid }, "Withdraw decision", "Decision withdrawn.");
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
    <div className="pageStack pageNarrow detailPage proposalDetailPage">
      <section className="card heroCard detailHeroCard">
        <div className="cardBody heroBody compactHero">
          <div className="heroSplit">
            <div>
              <div className="eyebrow">Decision</div>
              <h1 className="heroTitle heroTitleSm">{title}</h1>
              <p className="heroText">
                Decision detail keeps status, voting activity, and creator controls in one place. It separates saving an action from the final visible result.
              </p>
            </div>
            <div className="heroInfoPanel">
              <div className="heroInfoTitle">Status</div>
              <div className="heroInfoList">
                <span className={stageBadgeClass(stage)}>{stage}</span>
                <span className="statusPill">Votes {activeCount.total}</span>
                <span className={`statusPill ${gate.ok ? "ok" : ""}`}>
                  {gate.ok ? "Trusted Verified Person" : "Live verification required"}
                </span>
                <span className="statusPill">{accountSummary}</span>
              </div>
            </div>
          </div>

          <div className="heroActions">
            <button className="btn" onClick={() => nav("/decisions")}>
              Back to decisions
            </button>
            <button className="btn" onClick={() => void refreshMutationSlices(load, loadAccountState, refreshAccountContext)}>
              Refresh detail
            </button>
          </div>

          <div className="statsGrid statsGridCompact">
            <div className="statCard">
              <span className="statLabel">Yes</span>
              <span className="statValue">{activeCount.yes}</span>
            </div>
            <div className="statCard">
              <span className="statLabel">No</span>
              <span className="statValue">{activeCount.no}</span>
            </div>
            <div className="statCard">
              <span className="statLabel">Abstain</span>
              <span className="statValue">{activeCount.abstain}</span>
            </div>
            <div className="statCard">
              <span className="statLabel">Decision id</span>
              <span className="statValue mono">{pid || "(unknown)"}</span>
            </div>
          </div>
        </div>
      </section>

      <ErrorBanner message={err?.msg} details={err?.details} onRetry={() => void refreshMutationSlices(load, loadAccountState, refreshAccountContext)} onDismiss={() => setErr(null)} />
      <ErrorBanner message={voteErr?.msg} details={voteErr?.details} onDismiss={() => setVoteErr(null)} />
      <ErrorBanner message={adminErr?.msg} details={adminErr?.details} onDismiss={() => setAdminErr(null)} />

      <section className="detailFocusStrip">
        <article className="detailFocusCard">
          <div className="detailFocusLabel">Primary object</div>
          <div className="detailFocusValue">Decision detail</div>
          <div className="detailFocusText">This route is for one decision only. Queue browsing belongs on the decisions hub.</div>
        </article>
        <article className="detailFocusCard">
          <div className="detailFocusLabel">Current dominant action</div>
          <div className="detailFocusValue">{canVote ? "Vote now" : canEdit ? "Author controls" : "Read-only review"}</div>
          <div className="detailFocusText">{voteHelp}</div>
        </article>
        <article className="detailFocusCard">
          <div className="detailFocusLabel">Current status</div>
          <div className="detailFocusValue">{readiness}</div>
          <div className="detailFocusText">{nextLifecycleHint(stage)}</div>
        </article>
      </section>

      {stage === "draft" ? (
        <section className="card">
          <div className="cardBody formStack">
            <div className="sectionHead">
              <div>
                <div className="eyebrow">Draft-only status</div>
                <h2 className="cardTitle">This decision is not vote-ready yet</h2>
              </div>
              <div className="statusSummary">
                <span className="statusPill warn">Draft only</span>
              </div>
            </div>
            <div className="cardDesc">
              Draft should normally end on the create surface. For tester-facing decision runs, create decisions with <span className="mono">start_stage=poll</span> so voting is available immediately after creation.
            </div>
            <div className="buttonRow">
              <button className="btn btnPrimary" onClick={() => nav("/decisions/create")}>Open decision composer</button>
            </div>
          </div>
        </section>
      ) : null}

      <section className="summaryCardGrid">
        <article className="summaryCard">
          <div className="summaryCardLabel">Voting model</div>
          <div className="summaryCardValue">Direct civic voting only</div>
          <div className="summaryCardText">
            This decision uses direct voter records. Participation is personal and non-delegable.
          </div>
        </article>
        <article className="summaryCard">
          <div className="summaryCardLabel">Outcome clarity</div>
          <div className="summaryCardValue">Saving is not approval</div>
          <div className="summaryCardText">
            Decision edits, withdrawals, and votes are saved first. Later status changes and results remain authoritative backend state.
          </div>
        </article>
      </section>

      <section className="card">
        <div className="cardBody formStack">
          <div className="sectionHead">
            <div>
              <div className="eyebrow">Participation</div>
              <h2 className="cardTitle">Vote on this decision</h2>
            </div>
            <div className="statusSummary">
              <span className={`statusPill ${canVote ? "ok" : ""}`}>{voteModeLabel}</span>
              {currentChoice ? <span className="statusPill">Current: {decisionVoteChoiceLabel(currentChoice)}</span> : null}
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
              <div className="summaryCardValue">{decisionVoteChoiceLabel(currentChoice)}</div>
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
              <h2 className="cardTitle">Decision path</h2>
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
              <div className="summaryCardLabel">Status note</div>
              <div className="summaryCardValue">{decisionStageLabel(stage)}</div>
              <div className="summaryCardText">{decisionStageHelp(stage)}</div>
            </article>
            <article className="summaryCard">
              <div className="summaryCardLabel">Next step</div>
              <div className="summaryCardValue">{readiness}</div>
            </article>
            <article className="summaryCard">
              <div className="summaryCardLabel">Applied changes</div>
              <div className="summaryCardValue">{Number(proposal?.execution_count || proposal?.executions?.length || 0)}</div>
            </article>
          </div>

          <div className="cardDesc">{lifecycleActionHint(stage, isCreator)}</div>

          <div className="buttonRow">
            {canVote ? (
              <button className="btn btnPrimary" onClick={() => void castVote("yes")}>
                Vote Yes
              </button>
            ) : currentChoice ? (
              <span className="statusPill ok">Vote already recorded</span>
            ) : null}
            {canEdit ? (
              <button className="btn" onClick={() => window.scrollTo({ top: document.body.scrollHeight, behavior: "smooth" })}>
                Jump to author controls
              </button>
            ) : null}
            <button className="btn" onClick={() => void refreshMutationSlices(load, loadAccountState, refreshAccountContext)}>{signerBusy ? "Waiting…" : "Refresh decision"}</button>
          </div>
        </div>
      </section>

      <section className="grid2">
        <article className="card">
          <div className="cardBody formStack">
            <div className="sectionHead">
              <div>
                <div className="eyebrow">Description</div>
                <h2 className="cardTitle">Decision description</h2>
              </div>
            </div>

            {proposal?.body ? (
              <div className="feedBodyText">{String(proposal.body)}</div>
            ) : (
              <div className="cardDesc">No decision description provided.</div>
            )}

            {Array.isArray(proposal?.actions) && proposal.actions.length > 0 ? (
              <details className="detailsPanel">
                <summary>View technical record</summary>
                <div className="cardDesc mono" style={{ whiteSpace: "pre-wrap" }}>
                  {JSON.stringify(proposal.actions, null, 2)}
                </div>
              </details>
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
                <div className="summaryCardLabel">Yes</div>
                <div className="summaryCardValue">{activeCount.yes}</div>
                <div className="summaryCardText">{yesPct}</div>
              </article>
              <article className="summaryCard">
                <div className="summaryCardLabel">No</div>
                <div className="summaryCardValue">{activeCount.no}</div>
                <div className="summaryCardText">{noPct}</div>
              </article>
              <article className="summaryCard">
                <div className="summaryCardLabel">Abstain</div>
                <div className="summaryCardValue">{activeCount.abstain}</div>
                <div className="summaryCardText">{abstainPct}</div>
              </article>
              <article className="summaryCard">
                <div className="summaryCardLabel">Total</div>
                <div className="summaryCardValue">{activeCount.total}</div>
                <div className="summaryCardText">Counted from recorded votes</div>
              </article>
            </div>

            {sortedVoteEntries(activeCount.total > 0 ? (stage === "poll" ? pollVotes : finalVotes) : {}).length > 0 ? (
              <div className="pageStack">
                {sortedVoteEntries(stage === "poll" ? pollVotes : finalVotes).map(([signer, rec]) => (
                  <article key={signer} className="summaryCard">
                    <div className="summaryCardLabel mono">{signer}</div>
                    <div className="summaryCardValue">{decisionVoteChoiceLabel(rec?.vote)}</div>
                    <div className="summaryCardText">Record {Number(rec?.height || 0)}</div>
                  </article>
                ))}
              </div>
            ) : (
              <div className="cardDesc">No votes recorded for the current status yet.</div>
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
                  <h2 className="cardTitle">Edit decision</h2>
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
                  <h2 className="cardTitle">Withdraw decision</h2>
                </div>
              </div>

              <div className="cardDesc">
                Withdrawal is only available while the decision is still editable and only to the original creator.
              </div>

              <div className="buttonRow">
                <button className="btn" onClick={() => void withdrawProposal()} disabled={!canWithdraw || signerBusy}>
                  Withdraw decision
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
                <h2 className="cardTitle">Latest action response</h2>
              </div>
              
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
