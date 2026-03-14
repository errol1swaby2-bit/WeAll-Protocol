import React, { useEffect, useMemo, useState } from "react";

import { getApiBaseUrl, weall } from "../api/weall";
import ErrorBanner from "../components/ErrorBanner";
import { nav } from "../lib/router";
import { getSession, getKeypair, submitSignedTx } from "../auth/session";
import { normalizeAccount } from "../auth/keys";
import { checkGates, summarizeAccountState } from "../lib/gates";
import { useAccount } from "../context/AccountContext";
import { useTxQueue } from "../hooks/useTxQueue";

function prettyErr(e: any): { msg: string; details: any } {
  const details = e?.data || e?.body || e;
  const msg = details?.message || details?.error?.message || e?.message || "error";
  return { msg, details };
}

type Props = { id: string };

function countFromVotes(votes: any[], choice: string): number {
  return votes.filter((v) => String(v?.choice || "").toLowerCase() === choice).length;
}

function pct(part: number, whole: number): string {
  if (!whole) return "0%";
  return `${Math.round((part / whole) * 100)}%`;
}

function lifecycleSteps(statusRaw: string): Array<{ label: string; state: "done" | "active" | "todo" }> {
  const status = String(statusRaw || "").toLowerCase();
  const labels = ["Draft", "Poll", "Revision", "Validation", "Vote", "Execution"];
  const activeIndexByStatus: Record<string, number> = {
    draft: 0,
    poll: 1,
    polling: 1,
    revision: 2,
    revise: 2,
    validation: 3,
    validate: 3,
    vote: 4,
    voting: 4,
    execution: 5,
    execute: 5,
    executed: 5,
    finalized: 5,
    complete: 5,
    completed: 5,
    withdrawn: 0,
  };
  const active = activeIndexByStatus[status] ?? (status ? 4 : 0);
  return labels.map((label, idx) => ({
    label,
    state: idx < active ? "done" : idx === active ? "active" : "todo",
  }));
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

  const [editTitle, setEditTitle] = useState<string>("");
  const [editBody, setEditBody] = useState<string>("");

  const session = getSession();
  const acct = session ? normalizeAccount(session.account) : null;
  const canSign = acct ? !!getKeypair(acct)?.secretKeyB64 : false;
  const { refresh: refreshAccountContext } = useAccount();
  const tx = useTxQueue();

  async function load(): Promise<void> {
    setErr(null);
    try {
      const [r, vr] = await Promise.all([weall.proposal(id, base), weall.proposalVotes(id, base)]);
      const p = (r as any)?.proposal || r || null;
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
  }, [id]);

  const pid = String(proposal?.proposal_id || proposal?.id || id || "");
  const title = String(proposal?.title || pid || "(proposal)");
  const status = String(proposal?.status || "");

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

      const r = await tx.runTx({
        title: toastTitle,
        pendingMessage: "Submitting governance action…",
        successMessage,
        errorMessage: (e) => prettyErr(e).msg,
        getTxId: (res: any) => res?.result?.tx_id,
        task: async () => {
          const res = await submitSignedTx({
            account: acct!,
            tx_type,
            payload,
            parent: null,
            base,
          });
          return res;
        },
      });

      setAdminRes(r);
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

      const r = await tx.runTx({
        title: "Cast vote",
        pendingMessage: `Submitting ${choice} vote…`,
        successMessage: `Vote recorded: ${choice}.`,
        errorMessage: (e) => prettyErr(e).msg,
        getTxId: (res: any) => res?.result?.tx_id,
        task: async () => {
          const res = await submitSignedTx({
            account: acct!,
            tx_type: "GOV_VOTE_CAST",
            payload: { proposal_id: pid, choice },
            parent: null,
            base,
          });
          return res;
        },
      });

      setVoteRes(r);
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

  const votes = Array.isArray(proposalVotes?.votes) ? proposalVotes.votes : [];
  const yesCount = countFromVotes(votes, "yes");
  const noCount = countFromVotes(votes, "no");
  const abstainCount = countFromVotes(votes, "abstain");
  const totalVotes = votes.length;

  const yesPct = pct(yesCount, totalVotes);
  const noPct = pct(noCount, totalVotes);
  const abstainPct = pct(abstainCount, totalVotes);
  const life = lifecycleSteps(status);
  const accountSummary = acctState ? summarizeAccountState(acctState) : "(state unknown)";

  return (
    <div className="pageStack pageNarrow">
      <section className="card heroCard">
        <div className="cardBody heroBody compactHero">
          <div className="heroSplit">
            <div>
              <div className="eyebrow">Governance</div>
              <h1 className="heroTitle heroTitleSm">{title}</h1>
              <p className="heroText">
                Proposal detail includes the live vote ledger, tally split, and the proposal lifecycle
                so governance pages reflect real state instead of only tx submission results.
              </p>
            </div>
            <div className="heroInfoPanel">
              <div className="heroInfoTitle">Status</div>
              <div className="heroInfoList">
                {status ? <span className="statusPill ok">{status}</span> : null}
                <span className="statusPill">Votes {totalVotes}</span>
                <span className={`statusPill ${gate.ok ? "ok" : ""}`}>
                  {gate.ok ? "Eligible to vote" : "Gated"}
                </span>
                <span className="statusPill">{accountSummary}</span>
              </div>
            </div>
          </div>

          <div className="heroActions">
            <button className="btn" onClick={() => nav("/proposals")}>
              Back to proposals
            </button>
            {gate.ok ? (
              <>
                <button className="btn btnPrimary" onClick={() => void castVote("yes")}>
                  Vote yes
                </button>
                <button className="btn" onClick={() => void castVote("no")}>
                  Vote no
                </button>
                <button className="btn" onClick={() => void castVote("abstain")}>
                  Abstain
                </button>
              </>
            ) : null}
          </div>

          <div className="statsGrid statsGridCompact">
            <div className="statCard">
              <span className="statLabel">YES</span>
              <span className="statValue">{yesCount}</span>
            </div>
            <div className="statCard">
              <span className="statLabel">NO</span>
              <span className="statValue">{noCount}</span>
            </div>
            <div className="statCard">
              <span className="statLabel">ABSTAIN</span>
              <span className="statValue">{abstainCount}</span>
            </div>
          </div>
        </div>
      </section>

      <ErrorBanner message={err?.msg} details={err?.details} onRetry={load} onDismiss={() => setErr(null)} />
      <ErrorBanner message={voteErr?.msg} details={voteErr?.details} onDismiss={() => setVoteErr(null)} />
      <ErrorBanner message={adminErr?.msg} details={adminErr?.details} onDismiss={() => setAdminErr(null)} />

      <section className="card">
        <div className="cardBody formStack">
          <div className="sectionHead">
            <div>
              <div className="eyebrow">Lifecycle</div>
              <h2 className="cardTitle">Proposal path</h2>
            </div>
          </div>

          <div className="statsGrid" style={{ gridTemplateColumns: "repeat(6, minmax(0, 1fr))" }}>
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
        </div>
      </section>

      <section className="grid2">
        <article className="card">
          <div className="cardBody formStack">
            <div className="sectionHead">
              <div>
                <div className="eyebrow">Metadata</div>
                <h2 className="cardTitle">Proposal detail</h2>
              </div>
            </div>

            <div className="feedBodyText">
              {String(proposal?.body || proposal?.description || "No proposal body provided.")}
            </div>

            <div className="progressList">
              <div className="progressRow">
                <span>YES</span>
                <span className="statusPill ok">
                  {yesCount} · {yesPct}
                </span>
              </div>
              <div className="progressRow">
                <span>NO</span>
                <span className="statusPill">
                  {noCount} · {noPct}
                </span>
              </div>
              <div className="progressRow">
                <span>ABSTAIN</span>
                <span className="statusPill">
                  {abstainCount} · {abstainPct}
                </span>
              </div>
            </div>

            <details className="detailsPanel">
              <summary>Raw proposal payload</summary>
              <pre className="codePanel mono">{JSON.stringify(proposal, null, 2)}</pre>
            </details>
          </div>
        </article>

        <article className="card">
          <div className="cardBody formStack">
            <div className="sectionHead">
              <div>
                <div className="eyebrow">Votes</div>
                <h2 className="cardTitle">Per-voter ledger</h2>
              </div>
            </div>

            {votes.length === 0 ? (
              <div className="cardDesc">No votes recorded yet.</div>
            ) : (
              <div className="pageStack">
                {votes.map((v: any, idx: number) => (
                  <div key={`${String(v?.voter || idx)}`} className="feedMediaCard">
                    <div className="feedMediaTitle mono">{String(v?.voter || v?.account || "unknown")}</div>
                    <div className="feedMediaMeta">
                      {String(v?.choice || "unknown")}
                      {v?.ts_ms ? ` • ${new Date(Number(v.ts_ms)).toLocaleString()}` : ""}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </article>
      </section>

      {gate.ok ? (
        <section className="grid2">
          <article className="card">
            <div className="cardBody formStack">
              <div className="sectionHead">
                <div>
                  <div className="eyebrow">Vote actions</div>
                  <h2 className="cardTitle">Cast or revoke</h2>
                </div>
              </div>

              <div className="buttonRow buttonRowWide">
                <button className="btn btnPrimary" onClick={() => void castVote("yes")}>
                  Vote yes
                </button>
                <button className="btn" onClick={() => void castVote("no")}>
                  Vote no
                </button>
                <button className="btn" onClick={() => void castVote("abstain")}>
                  Abstain
                </button>
                <button className="btn" onClick={() => void revokeVote()}>
                  Revoke vote
                </button>
              </div>

              {voteRes ? (
                <details className="detailsPanel">
                  <summary>Last vote result</summary>
                  <pre className="codePanel mono">{JSON.stringify(voteRes, null, 2)}</pre>
                </details>
              ) : null}
            </div>
          </article>

          <article className="card">
            <div className="cardBody formStack">
              <div className="sectionHead">
                <div>
                  <div className="eyebrow">Author controls</div>
                  <h2 className="cardTitle">Edit or withdraw</h2>
                </div>
              </div>

              <label className="fieldLabel">
                Title
                <input value={editTitle} onChange={(e) => setEditTitle(e.target.value)} />
              </label>

              <label className="fieldLabel">
                Body
                <textarea value={editBody} onChange={(e) => setEditBody(e.target.value)} rows={10} />
              </label>

              <div className="buttonRow buttonRowWide">
                <button className="btn btnPrimary" onClick={() => void editProposal()}>
                  Submit edit
                </button>
                <button className="btn" onClick={() => void withdrawProposal()}>
                  Withdraw proposal
                </button>
              </div>

              {adminRes ? (
                <details className="detailsPanel">
                  <summary>Last admin action result</summary>
                  <pre className="codePanel mono">{JSON.stringify(adminRes, null, 2)}</pre>
                </details>
              ) : null}
            </div>
          </article>
        </section>
      ) : null}
    </div>
  );
}
