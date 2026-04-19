import React, { useEffect, useMemo, useState } from "react";

import { getApiBaseUrl, weall } from "../api/weall";
import ErrorBanner from "../components/ErrorBanner";
import { getSession, submitSignedTx } from "../auth/session";
import { normalizeAccount } from "../auth/keys";
import { checkGates, summarizeAccountState } from "../lib/gates";
import { nav } from "../lib/router";
import { useAccount } from "../context/AccountContext";
import { useTxQueue } from "../hooks/useTxQueue";
import { useSignerSubmissionBusy } from "../hooks/useSignerSubmissionBusy";
import { reconcileDisputeMutation } from "../lib/disputeRevalidation";
import { refreshMutationSlices } from "../lib/revalidation";
import { actionableTxError, txPendingKey } from "../lib/txAction";

function prettyErr(e: any): { msg: string; details: any } {
  return actionableTxError(e, "Dispute action failed.");
}

function asArray<T = any>(value: any): T[] {
  return Array.isArray(value) ? value : [];
}

function asRecord(value: any): Record<string, any> {
  return value && typeof value === "object" ? value : {};
}


function accountVariants(value: string): string[] {
  const raw = String(value || "").trim();
  if (!raw) return [];
  const normalized = normalizeAccount(raw);
  const base = normalized.startsWith("@") ? normalized.slice(1) : normalized;
  const out = [normalized, base ? `@${base}` : "", base, raw].filter(Boolean);
  return Array.from(new Set(out));
}

function recordForAccount(mapping: any, account: string): Record<string, any> | null {
  const recs = asRecord(mapping);
  for (const variant of accountVariants(account)) {
    const rec = recs[variant];
    if (rec && typeof rec === "object" && !Array.isArray(rec)) return rec as Record<string, any>;
  }
  return null;
}

function fmtNonce(v: any): string {
  const n = Number(v);
  return Number.isFinite(n) && n > 0 ? String(Math.floor(n)) : "—";
}

function jurorStatusOf(dispute: any, account: string): string {
  const rec = recordForAccount(dispute?.jurors, account);
  return String(rec?.status || "unassigned");
}

function jurorAttendancePresent(dispute: any, account: string): boolean {
  const rec = recordForAccount(dispute?.jurors, account);
  return !!asRecord(rec?.attendance).present;
}

function voteCountSummary(dispute: any): { yes: number; no: number; abstain: number; total: number } {
  const votes = asRecord(dispute?.votes);
  let yes = 0;
  let no = 0;
  let abstain = 0;
  for (const key of Object.keys(votes).sort()) {
    const vote = String(votes[key]?.vote || "").trim().toLowerCase();
    if (vote === "yes") yes += 1;
    else if (vote === "no") no += 1;
    else if (vote) abstain += 1;
  }
  return { yes, no, abstain, total: yes + no + abstain };
}

function stageClass(stage: string): string {
  const s = String(stage || "").toLowerCase();
  if (["resolved", "closed", "finalized"].includes(s)) return "statusPill ok";
  if (["open", "review", "voting", "assigned", "juror_review"].includes(s)) return "statusPill";
  return "statusPill";
}

function pageViewReason(account: string): string {
  return account ? "" : "Log in with a participant account to inspect disputes and juror assignments.";
}

function actionReason(params: {
  account: string;
  tierGateOk: boolean;
  tierGateReason: string;
  jurorStatus: string;
  attendancePresent: boolean;
  signerBusy: boolean;
}): string {
  const { account, tierGateOk, tierGateReason, jurorStatus, attendancePresent, signerBusy } = params;
  if (!account) return "Log in to take dispute actions.";
  if (signerBusy) return "Another signed action is still settling for this account.";
  if (!tierGateOk) return tierGateReason || "Tier 3 access and a local signer are required for juror actions.";
  if (jurorStatus === "unassigned") return "This dispute is visible, but your account is not assigned as a juror on it.";
  if (jurorStatus === "declined") return "You declined this juror assignment. No further actions are available from this account.";
  if (jurorStatus === "assigned" && !attendancePresent) return "Accept the assignment before submitting a vote. Acceptance will also mark you present.";
  if (jurorStatus === "accepted" && !attendancePresent) return "Presence should be recorded automatically after acceptance. Refresh if the vote controls do not unlock yet.";
  if ((jurorStatus === "assigned" || jurorStatus === "accepted") && attendancePresent) return "Juror action unlocked. This account may now cast a dispute vote.";
  return "Read-only dispute state.";
}

export default function Disputes(): JSX.Element {
  const apiBase = useMemo(() => getApiBaseUrl(), []);
  const session = getSession();
  const account = session ? normalizeAccount(session.account) : "";
  const { refresh: refreshAccountContext } = useAccount();
  const tx = useTxQueue();
  const signerSubmission = useSignerSubmissionBusy(account);

  const [acctState, setAcctState] = useState<any | null>(null);
  const [items, setItems] = useState<any[]>([]);
  const [selectedId, setSelectedId] = useState<string>("");
  const [selectedDetail, setSelectedDetail] = useState<any | null>(null);
  const [selectedVotes, setSelectedVotes] = useState<any | null>(null);
  const [filter, setFilter] = useState<"all" | "mine" | "assigned">("all");
  const [err, setErr] = useState<{ msg: string; details: any } | null>(null);
  const [result, setResult] = useState<any>(null);
  const [busy, setBusy] = useState(false);
  const [detailBusy, setDetailBusy] = useState(false);

  const tierGate = checkGates({
    loggedIn: !!account,
    canSign: true,
    accountState: acctState,
    requireTier: 3,
  });

  async function refreshAccount(): Promise<void> {
    if (!account) {
      setAcctState(null);
      return;
    }
    try {
      const acct: any = await weall.account(account, apiBase);
      setAcctState(acct?.state ?? null);
    } catch {
      setAcctState(null);
    }
  }

  async function load(): Promise<void> {
    setBusy(true);
    setErr(null);
    try {
      const [disputesRes] = await Promise.all([weall.disputes(apiBase), refreshAccount()]);
      const next = asArray(disputesRes?.items);
      setItems(next);
      if (!selectedId && next.length) setSelectedId(String(next[0]?.id || ""));
      if (selectedId && !next.some((item) => String(item?.id || "") === selectedId)) {
        setSelectedId(String(next[0]?.id || ""));
      }
      if (!next.length) {
        setSelectedDetail(null);
        setSelectedVotes(null);
      }
    } catch (e: any) {
      setErr(prettyErr(e));
      setItems([]);
      setSelectedDetail(null);
      setSelectedVotes(null);
    } finally {
      setBusy(false);
    }
  }

  async function loadSelected(nextId: string): Promise<void> {
    const disputeId = String(nextId || "").trim();
    if (!disputeId) {
      setSelectedDetail(null);
      setSelectedVotes(null);
      return;
    }
    setDetailBusy(true);
    try {
      const [detailRes, votesRes] = await Promise.all([
        weall.dispute(disputeId, apiBase),
        weall.disputeVotes(disputeId, apiBase),
      ]);
      setSelectedDetail((detailRes as any)?.dispute || null);
      setSelectedVotes(votesRes || null);
    } catch (e: any) {
      setErr(prettyErr(e));
      setSelectedDetail(null);
      setSelectedVotes(null);
    } finally {
      setDetailBusy(false);
    }
  }

  useEffect(() => { void load(); }, [account]);
  useEffect(() => { void loadSelected(selectedId); }, [selectedId]);

  const filtered = useMemo(() => {
    const acct = String(account || "").trim();
    return items.filter((item) => {
      const openedBy = String(item?.opened_by || "");
      const jurorStatus = acct ? jurorStatusOf(item, acct) : "unassigned";
      if (filter === "mine") return acct ? openedBy === acct : false;
      if (filter === "assigned") return acct ? jurorStatus !== "unassigned" : false;
      return true;
    });
  }, [account, filter, items]);

  const selectedSummary = useMemo(
    () => filtered.find((item) => String(item?.id || "") === selectedId) || filtered[0] || null,
    [filtered, selectedId],
  );
  const selected = selectedDetail || selectedSummary;
  const selectedJurorStatus = account && selected ? jurorStatusOf(selected, account) : "unassigned";
  const attendancePresent = account && selected ? jurorAttendancePresent(selected, account) : false;
  const counts = selectedVotes?.vote_counts || (selected ? voteCountSummary(selected) : { yes: 0, no: 0, abstain: 0, total: 0 });
  const currentVote = selected && account ? String(asRecord(selected?.votes)?.[account]?.vote || "").trim().toLowerCase() : "";
  const canAccept = !!selected && !!account && !signerSubmission.busy && tierGate.ok && selectedJurorStatus === "assigned";
  const canDecline = !!selected && !!account && !signerSubmission.busy && tierGate.ok && selectedJurorStatus === "assigned";
  const canAttend = !!selected && !!account && !signerSubmission.busy && tierGate.ok && false;
  const canVote = !!selected && !!account && !signerSubmission.busy && tierGate.ok && (selectedJurorStatus === "assigned" || selectedJurorStatus === "accepted") && attendancePresent && !currentVote;
  const summary = acctState ? summarizeAccountState(acctState) : "(state unknown)";
  const pageReason = pageViewReason(account);
  const actionHint = actionReason({
    account,
    tierGateOk: tierGate.ok,
    tierGateReason: tierGate.reason || "",
    jurorStatus: selectedJurorStatus,
    attendancePresent,
    signerBusy: signerSubmission.busy,
  });

  async function submitDisputeTx(txType: string, payload: any, title: string, successMessage: string): Promise<void> {
    if (!account) throw new Error("not_logged_in");
    if (signerSubmission.busy) throw new Error("Another signed action is still settling for this juror account.");
    const res = await tx.runTx({
      title,
      pendingKey: txPendingKey(["dispute", txType, String(payload?.dispute_id || selectedId || ""), account]),
      pendingMessage: "Submitting dispute action…",
      successMessage,
      errorMessage: (e) => prettyErr(e).msg,
      getTxId: (raw: any) => raw?.tx_id,
      task: () => submitSignedTx({ account, tx_type: txType, payload, base: apiBase }),
      finality: {
        track: true,
        timeoutMs: 18000,
        reconcile: async () =>
          reconcileDisputeMutation({
            disputeId: String(payload?.dispute_id || selectedId || ""),
            account,
            txType: txType as any,
            vote: payload?.vote || null,
            base: apiBase,
          }),
      },
    });
    setResult(res);
    await refreshMutationSlices(
      refreshAccount,
      refreshAccountContext,
      load,
      async () => loadSelected(String(payload?.dispute_id || selectedId || "")),
    );
  }

  return (
    <div className="pageStack">
      <section className="heroCard compact">
        <div className="heroBody pageStack">
          <div className="surfaceSummaryRow">
            <div>
              <h1 className="heroTitle heroTitleSm">Disputes</h1>
              <p className="heroSubtitle">Review moderation-related disputes, inspect assigned jurors, and cast juror actions from a dedicated dispute surface instead of burying them in content detail.</p>
            </div>
            <div className="surfaceSummaryStats">
              <div className="surfaceSummaryStat"><strong className="surfaceSummaryValue">{filtered.length}</strong><span className="surfaceSummaryHint">visible disputes</span></div>
              <div className="surfaceSummaryStat"><strong className="surfaceSummaryValue">{summary}</strong><span className="surfaceSummaryHint">current account standing</span></div>
            </div>
          </div>
          <div className="buttonRow">
            <button className="btn" onClick={() => void load()}>{busy ? "Refreshing…" : signerSubmission.busy ? "Waiting for signer…" : "Refresh disputes"}</button>
            <button className="btn" onClick={() => nav("/juror")}>Open juror work</button>
          </div>
        </div>
      </section>

      {pageReason ? <div className="calloutInfo">{pageReason}</div> : null}
      {signerSubmission.busy ? <div className="calloutInfo">Another signed action is still settling. Dispute juror actions are serialized so signer nonces remain monotonic.</div> : null}
      <ErrorBanner message={err?.msg} details={err?.details} onDismiss={() => setErr(null)} onRetry={() => void load()} />

      <section className="card">
        <div className="cardBody formStack">
          <div className="buttonRow">
            <label className="fieldLabel">Scope
              <select value={filter} onChange={(e) => setFilter(e.target.value as "all" | "mine" | "assigned")}>
                <option value="all">all disputes</option>
                <option value="assigned">assigned to me</option>
                <option value="mine">opened by me</option>
              </select>
            </label>
          </div>
        </div>
      </section>

      <div className="twoColumnLayout">
        <section className="card">
          <div className="cardBody formStack">
            <div className="sectionHead"><div><div className="eyebrow">Queue</div><h2 className="cardTitle">Dispute list</h2></div><div className="statusSummary"><span className={`statusPill ${filtered.length ? "ok" : ""}`}>{filtered.length} item(s)</span></div></div>
            {filtered.length === 0 ? <div className="cardDesc">No disputes are visible yet. If a flag already escalated, refresh after the next block or review the content target again.</div> : filtered.map((item) => {
              const id = String(item?.id || "");
              const jurorStatus = account ? jurorStatusOf(item, account) : "unassigned";
              const active = selected && String(selected?.id || "") === id;
              return (
                <div key={id} className={`sidebarNavItem ${active ? "active" : ""}`}>
                  <button className="sidebarNavLead" style={{ background: "transparent", border: 0, padding: 0, width: "100%", textAlign: "left" }} onClick={() => nav(`/disputes/${encodeURIComponent(id)}`)}>
                    <span className="sidebarNavText"><span className="sidebarNavLabel mono">{id}</span><span className="sidebarNavHint">{String(item?.target_type || "target")} · {String(item?.target_id || "")}</span></span>
                  </button>
                  <span className="sidebarNavArrow">{jurorStatus === "unassigned" ? String(item?.stage || "open") : jurorStatus}</span>
                </div>
              );
            })}
          </div>
        </section>

        <section className="card">
          <div className="cardBody formStack">
            {!selected ? <div className="cardDesc">Choose a dispute to inspect it.</div> : <>
              <div className="sectionHead"><div><div className="eyebrow">Dispute</div><h2 className="cardTitle mono">{String(selected?.id || "")}</h2></div><div className="statusSummary"><span className={stageClass(String(selected?.stage || "open"))}>{detailBusy ? "refreshing…" : String(selected?.stage || "open")}</span>{selected?.resolved ? <span className="statusPill ok">resolved</span> : null}</div></div>
              <div className="summaryCardGrid">
                <article className="summaryCard"><div className="summaryCardLabel">Target</div><div className="summaryCardValue">{String(selected?.target_type || "target")}</div><div className="summaryCardText mono">{String(selected?.target_id || "")}</div></article>
                <article className="summaryCard"><div className="summaryCardLabel">Opened by</div><div className="summaryCardValue mono">{String(selected?.opened_by || "—")}</div><div className="summaryCardText">nonce {fmtNonce(selected?.opened_at_nonce)}</div></article>
                <article className="summaryCard"><div className="summaryCardLabel">Your juror status</div><div className="summaryCardValue">{selectedJurorStatus}</div><div className="summaryCardText">{attendancePresent ? "Attendance recorded." : "Assignment and attendance determine which juror actions unlock."}</div></article>
                <article className="summaryCard"><div className="summaryCardLabel">Votes</div><div className="summaryCardValue">{counts.total}</div><div className="summaryCardText">YES {counts.yes} · NO {counts.no} · ABSTAIN {counts.abstain}</div></article>
              </div>
              {selected?.reason ? <div className="feedBodyText">{String(selected.reason)}</div> : <div className="cardDesc">No dispute reason was recorded.</div>}

              <div className="calloutInfo">{currentVote ? `Current signer vote: ${currentVote.toUpperCase()}. Open the dedicated review page to inspect the flagged content.` : actionHint}</div>

              <div className="infoCard">
                <div className="feedMediaTitle">Assigned jurors</div>
                <div className="milestoneList">{Object.entries(asRecord(selected?.jurors)).sort((a, b) => String(a[0]).localeCompare(String(b[0]))).map(([juror, rec]) => <span key={juror} className="miniTag">{juror}: {String((rec as any)?.status || "assigned")}{asRecord((rec as any)?.attendance).present ? " · present" : ""}</span>)}</div>
              </div>

              <div className="buttonRow">
                <button className="btn btnPrimary" onClick={() => nav(`/disputes/${encodeURIComponent(String(selected.id || ""))}`)}>Open dedicated review page</button>
              </div>

              <div className="buttonRow buttonRowWide">
                <button className="btn" onClick={() => void submitDisputeTx("DISPUTE_JUROR_ACCEPT", { dispute_id: selected.id }, "Accept dispute", "Dispute accepted.")} disabled={!canAccept}>{signerSubmission.busy ? "Waiting…" : "Accept"}</button>
                <button className="btn" onClick={() => void submitDisputeTx("DISPUTE_JUROR_DECLINE", { dispute_id: selected.id }, "Decline dispute", "Dispute declined.")} disabled={!canDecline}>{signerSubmission.busy ? "Waiting…" : "Decline"}</button>
                <button className="btn" onClick={() => void submitDisputeTx("DISPUTE_JUROR_ATTENDANCE", { dispute_id: selected.id, present: true }, "Mark present", "Attendance recorded.")} disabled={!canAttend}>{signerSubmission.busy ? "Waiting…" : attendancePresent ? "Present" : "Mark present"}</button>
                <button className="btn btnPrimary" onClick={() => void submitDisputeTx("DISPUTE_VOTE_SUBMIT", { dispute_id: selected.id, vote: "yes" }, "Vote yes", "YES vote submitted.")} disabled={!canVote}>{signerSubmission.busy ? "Waiting…" : "Vote yes"}</button>
                <button className="btn" onClick={() => void submitDisputeTx("DISPUTE_VOTE_SUBMIT", { dispute_id: selected.id, vote: "no" }, "Vote no", "NO vote submitted.")} disabled={!canVote}>{signerSubmission.busy ? "Waiting…" : "Vote no"}</button>
                <button className="btn" onClick={() => void submitDisputeTx("DISPUTE_VOTE_SUBMIT", { dispute_id: selected.id, vote: "abstain" }, "Vote abstain", "Abstain vote submitted.")} disabled={!canVote}>{signerSubmission.busy ? "Waiting…" : "Vote abstain"}</button>
              </div>

              <details className="detailsPanel"><summary>Raw dispute detail</summary><pre className="codePanel mono">{JSON.stringify(selected, null, 2)}</pre></details>
            </>}
          </div>
        </section>
      </div>

      {result ? <section className="card"><div className="cardBody formStack"><div className="eyebrow">Last action</div><pre className="codePanel mono">{JSON.stringify(result, null, 2)}</pre></div></section> : null}
    </div>
  );
}
