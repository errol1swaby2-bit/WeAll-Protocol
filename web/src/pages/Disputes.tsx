import React, { useEffect, useMemo, useState } from "react";

import { getApiBaseUrl, weall } from "../api/weall";
import ErrorBanner from "../components/ErrorBanner";
import { getSession } from "../auth/session";
import { normalizeAccount } from "../auth/keys";
import { checkGates, summarizeAccountState } from "../lib/gates";
import { nav } from "../lib/router";
import { useAccount } from "../context/AccountContext";
import { useMutationRefresh } from "../hooks/useMutationRefresh";
import { useSignerSubmissionBusy } from "../hooks/useSignerSubmissionBusy";
import { actionableTxError } from "../lib/txAction";
import { refreshMutationSlices } from "../lib/revalidation";
import {
  disputeAttendancePresent,
  disputeCurrentVote,
  disputeJurorStatus,
  disputeVoteCountSummary,
} from "../lib/disputeSurface";

function prettyErr(e: any): { msg: string; details: any } {
  return actionableTxError(e, "Dispute surface failed to load.");
}

function asArray<T = any>(value: any): T[] {
  return Array.isArray(value) ? value : [];
}


function stageClass(stage: string): string {
  const s = String(stage || "").toLowerCase();
  if (["resolved", "closed", "finalized"].includes(s)) return "statusPill ok";
  if (["open", "review", "voting", "assigned", "juror_review"].includes(s)) return "statusPill";
  return "statusPill";
}

function disputeScopeText(filter: string): string {
  if (filter === "assigned") return "Only disputes where this signer is assigned as a juror are shown.";
  if (filter === "mine") return "Only disputes opened by this account are shown.";
  return "This queue is a browse-and-route surface. Review actions live on dedicated detail and review pages.";
}

function queueNextAction(params: {
  account: string;
  dispute: any;
}): { label: string; hint: string; href: string } {
  const { account, dispute } = params;
  const status = account ? disputeJurorStatus(dispute, account) : "unassigned";
  const present = account ? disputeAttendancePresent(dispute, account) : false;
  const currentVote = account ? disputeCurrentVote(dispute, account) : "";
  const id = encodeURIComponent(String(dispute?.id || ""));

  if (!account) return { label: "Open detail", hint: "Inspect the flagged target and recorded reason.", href: `/disputes/${id}` };
  if (currentVote) return { label: "Open reviewed dispute", hint: `Current signer vote: ${currentVote.toUpperCase()}.`, href: `/disputes/${id}` };
  if ((status === "assigned" || status === "accepted") && present) {
    return { label: "Continue review", hint: "This signer can open the dedicated review workspace and vote once.", href: `/disputes/${id}/review` };
  }
  if (status === "assigned") {
    return { label: "Open detail", hint: "Accept or decline the assignment from the dispute detail page.", href: `/disputes/${id}` };
  }
  if (status === "accepted") {
    return { label: "Open detail", hint: "Attendance should already be present. Refresh detail if review is still locked.", href: `/disputes/${id}` };
  }
  return { label: "Open detail", hint: "Inspect current stage, reason, and juror assignments.", href: `/disputes/${id}` };
}

export default function Disputes(): JSX.Element {
  const apiBase = useMemo(() => getApiBaseUrl(), []);
  const session = getSession();
  const account = session ? normalizeAccount(session.account) : "";
  const { refresh: refreshAccountContext } = useAccount();
  const signerSubmission = useSignerSubmissionBusy(account);

  const [acctState, setAcctState] = useState<any | null>(null);
  const [items, setItems] = useState<any[]>([]);
  const [filter, setFilter] = useState<"all" | "mine" | "assigned">("all");
  const [query, setQuery] = useState("");
  const [err, setErr] = useState<{ msg: string; details: any } | null>(null);
  const [busy, setBusy] = useState(false);

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
      setItems(asArray(disputesRes?.items));
    } catch (e: any) {
      setErr(prettyErr(e));
      setItems([]);
    } finally {
      setBusy(false);
    }
  }

  useEffect(() => { void load(); }, [account]);

  useMutationRefresh({
    entityTypes: ["dispute", "content"],
    account,
    onRefresh: async () => {
      await load();
      await refreshAccount();
      await refreshAccountContext();
    },
  });

  const filtered = useMemo(() => {
    const acct = String(account || "").trim();
    const needle = query.trim().toLowerCase();
    return items.filter((item) => {
      const openedBy = String(item?.opened_by || "");
      const jurorStatus = acct ? disputeJurorStatus(item, acct) : "unassigned";
      if (filter === "mine" && (!acct || openedBy !== acct)) return false;
      if (filter === "assigned" && (!acct || jurorStatus === "unassigned")) return false;
      if (!needle) return true;
      return [
        String(item?.id || ""),
        String(item?.target_type || ""),
        String(item?.target_id || ""),
        String(item?.stage || ""),
        String(item?.reason || ""),
        openedBy,
        jurorStatus,
      ].some((value) => value.toLowerCase().includes(needle));
    });
  }, [account, filter, items, query]);

  const summary = acctState ? summarizeAccountState(acctState) : "(state unknown)";
  const assignedCount = useMemo(() => items.filter((item) => account && disputeJurorStatus(item, account) !== "unassigned").length, [account, items]);
  const openCount = useMemo(() => items.filter((item) => !String(item?.resolved || "")).length, [items]);

  return (
    <div className="pageStack">
      <section className="heroCard compact">
        <div className="heroBody pageStack">
          <div className="surfaceSummaryRow">
            <div>
              <h1 className="heroTitle heroTitleSm">Disputes</h1>
              <p className="heroSubtitle">This hub now behaves as a real queue. It lists visible disputes and routes you into dedicated detail or review surfaces instead of embedding vote controls directly into the queue.</p>
            </div>
            <div className="surfaceSummaryStats">
              <div className="surfaceSummaryStat"><strong className="surfaceSummaryValue">{filtered.length}</strong><span className="surfaceSummaryHint">visible disputes</span></div>
              <div className="surfaceSummaryStat"><strong className="surfaceSummaryValue">{summary}</strong><span className="surfaceSummaryHint">current account standing</span></div>
            </div>
          </div>
          <div className="buttonRow">
            <button className="btn" onClick={() => void refreshMutationSlices(refreshAccount, refreshAccountContext, load)}>{busy ? "Refreshing…" : signerSubmission.busy ? "Waiting for signer…" : "Refresh disputes"}</button>
            <button className="btn" onClick={() => nav("/juror")}>Open juror work</button>
          </div>
        </div>
      </section>

      <section className="surfaceBoundaryBar" aria-label="Dispute queue contract">
        <div className="surfaceBoundaryHeader">
          <div>
            <h2 className="surfaceBoundaryTitle">The queue routes work, but it does not adjudicate inline.</h2>
            <p className="surfaceBoundaryText">
              Detail pages carry flagged content, assignment state, and the next step. Final juror decisions remain in the dedicated review route so dispute work feels formal instead of feed-like.
            </p>
          </div>
          <span className="statusPill">Hub surface</span>
        </div>
        <div className="surfaceBoundaryList">
          <span className="surfaceBoundaryTag">Queue: discover and route</span>
          <span className="surfaceBoundaryTag">Detail: inspect and accept</span>
          <span className="surfaceBoundaryTag">Review route: vote once</span>
        </div>
      </section>

      {!account ? <div className="calloutInfo">Log in with a participant account to inspect personal juror assignments and unlock review routing.</div> : null}
      {signerSubmission.busy ? <div className="calloutInfo">Another signed action is still settling. Queue actions stay read-only while signer nonces are in flight.</div> : null}
      <ErrorBanner message={err?.msg} details={err?.details} onDismiss={() => setErr(null)} onRetry={() => void refreshMutationSlices(refreshAccount, refreshAccountContext, load)} />

      <section className="summaryCardGrid">
        <article className="summaryCard">
          <div className="summaryCardLabel">All visible disputes</div>
          <div className="summaryCardValue">{items.length}</div>
          <div className="summaryCardText">Current backend-visible queue size.</div>
        </article>
        <article className="summaryCard">
          <div className="summaryCardLabel">Open / unresolved</div>
          <div className="summaryCardValue">{openCount}</div>
          <div className="summaryCardText">Resolved cases should leave the active juror workload path.</div>
        </article>
        <article className="summaryCard">
          <div className="summaryCardLabel">Assigned to this signer</div>
          <div className="summaryCardValue">{account ? assignedCount : "—"}</div>
          <div className="summaryCardText">Personalized routing depends on signer-aware dispute state.</div>
        </article>
        <article className="summaryCard">
          <div className="summaryCardLabel">Juror gate</div>
          <div className="summaryCardValue">{tierGate.ok ? "Ready" : "Locked"}</div>
          <div className="summaryCardText">{tierGate.ok ? "Tier and account posture allow juror actions when assigned." : tierGate.reason || "Tier 3 and signer posture still gate juror actions."}</div>
        </article>
      </section>

      <section className="card">
        <div className="cardBody formStack">
          <div className="grid2">
            <label className="fieldLabel">
              Search
              <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search id, target, stage, reason, or opener…" />
            </label>
            <label className="fieldLabel">
              Scope
              <select value={filter} onChange={(e) => setFilter(e.target.value as "all" | "mine" | "assigned")}>
                <option value="all">all visible disputes</option>
                <option value="assigned">assigned to me</option>
                <option value="mine">opened by me</option>
              </select>
            </label>
          </div>
          <div className="cardDesc">{disputeScopeText(filter)}</div>
        </div>
      </section>

      <section className="pageStack">
        {filtered.length === 0 ? (
          <section className="card">
            <div className="cardBody formStack">
              <div className="eyebrow">Queue</div>
              <h2 className="cardTitle">No disputes in this slice</h2>
              <div className="cardDesc">If a content flag already escalated, refresh after the next block and verify the content detail still reflects the moderation transition.</div>
            </div>
          </section>
        ) : filtered.map((item) => {
          const id = String(item?.id || "");
          const status = account ? disputeJurorStatus(item, account) : "unassigned";
          const present = account ? disputeAttendancePresent(item, account) : false;
          const counts = disputeVoteCountSummary(item);
          const next = queueNextAction({ account, dispute: item });
          return (
            <article key={id} className="card">
              <div className="cardBody formStack">
                <div className="sectionHead">
                  <div>
                    <div className="eyebrow">Dispute</div>
                    <h2 className="cardTitle mono">{id}</h2>
                  </div>
                  <div className="statusSummary">
                    <span className={stageClass(String(item?.stage || "open"))}>{String(item?.stage || "open")}</span>
                    <span className={`statusPill ${status !== "unassigned" ? "ok" : ""}`}>{status}</span>
                  </div>
                </div>

                <div className="summaryCardGrid">
                  <article className="summaryCard">
                    <div className="summaryCardLabel">Target</div>
                    <div className="summaryCardValue">{String(item?.target_type || "content")}</div>
                    <div className="summaryCardText mono">{String(item?.target_id || "")}</div>
                  </article>
                  <article className="summaryCard">
                    <div className="summaryCardLabel">Opened by</div>
                    <div className="summaryCardValue mono">{String(item?.opened_by || "—")}</div>
                    <div className="summaryCardText">Queue surfaces should show who triggered the case without forcing detail navigation.</div>
                  </article>
                  <article className="summaryCard">
                    <div className="summaryCardLabel">Votes</div>
                    <div className="summaryCardValue">{counts.total}</div>
                    <div className="summaryCardText">YES {counts.yes} · NO {counts.no} · ABSTAIN {counts.abstain}</div>
                  </article>
                  <article className="summaryCard">
                    <div className="summaryCardLabel">Attendance</div>
                    <div className="summaryCardValue">{present ? "Present" : status === "unassigned" ? "N/A" : "Not yet"}</div>
                    <div className="summaryCardText">Review voting should not unlock until assignment and attendance resolve cleanly.</div>
                  </article>
                </div>

                {item?.reason ? <div className="feedBodyText">{String(item.reason)}</div> : <div className="cardDesc">No dispute reason was recorded on this queue item.</div>}

                <div className="calloutInfo">{next.hint}</div>

                <div className="buttonRow">
                  <button className="btn" onClick={() => nav(`/disputes/${encodeURIComponent(id)}`)}>Open detail</button>
                  <button className="btn btnPrimary" onClick={() => nav(next.href)}>{next.label}</button>
                  {String(item?.target_id || "") ? (
                    <button className="btn" onClick={() => nav(`/content/${encodeURIComponent(String(item?.target_id || ""))}`)}>Open content</button>
                  ) : null}
                </div>
              </div>
            </article>
          );
        })}
      </section>
    </div>
  );
}
