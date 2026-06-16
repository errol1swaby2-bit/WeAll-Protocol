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
import { reportStageLabel, reviewChoiceLabel, reviewStatusLabel, reviewTallyText } from "../lib/userLanguage";
import {
  disputeAttendancePresent,
  disputeCurrentVote,
  disputeJurorStatus,
  disputeVoteCountSummary,
} from "../lib/disputeSurface";

function prettyErr(e: any): { msg: string; details: any } {
  return actionableTxError(e, "Reports failed to load.");
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
  if (filter === "assigned") return "Only reports assigned to you for review are shown.";
  if (filter === "mine") return "Only reports opened by this account are shown.";
  return "This queue is for browsing reports and opening the right detail or review page.";
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

  if (!account) return { label: "Open detail", hint: "Inspect the flagged target and recorded reason.", href: `/reports/${id}` };
  if (currentVote) return { label: "Open reviewed report", hint: `Current recorded choice: ${reviewChoiceLabel(currentVote)}.`, href: `/reports/${id}` };
  if ((status === "assigned" || status === "accepted") && present) {
    return { label: "Continue review", hint: "You can open the dedicated review workspace and choose once.", href: `/reviews/${id}` };
  }
  if (status === "assigned") {
    return { label: "Open detail", hint: "Accept or decline the assignment from the report detail page.", href: `/reports/${id}` };
  }
  if (status === "accepted") {
    return { label: "Open detail", hint: "Review attendance should already be present. Refresh detail if review is still locked.", href: `/reports/${id}` };
  }
  return { label: "Open detail", hint: "Inspect current status, reason, and review assignment.", href: `/reports/${id}` };
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
    requireTier: 2,
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
              <h1 className="heroTitle heroTitleSm">Reports</h1>
              <p className="heroSubtitle">Browse reported content, see what needs attention, and open assigned review work when selected.</p>
            </div>
            <div className="surfaceSummaryStats">
              <div className="surfaceSummaryStat"><strong className="surfaceSummaryValue">{filtered.length}</strong><span className="surfaceSummaryHint">visible reports</span></div>
              <div className="surfaceSummaryStat"><strong className="surfaceSummaryValue">{summary}</strong><span className="surfaceSummaryHint">current account standing</span></div>
            </div>
          </div>
          <div className="buttonRow">
            <button className="btn" onClick={() => void refreshMutationSlices(refreshAccount, refreshAccountContext, load)}>{busy ? "Refreshing…" : signerSubmission.busy ? "Waiting…" : "Refresh reports"}</button>
            <button className="btn" onClick={() => nav("/reviews")}>Open Review Center</button>
          </div>
        </div>
      </section>

      <section className="surfaceBoundaryBar" aria-label="How reports work">
        <div className="surfaceBoundaryHeader">
          <div>
            <h2 className="surfaceBoundaryTitle">Reports move from submission to community review.</h2>
            <p className="surfaceBoundaryText">
              Open a report to read the context. Selected Community Reviewers use the review page to choose what should happen next.
            </p>
          </div>
          <span className="statusPill">Browse</span>
        </div>
        <div className="surfaceBoundaryList">
          <span className="surfaceBoundaryTag">Browse reports</span>
          <span className="surfaceBoundaryTag">Read context</span>
          <span className="surfaceBoundaryTag">Review when selected</span>
        </div>
      </section>

      {!account ? <div className="calloutInfo">Log in to see reports assigned to you and unlock review routing.</div> : null}
      {signerSubmission.busy ? <div className="calloutInfo">Another signed action is still settling. Queue actions stay read-only while the current action finishes.</div> : null}
      <ErrorBanner message={err?.msg} details={err?.details} onDismiss={() => setErr(null)} onRetry={() => void refreshMutationSlices(refreshAccount, refreshAccountContext, load)} />

      <section className="summaryCardGrid">
        <article className="summaryCard">
          <div className="summaryCardLabel">All visible reports</div>
          <div className="summaryCardValue">{items.length}</div>
          <div className="summaryCardText">Current visible queue size.</div>
        </article>
        <article className="summaryCard">
          <div className="summaryCardLabel">Open / unresolved</div>
          <div className="summaryCardValue">{openCount}</div>
          <div className="summaryCardText">Resolved reports should leave the active reviewer workload path.</div>
        </article>
        <article className="summaryCard">
          <div className="summaryCardLabel">Assigned to me</div>
          <div className="summaryCardValue">{account ? assignedCount : "—"}</div>
          <div className="summaryCardText">This shows reports where you may have a review task.</div>
        </article>
        <article className="summaryCard">
          <div className="summaryCardLabel">Reviewer readiness</div>
          <div className="summaryCardValue">{tierGate.ok ? "Ready" : "Locked"}</div>
          <div className="summaryCardText">{tierGate.ok ? "You can review reports when selected." : tierGate.reason || "Complete live verification and keep this device signed in before reviewing reports."}</div>
        </article>
      </section>

      <section className="card">
        <div className="cardBody formStack">
          <div className="grid2">
            <label className="fieldLabel">
              Search
              <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search id, content, status, reason, or reporter…" />
            </label>
            <label className="fieldLabel">
              Scope
              <select value={filter} onChange={(e) => setFilter(e.target.value as "all" | "mine" | "assigned")}>
                <option value="all">all visible reports</option>
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
              <h2 className="cardTitle">No reports in this view</h2>
              <div className="cardDesc">If a report was just submitted, refresh soon and check the content detail for review status.</div>
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
                    <div className="eyebrow">Report</div>
                    <h2 className="cardTitle mono">{id}</h2>
                  </div>
                  <div className="statusSummary">
                    <span className={stageClass(String(item?.stage || "open"))}>{reportStageLabel(item?.stage || "open")}</span>
                    <span className={`statusPill ${status !== "unassigned" ? "ok" : ""}`}>{reviewStatusLabel(status)}</span>
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
                    <div className="summaryCardLabel">Reviews</div>
                    <div className="summaryCardValue">{counts.total}</div>
                    <div className="summaryCardText">{reviewTallyText(counts)}</div>
                  </article>
                  <article className="summaryCard">
                    <div className="summaryCardLabel">Review attendance</div>
                    <div className="summaryCardValue">{present ? "Present" : status === "unassigned" ? "N/A" : "Not yet"}</div>
                    <div className="summaryCardText">Review choices should not unlock until assignment and attendance are clear.</div>
                  </article>
                </div>

                {item?.reason ? <div className="feedBodyText">{String(item.reason)}</div> : <div className="cardDesc">No report reason was recorded on this queue item.</div>}

                <div className="calloutInfo">{next.hint}</div>

                <div className="buttonRow">
                  <button className="btn" onClick={() => nav(`/reports/${encodeURIComponent(id)}`)}>Open detail</button>
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
