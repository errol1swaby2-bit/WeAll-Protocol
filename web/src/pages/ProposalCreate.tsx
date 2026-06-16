import React, { useEffect, useMemo, useState } from "react";

import { getApiBaseUrl } from "../api/weall";
import ErrorBanner from "../components/ErrorBanner";
import RequirementList from "../components/RequirementList";
import ActionLifecycleCard from "../components/ActionLifecycleCard";
import { getKeypair, getSession, submitSignedTx } from "../auth/session";
import { normalizeAccount } from "../auth/keys";
import { useAccount } from "../context/AccountContext";
import { useTxQueue } from "../hooks/useTxQueue";
import { useSignerSubmissionBusy } from "../hooks/useSignerSubmissionBusy";
import { checkGates, summarizeAccountState } from "../lib/gates";
import { canShowAdvancedMode } from "../lib/config";
import { nav, navWithReturn } from "../lib/router";
import { refreshMutationSlices } from "../lib/revalidation";
import { actionableTxError, txPendingKey } from "../lib/txAction";
import { governanceProposalIdOf, reconcileProposalVisible } from "../lib/governance";

function prettyErr(e: any): { msg: string; details: any } {
  return actionableTxError(e, "Decision action failed.");
}

function slugifyProposalPart(value: string): string {
  return value.trim().toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 48);
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
  const payload: any = {
    proposal_id,
    title: input.title.trim() || undefined,
    body: input.body.trim() || undefined,
  };

  const startStage = input.startStage.trim().toLowerCase();
  if (startStage) payload.rules = { start_stage: startStage };

  const actionTxType = input.actionTxType.trim().toUpperCase();
  if (actionTxType) {
    let actionPayload: any = {};
    if (input.actionPayloadJson.trim()) actionPayload = JSON.parse(input.actionPayloadJson);
    payload.actions = [{ tx_type: actionTxType, payload: actionPayload }];
  }

  return payload;
}

export default function ProposalCreate(): JSX.Element {
  const base = useMemo(() => getApiBaseUrl(), []);
  const [acctState, setAcctState] = useState<any | null>(null);
  const [proposalId, setProposalId] = useState("");
  const [title, setTitle] = useState("");
  const [body, setBody] = useState("");
  const [startStage, setStartStage] = useState("poll");
  const [actionTxType, setActionTxType] = useState("");
  const [actionPayloadJson, setActionPayloadJson] = useState("{}");
  const [useAdvancedPayload, setUseAdvancedPayload] = useState(false);
  const [payloadJson, setPayloadJson] = useState(JSON.stringify({ proposal_id: "", title: "", body: "", rules: { start_stage: "poll" } }, null, 2));
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<{ msg: string; details: any } | null>(null);
  const [createRes, setCreateRes] = useState<any>(null);

  const session = getSession();
  const acct = session ? normalizeAccount(session.account) : null;
  const canSign = acct ? !!getKeypair(acct)?.secretKeyB64 : false;
  const tx = useTxQueue();
  const signerSubmission = useSignerSubmissionBusy(acct);
  const { refresh: refreshAccountContext } = useAccount();
  const showAdvancedMode = canShowAdvancedMode();

  const createGate = useMemo(
    () => checkGates({ loggedIn: !!acct, canSign, accountState: acctState, requireTier: 2 }),
    [acct, canSign, acctState],
  );
  const accountSummary = acctState ? summarizeAccountState(acctState) : "(state unknown)";
  const resolvedProposalId = useMemo(() => proposalId.trim() || buildGeneratedProposalId(acct, title, body), [acct, body, proposalId, title]);

  async function loadAccountState(): Promise<void> {
    if (!acct) {
      setAcctState(null);
      return;
    }
    try {
      const response = await fetch(`${base}/v1/accounts/${encodeURIComponent(acct)}`);
      if (!response.ok) throw new Error(`account state ${response.status}`);
      const json: any = await response.json();
      setAcctState(json?.state ?? json?.account?.state ?? json?.account_state ?? null);
    } catch {
      setAcctState(null);
    }
  }

  useEffect(() => {
    void loadAccountState();
  }, [acct, base]);

  async function createProposal(): Promise<void> {
    setErr(null);
    setCreateRes(null);

    if (!acct || !canSign) {
      setErr({
        msg: "You are not logged in on this device.",
        details: "Restore your device signer in Login or Devices & Sessions before creating a decision.",
      });
      return;
    }
    if (!createGate.ok) {
      setErr({ msg: createGate.reason || "gated", details: acctState });
      return;
    }
    if (signerSubmission.busy) {
      setErr({ msg: "Another signed action is still settling for this account.", details: null });
      return;
    }

    setBusy(true);
    try {
      const payload = useAdvancedPayload
        ? JSON.parse(payloadJson)
        : normalizeCreatePayload({ proposalId, title, body, actionTxType, actionPayloadJson, startStage, account: acct });

      await tx.runTx({
        title: "Create community decision",
        pendingKey: txPendingKey(["proposal-create", acct, resolvedProposalId || payload?.proposal_id || title]),
        pendingMessage: "Saving decision…",
        successMessage: "Decision saved. The detail page will open once it is visible.",
        errorMessage: (e) => prettyErr(e)?.msg || "error",
        getTxId: (res: any) => String(res?.tx_id || res?.result?.tx_id || "") || undefined,
        finality: {
          mutation: {
            entityType: "proposal",
            entityId: String(payload?.proposal_id || resolvedProposalId || ""),
            account: acct || undefined,
            routeHint: `/decisions/${encodeURIComponent(String(payload?.proposal_id || resolvedProposalId || ""))}`,
            txType: "GOV_PROPOSAL_CREATE",
          },
          reconcile: async () => reconcileProposalVisible(String(payload?.proposal_id || resolvedProposalId || ""), base),
        },
        task: async () =>
          submitSignedTx({
            account: String(acct || ""),
            tx_type: "GOV_PROPOSAL_CREATE",
            payload,
            parent: null,
            base,
          }),
      });

      setCreateRes(payload);
      await refreshAccountContext();
      nav(`/decisions/${encodeURIComponent(String(governanceProposalIdOf(payload) || payload?.proposal_id || resolvedProposalId || ""))}`);
    } catch (e: any) {
      setErr(prettyErr(e));
      setCreateRes(e?.data || e?.body || null);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="pageStack pageNarrow actionPage proposalCreatePage">
      <section className="card heroCard actionHeroCard">
        <div className="cardBody heroBody compactHero">
          <div className="heroSplit">
            <div>
              <div className="eyebrow">Create decision</div>
              <h1 className="heroTitle heroTitleSm">Create a community decision</h1>
              <p className="heroText">
                Decision creation is separated from the decision queue so browsing and writing do not compete for the same visual space.
              </p>
            </div>

            <div className="heroInfoPanel">
              <div className="heroInfoTitle">Eligibility</div>
              <div className="heroInfoList">
                <span className={`statusPill ${createGate.ok ? "ok" : ""}`}>
                  {createGate.ok ? "Creation unlocked" : "Live verification required"}
                </span>
                <span className="statusPill">{accountSummary}</span>
                <span className="statusPill mono">{acct || "Read-only"}</span>
              </div>
            </div>
          </div>
        </div>
      </section>

      {signerSubmission.busy ? (
        <div className="calloutInfo">
          Another signed action for {acct || "this account"} is still settling. Decision creation waits for that action to finish so submissions stay ordered.
        </div>
      ) : null}

      <ErrorBanner
        message={err?.msg}
        details={err?.details}
        onRetry={() => void refreshMutationSlices(loadAccountState, refreshAccountContext)}
        onDismiss={() => setErr(null)}
      />

      <section className="detailFocusStrip actionFocusStrip">
        <article className="detailFocusCard">
          <div className="detailFocusLabel">Primary object</div>
          <div className="detailFocusValue">Decision composer</div>
          <div className="detailFocusText">Creation is separated from the decision queue so browsing stays structured and calm.</div>
        </article>
        <article className="detailFocusCard">
          <div className="detailFocusLabel">Creation readiness</div>
          <div className="detailFocusValue">{createGate.ok ? "Ready to create" : "live verification required"}</div>
          <div className="detailFocusText">{createGate.ok ? "A signed-in Trusted Verified Person can create a decision from this route." : createGate.reason || "Restore a signed-in Trusted Verified Person account before creating a decision."}</div>
        </article>
        <article className="detailFocusCard">
          <div className="detailFocusLabel">Design rule</div>
          <div className="detailFocusValue">Action route only</div>
          <div className="detailFocusText">Once created, decision inspection and voting return to the dedicated detail page instead of expanding this composer into a queue page.</div>
        </article>
      </section>


      <ActionLifecycleCard intro="This route should always show the same honest sequence: checking, saving, recorded, updating the page, visible, or failed." />

      <section className="card pageNarrow">
        <div className="cardBody formStack">
          <div className="sectionHead">
            <div>
              <div className="eyebrow">Decision</div>
              <h2 className="cardTitle">New community decision</h2>
              <div className="cardDesc">
                This route is intentionally narrow. Queue browsing belongs on the decisions hub, while creation belongs here with clear eligibility and action feedback.
              </div>
            </div>
            <div className="statusSummary">
              <button className="btn" onClick={() => nav("/decisions")}>Back to decisions</button>
            </div>
          </div>

          {!createGate.ok ? (
            <div className="formStack">
              <div className="inlineMessage inlineMessage-neutral">{createGate.reason}</div>
              <RequirementList requirements={createGate.requirements} />
            </div>
          ) : null}

          {!acct || !canSign ? (
            <div className="calloutInfo">
              Decision creation requires an active device session on this browser.
              <button className="btn" style={{ marginLeft: 12 }} onClick={() => navWithReturn(acct ? "/session" : "/login", "/decisions/create")}>
                {acct ? "Open session recovery" : "Open login"}
              </button>
            </div>
          ) : null}

          {showAdvancedMode ? (
            <label className="fieldLabel">
              <input type="checkbox" checked={useAdvancedPayload} onChange={(e) => setUseAdvancedPayload(e.target.checked)} />
              Use advanced decision JSON
            </label>
          ) : null}

          {showAdvancedMode && useAdvancedPayload ? (
            <label className="fieldLabel">
              Decision technical JSON
              <textarea rows={16} value={payloadJson} onChange={(e) => setPayloadJson(e.target.value)} placeholder='{"proposal_id":"proposal:alice:1","title":"Example","body":"Body"}' />
            </label>
          ) : (
            <>
              {showAdvancedMode ? (
                <label className="fieldLabel">
                  Advanced decision id
                  <input value={proposalId} onChange={(e) => setProposalId(e.target.value)} placeholder="Leave blank to auto-generate" />
                  <span className="fieldHint">Resolved id: <span className="mono">{resolvedProposalId}</span></span>
                </label>
              ) : null}

              <label className="fieldLabel">
                Title
                <input value={title} onChange={(e) => setTitle(e.target.value)} placeholder="Decision title" />
              </label>

              <label className="fieldLabel">
                Description
                <textarea value={body} onChange={(e) => setBody(e.target.value)} rows={6} placeholder="Describe what changes if this decision passes." />
              </label>

              <label className="fieldLabel">
                Starting status
                <select value={startStage} onChange={(e) => setStartStage(e.target.value)}>
                  <option value="poll">open for early input</option>
                  <option value="voting">open for voting</option>
                  <option value="revision">being revised</option>
                  <option value="validation">being checked</option>
                  <option value="draft">draft</option>
                </select>
              </label>

              {showAdvancedMode ? (
                <details className="detailsPanel">
                  <summary>View technical action options</summary>
                  <label className="fieldLabel">
                    Technical action type
                    <input value={actionTxType} onChange={(e) => setActionTxType(e.target.value)} placeholder="GOV_RULES_SET, GOV_QUORUM_SET, ..." />
                  </label>

                  <label className="fieldLabel">
                    Technical action JSON
                    <textarea rows={8} value={actionPayloadJson} onChange={(e) => setActionPayloadJson(e.target.value)} placeholder='{"params":{"poh":{"tier2_n_jurors":7}}}' />
                  </label>
                </details>
              ) : null}
            </>
          )}

          {showAdvancedMode ? (
            <div className="feedMediaCard">
              <div className="feedMediaTitle">Advanced decision id preview</div>
              <div className="feedMediaMeta mono">{resolvedProposalId}</div>
            </div>
          ) : null}

          <div className="buttonRow">
            <button className="btn btnPrimary" onClick={() => void createProposal()} disabled={busy || signerSubmission.busy}>
              {busy ? "Saving…" : signerSubmission.busy ? "Waiting…" : "Create decision"}
            </button>
          </div>

          {createRes ? (
            <details className="detailsPanel">
              <summary>View technical saved details</summary>
              <div className="cardDesc mono" style={{ whiteSpace: "pre-wrap" }}>{JSON.stringify(createRes, null, 2)}</div>
            </details>
          ) : null}
        </div>
      </section>
    </div>
  );
}
