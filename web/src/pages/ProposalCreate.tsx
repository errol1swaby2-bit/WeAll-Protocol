import React, { useEffect, useMemo, useState } from "react";

import { getApiBaseUrl } from "../api/weall";
import ErrorBanner from "../components/ErrorBanner";
import ActionLifecycleCard from "../components/ActionLifecycleCard";
import { getKeypair, getSession, submitSignedTx } from "../auth/session";
import { normalizeAccount } from "../auth/keys";
import { useAccount } from "../context/AccountContext";
import { useTxQueue } from "../hooks/useTxQueue";
import { useSignerSubmissionBusy } from "../hooks/useSignerSubmissionBusy";
import { checkGates, summarizeAccountState } from "../lib/gates";
import { loadSettings } from "../lib/settings";
import { nav, navWithReturn } from "../lib/router";
import { refreshMutationSlices } from "../lib/revalidation";
import { actionableTxError, txPendingKey } from "../lib/txAction";
import { governanceProposalIdOf, reconcileProposalVisible } from "../lib/governance";

function prettyErr(e: any): { msg: string; details: any } {
  return actionableTxError(e, "Governance action failed.");
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
  const showAdvancedMode = loadSettings().showAdvancedMode;

  const createGate = useMemo(
    () => checkGates({ loggedIn: !!acct, canSign, accountState: acctState, requireTier: 3 }),
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
        details: "Restore your device signer in Login or Session devices before authoring a governance proposal.",
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
        title: "Create governance proposal",
        pendingKey: txPendingKey(["proposal-create", acct, resolvedProposalId || payload?.proposal_id || title]),
        pendingMessage: "Submitting proposal…",
        successMessage: "Proposal submitted. The detail route will open once the object is visible.",
        errorMessage: (e) => prettyErr(e)?.msg || "error",
        getTxId: (res: any) => String(res?.tx_id || res?.result?.tx_id || "") || undefined,
        finality: {
          mutation: {
            entityType: "proposal",
            entityId: String(payload?.proposal_id || resolvedProposalId || ""),
            account: acct || undefined,
            routeHint: `/proposal/${encodeURIComponent(String(payload?.proposal_id || resolvedProposalId || ""))}`,
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
      nav(`/proposal/${encodeURIComponent(String(governanceProposalIdOf(payload) || payload?.proposal_id || resolvedProposalId || ""))}`);
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
              <div className="eyebrow">Create proposal</div>
              <h1 className="heroTitle heroTitleSm">Author governance from a dedicated action route</h1>
              <p className="heroText">
                Proposal creation is separated from the governance queue so deliberation and authorship do not compete for the same visual space.
              </p>
            </div>

            <div className="heroInfoPanel">
              <div className="heroInfoTitle">Eligibility</div>
              <div className="heroInfoList">
                <span className={`statusPill ${createGate.ok ? "ok" : ""}`}>
                  {createGate.ok ? "Authoring unlocked" : "Authoring requires Tier 3"}
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
          Another signed action for {acct || "this account"} is still settling. Proposal creation waits for that signer lane to clear so nonces stay ordered.
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
          <div className="detailFocusValue">Proposal composer</div>
          <div className="detailFocusText">Authoring is separated from the governance queue so governance browsing stays structured and non-chaotic.</div>
        </article>
        <article className="detailFocusCard">
          <div className="detailFocusLabel">Authoring posture</div>
          <div className="detailFocusValue">{createGate.ok ? "Ready to create" : "Tier 3 required"}</div>
          <div className="detailFocusText">{createGate.ok ? "A signer-capable Tier 3 account can create a proposal from this route." : createGate.reason || "Restore a signer-capable Tier 3 account before authoring."}</div>
        </article>
        <article className="detailFocusCard">
          <div className="detailFocusLabel">Design rule</div>
          <div className="detailFocusValue">Action route only</div>
          <div className="detailFocusText">Once created, proposal inspection and voting return to the dedicated detail surface instead of expanding this composer into a queue page.</div>
        </article>
      </section>


      <ActionLifecycleCard intro="This route should always show the same honest sequence: validating, submitting, recorded, reconciling, visible confirmed, or failed." />

      <section className="card pageNarrow">
        <div className="cardBody formStack">
          <div className="sectionHead">
            <div>
              <div className="eyebrow">Action</div>
              <h2 className="cardTitle">New governance proposal</h2>
              <div className="cardDesc">
                This route is intentionally narrow. Queue browsing belongs on the proposals hub, while authoring belongs here with explicit gating and transaction feedback.
              </div>
            </div>
            <div className="statusSummary">
              <button className="btn" onClick={() => nav("/proposals")}>Back to proposals</button>
            </div>
          </div>

          {!createGate.ok ? <div className="inlineError">Gated: {createGate.reason}</div> : null}

          {!acct || !canSign ? (
            <div className="calloutInfo">
              Proposal authoring requires an active device session and local signer.
              <button className="btn" style={{ marginLeft: 12 }} onClick={() => navWithReturn(acct ? "/session" : "/login", "/proposals/create")}>
                {acct ? "Open session recovery" : "Open login"}
              </button>
            </div>
          ) : null}

          <label className="fieldLabel">
            <input type="checkbox" checked={useAdvancedPayload} onChange={(e) => setUseAdvancedPayload(e.target.checked)} />
            Use advanced payload JSON
          </label>

          {showAdvancedMode && useAdvancedPayload ? (
            <label className="fieldLabel">
              Proposal payload JSON
              <textarea rows={16} value={payloadJson} onChange={(e) => setPayloadJson(e.target.value)} placeholder='{"proposal_id":"proposal:alice:1","title":"Example","body":"Body"}' />
            </label>
          ) : (
            <>
              <label className="fieldLabel">
                Proposal id
                <input value={proposalId} onChange={(e) => setProposalId(e.target.value)} placeholder="Leave blank to auto-generate" />
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
                  <option value="poll">poll</option>
                  <option value="voting">voting</option>
                  <option value="revision">revision</option>
                  <option value="validation">validation</option>
                  <option value="draft">draft</option>
                </select>
              </label>

              <label className="fieldLabel">
                Optional action tx type
                <input value={actionTxType} onChange={(e) => setActionTxType(e.target.value)} placeholder="GOV_RULES_SET, GOV_QUORUM_SET, ..." />
              </label>

              <label className="fieldLabel">
                Optional action payload JSON
                <textarea rows={8} value={actionPayloadJson} onChange={(e) => setActionPayloadJson(e.target.value)} placeholder='{"params":{"poh":{"tier2_n_jurors":7}}}' />
              </label>
            </>
          )}

          <div className="feedMediaCard">
            <div className="feedMediaTitle">Preview proposal id</div>
            <div className="feedMediaMeta mono">{resolvedProposalId}</div>
          </div>

          <div className="buttonRow">
            <button className="btn btnPrimary" onClick={() => void createProposal()} disabled={busy || signerSubmission.busy}>
              {busy ? "Creating…" : signerSubmission.busy ? "Waiting for signer…" : "Create proposal"}
            </button>
          </div>

          {createRes ? <div className="cardDesc mono" style={{ whiteSpace: "pre-wrap" }}>{JSON.stringify(createRes, null, 2)}</div> : null}
        </div>
      </section>
    </div>
  );
}
