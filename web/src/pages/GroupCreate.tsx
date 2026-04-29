import React, { useEffect, useMemo, useState } from "react";

import { api, getApiBaseUrl } from "../api/weall";
import ErrorBanner from "../components/ErrorBanner";
import ActionLifecycleCard from "../components/ActionLifecycleCard";
import { getKeypair, getSession, submitSignedTx } from "../auth/session";
import { normalizeAccount } from "../auth/keys";
import { checkGates, summarizeAccountState } from "../lib/gates";
import { nav, navWithReturn } from "../lib/router";
import { useAccount } from "../context/AccountContext";
import { useTxQueue } from "../hooks/useTxQueue";
import { useSignerSubmissionBusy } from "../hooks/useSignerSubmissionBusy";
import { reconcileGroupVisible } from "../lib/groupsRevalidation";
import { refreshMutationSlices } from "../lib/revalidation";
import { actionableTxError, txPendingKey } from "../lib/txAction";

function prettyErr(e: any): { msg: string; details: any } {
  if (!e) return null as any;
  return actionableTxError(e, "Group action failed.");
}

function slugifyGroupId(s: string): string {
  const raw = String(s || "").trim().toLowerCase();
  const slug = raw
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+/, "")
    .replace(/-+$/, "")
    .slice(0, 40);
  return `g:${slug || "group"}`;
}

export default function GroupCreate(): JSX.Element {
  const base = useMemo(() => getApiBaseUrl(), []);
  const [createName, setCreateName] = useState<string>("");
  const [createDesc, setCreateDesc] = useState<string>("");
  const [acctState, setAcctState] = useState<any | null>(null);
  const [busy, setBusy] = useState<boolean>(false);
  const [err, setErr] = useState<{ msg: string; details: any } | null>(null);

  const session = getSession();
  const acct = session ? normalizeAccount(session.account) : null;
  const kp = acct ? getKeypair(acct) : null;
  const canSign = !!kp?.secretKeyB64;
  const tx = useTxQueue();
  const signerSubmission = useSignerSubmissionBusy(acct);
  const { refresh: refreshAccountContext } = useAccount();

  const createGate = useMemo(
    () => checkGates({ loggedIn: !!acct, canSign, accountState: acctState, requireTier: 3 }),
    [acct, canSign, acctState],
  );
  const accountSummary = acctState ? summarizeAccountState(acctState) : "(state unknown)";

  async function loadAccountState(): Promise<void> {
    if (!acct) {
      setAcctState(null);
      return;
    }
    try {
      const r: any = await api.account(acct, base);
      setAcctState(r?.account?.state ?? r?.state ?? r?.account_state ?? null);
    } catch {
      setAcctState(null);
    }
  }

  useEffect(() => {
    void loadAccountState();
  }, [acct, base]);

  async function createGroup(): Promise<void> {
    setErr(null);

    const name = createName.trim();
    const description = createDesc.trim();

    if (!name) {
      setErr({ msg: "Group name is required.", details: null });
      return;
    }
    if (!acct || !canSign) {
      setErr({
        msg: "You are not logged in on this device.",
        details: "Restore your device signer in Settings or PoH first.",
      });
      return;
    }
    if (!createGate.ok) {
      setErr({ msg: createGate.reason || "gated", details: acctState });
      return;
    }

    setBusy(true);
    try {
      const group_id = slugifyGroupId(name);

      await tx.runTx({
        title: "Create group",
        pendingKey: txPendingKey(["group-create", acct, group_id]),
        pendingMessage: "Submitting group creation…",
        successMessage: "Group created.",
        errorMessage: (e) => prettyErr(e).msg,
        getTxId: (res: any) => res?.result?.tx_id,
        finality: {
          timeoutMs: 16000,
          mutation: { entityType: "group", entityId: group_id, account: acct || undefined, routeHint: `/groups/${encodeURIComponent(group_id)}`, txType: "GROUP_CREATE" },
          reconcile: async () => reconcileGroupVisible(group_id, base),
        },
        task: async () =>
          submitSignedTx({
            account: acct,
            tx_type: "GROUP_CREATE",
            payload: {
              group_id,
              charter: description ? `${name}\n\n${description}` : name,
            },
            parent: null,
            base,
          }),
      });

      setCreateName("");
      setCreateDesc("");
      await refreshMutationSlices(refreshAccountContext);
      nav(`/groups/${encodeURIComponent(group_id)}`);
    } catch (e: any) {
      setErr(prettyErr(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="pageStack actionPage groupCreatePage">
      <section className="card heroCard">
        <div className="cardBody heroBody compactHero">
          <div className="heroSplit">
            <div>
              <div className="eyebrow">Create group</div>
              <h1 className="heroTitle heroTitleSm">Start a new group from a dedicated action route</h1>
              <p className="heroText">
                Group creation is a deliberate action. This page keeps the form narrow and focused so the directory route can stay calm and discovery-oriented.
              </p>
            </div>

            <div className="heroInfoPanel">
              <div className="heroInfoTitle">Eligibility</div>
              <div className="heroInfoList">
                <span className={`statusPill ${createGate.ok ? "ok" : ""}`}>
                  {createGate.ok ? "Create unlocked" : "Create requires Tier 3"}
                </span>
                <span className="statusPill">{accountSummary}</span>
                <span className="statusPill mono">{acct || "Read-only"}</span>
              </div>
            </div>
          </div>
        </div>
      </section>

      <section className="surfaceBoundaryBar" aria-label="Group creation route contract">
        <div className="surfaceBoundaryHeader">
          <div>
            <h2 className="surfaceBoundaryTitle">Action route contract</h2>
            <p className="surfaceBoundaryText">
              Group creation is intentionally separated from the groups hub. The center column only carries one deliberate mutation here: define a charter, submit once, and land on the new group detail route.
            </p>
          </div>
          <div className="statusSummary">
            <button className="btn" onClick={() => nav('/groups')}>Return to groups hub</button>
          </div>
        </div>
        <div className="surfaceBoundaryList">
          <span className="surfaceBoundaryTag">Primary object: new group charter</span>
          <span className="surfaceBoundaryTag">Primary action: signed group creation</span>
          <span className="surfaceBoundaryTag">Post-submit route: group detail</span>
        </div>
      </section>

      <section className="detailFocusStrip actionFocusStrip" aria-label="Group creation readiness">
        <article className="detailFocusCard">
          <div className="detailFocusLabel">Eligibility</div>
          <div className="detailFocusValue">{createGate.ok ? "Ready to create" : "Creation gated"}</div>
          <div className="detailFocusText">{createGate.ok ? "Tier and signer prerequisites are satisfied for this action route." : createGate.reason || "A Tier 3 account and local signer are required to create a group."}</div>
        </article>
        <article className="detailFocusCard">
          <div className="detailFocusLabel">Deterministic id preview</div>
          <div className="detailFocusValue mono">{slugifyGroupId(createName || "group")}</div>
          <div className="detailFocusText">The preview stays visible before submission so creation remains deliberate and legible on mobile and desktop.</div>
        </article>
        <article className="detailFocusCard">
          <div className="detailFocusLabel">Completion posture</div>
          <div className="detailFocusValue">Submit once</div>
          <div className="detailFocusText">After the signed transaction settles, this action route should hand off to the new group detail surface rather than keeping you inside a mixed create-and-browse flow.</div>
        </article>
      </section>

      {signerSubmission.busy ? (
        <div className="calloutInfo">
          Another signed action for {acct || "this account"} is still settling. Group creation waits for the signer lane to clear so nonces stay ordered.
        </div>
      ) : null}

      <ErrorBanner
        message={err?.msg}
        details={err?.details}
        onRetry={() => void refreshMutationSlices(loadAccountState, refreshAccountContext)}
        onDismiss={() => setErr(null)}
      />


      <ActionLifecycleCard intro="This route should always show the same honest sequence: validating, submitting, recorded, reconciling, visible confirmed, or failed." />

      <section className="card pageNarrow">
        <div className="cardBody formStack">
          <div className="sectionHead">
            <div>
              <div className="eyebrow">Action</div>
              <h2 className="cardTitle">New group charter</h2>
              <div className="cardDesc">Creating a group is a higher-trust action than requesting membership. The form is separated from the hub so creation and browsing do not compete for attention.</div>
            </div>
            <div className="statusSummary">
              <button className="btn" onClick={() => nav("/groups")}>Back to groups</button>
            </div>
          </div>

          {!createGate.ok ? <div className="inlineError">Gated: {createGate.reason}</div> : null}

          {!acct || !canSign ? (
            <div className="calloutInfo">
              Group creation requires an active device session and local signer.
              <button className="btn" style={{ marginLeft: 12 }} onClick={() => navWithReturn(acct ? "/session" : "/login", "/groups/create")}>
                {acct ? "Open session recovery" : "Open login"}
              </button>
            </div>
          ) : null}

          <label className="fieldLabel">
            Name
            <input value={createName} onChange={(e) => setCreateName(e.target.value)} placeholder="Community builders" />
          </label>

          <label className="fieldLabel">
            Description
            <textarea
              value={createDesc}
              onChange={(e) => setCreateDesc(e.target.value)}
              rows={6}
              placeholder="Describe the purpose and scope of the group."
            />
          </label>

          <div className="feedMediaCard">
            <div className="feedMediaTitle">Preview group id</div>
            <div className="feedMediaMeta mono">{slugifyGroupId(createName || "group")}</div>
          </div>

          <div className="buttonRow">
            <button className="btn btnPrimary" onClick={() => void createGroup()} disabled={busy || signerSubmission.busy}>
              {busy ? "Creating…" : signerSubmission.busy ? "Waiting for signer…" : "Create group"}
            </button>
          </div>
        </div>
      </section>
    </div>
  );
}
