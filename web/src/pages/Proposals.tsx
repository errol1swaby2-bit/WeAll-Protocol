import React, { useEffect, useMemo, useState } from "react";

import { getApiBaseUrl, weall } from "../api/weall";
import ErrorBanner from "../components/ErrorBanner";
import { nav } from "../lib/router";
import { getSession, submitSignedTx, getKeypair } from "../auth/session";
import { normalizeAccount } from "../auth/keys";
import { checkGates, summarizeAccountState } from "../lib/gates";
import { useAccount } from "../context/AccountContext";
import { useTxQueue } from "../hooks/useTxQueue";

function prettyErr(e: any): { msg: string; details: any } {
  const details = e?.body || e?.data || e;
  const msg = details?.message || e?.error?.message || e?.message || "error";
  return { msg, details };
}

function proposalIdOf(p: any): string {
  return String(p?.proposal_id || p?.id || "");
}

function proposalTitleOf(p: any): string {
  return String(p?.title || proposalIdOf(p) || "Untitled proposal");
}

function proposalBodyOf(p: any): string {
  return String(p?.body || p?.description || "");
}

function proposalStatusOf(p: any): string {
  return String(p?.status || "unknown");
}

export default function Proposals(): JSX.Element {
  const base = useMemo(() => getApiBaseUrl(), []);
  const [items, setItems] = useState<any[]>([]);
  const [err, setErr] = useState<{ msg: string; details: any } | null>(null);
  const [acctState, setAcctState] = useState<any | null>(null);
  const [query, setQuery] = useState("");

  const [proposalId, setProposalId] = useState<string>("");
  const [title, setTitle] = useState<string>("");
  const [body, setBody] = useState<string>("");

  const [useAdvancedPayload, setUseAdvancedPayload] = useState<boolean>(false);
  const [payloadJson, setPayloadJson] = useState<string>(
    JSON.stringify({ proposal_id: "", title: "", body: "" }, null, 2),
  );

  const [createErr, setCreateErr] = useState<{ msg: string; details: any } | null>(null);
  const [createRes, setCreateRes] = useState<any>(null);

  const [delegateTo, setDelegateTo] = useState<string>("");
  const [delegateEnabled, setDelegateEnabled] = useState<boolean>(true);
  const [delegErr, setDelegErr] = useState<{ msg: string; details: any } | null>(null);
  const [delegRes, setDelegRes] = useState<any>(null);

  const session = getSession();
  const acct = session ? normalizeAccount(session.account) : null;
  const canSign = acct ? !!getKeypair(acct)?.secretKeyB64 : false;
  const { refresh: refreshAccountContext } = useAccount();
  const tx = useTxQueue();

  const gate = checkGates({
    loggedIn: !!acct,
    canSign,
    accountState: acctState,
    requireTier: 2,
  });

  async function load(): Promise<void> {
    setErr(null);
    try {
      const r: any = await weall.proposals({ limit: 50 }, base);
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
  }, []);

  const filtered = useMemo(() => {
    const q = (query || "").trim().toLowerCase();
    if (!q) return items;
    return items.filter((p) => {
      const id = proposalIdOf(p).toLowerCase();
      const t = proposalTitleOf(p).toLowerCase();
      return id.includes(q) || t.includes(q);
    });
  }, [items, query]);

  async function createProposal(): Promise<void> {
    setCreateErr(null);
    setCreateRes(null);

    try {
      if (!gate.ok) throw new Error(gate.reason || "gated");

      let payload: any;

      if (useAdvancedPayload) {
        try {
          payload = JSON.parse(payloadJson || "{}");
        } catch {
          throw new Error("invalid_payload_json");
        }
      } else {
        const pid = proposalId.trim() || `proposal:${acct}:${Date.now()}`;
        if (!proposalId.trim()) setProposalId(pid);
        payload = {
          proposal_id: pid,
          title: title.trim() || undefined,
          body: body.trim() || undefined,
        };
      }

      const r = await tx.runTx({
        title: "Create proposal",
        pendingMessage: "Submitting governance proposal…",
        successMessage: "Proposal submitted successfully.",
        errorMessage: (e) => prettyErr(e).msg,
        getTxId: (res: any) => res?.result?.tx_id,
        task: async () => {
          const res = await submitSignedTx({
            account: acct!,
            tx_type: "GOV_PROPOSAL_CREATE",
            payload,
            parent: null,
            base,
          });
          return res;
        },
      });

      setCreateRes(r);
      await load();
      await loadAccountState();
      await refreshAccountContext();
    } catch (e: any) {
      setCreateErr(prettyErr(e));
      setCreateRes(e?.data || e?.body || null);
    }
  }

  async function setDelegation(): Promise<void> {
    setDelegErr(null);
    setDelegRes(null);

    try {
      if (!gate.ok) throw new Error(gate.reason || "gated");

      const d = delegateTo.trim();
      if (delegateEnabled && !d) throw new Error("missing_delegate");

      const payload = delegateEnabled
        ? { delegatee: normalizeAccount(d) }
        : { delegatee: "" };

      const r = await tx.runTx({
        title: "Update delegation",
        pendingMessage: "Saving governance delegation…",
        successMessage: "Delegation updated.",
        errorMessage: (e) => prettyErr(e).msg,
        getTxId: (res: any) => res?.result?.tx_id,
        task: async () => {
          const res = await submitSignedTx({
            account: acct!,
            tx_type: "GOV_DELEGATION_SET",
            payload,
            parent: null,
            base,
          });
          return res;
        },
      });

      setDelegRes(r);
      await loadAccountState();
      await refreshAccountContext();
    } catch (e: any) {
      setDelegErr(prettyErr(e));
      setDelegRes(e?.data || e?.body || null);
    }
  }

  const accountSummary = acctState ? summarizeAccountState(acctState) : "(state unknown)";

  return (
    <div className="pageStack">
      <section className="card heroCard">
        <div className="cardBody heroBody compactHero">
          <div className="heroSplit">
            <div>
              <div className="eyebrow">Protocol governance</div>
              <h1 className="heroTitle heroTitleSm">Read proposals, then author clear ones</h1>
              <p className="heroText">
                Governance should feel legible. This page keeps discovery, creation, and delegation
                in one place so the process feels structured instead of technical.
              </p>
            </div>

            <div className="heroInfoPanel">
              <div className="heroInfoTitle">Participation rules</div>
              <div className="heroInfoList">
                <span className={`statusPill ${gate.ok ? "ok" : ""}`}>
                  {gate.ok ? "Tier 2 unlocked" : "Tier 2 required"}
                </span>
                <span className="statusPill">{accountSummary}</span>
                <span className="statusPill mono">{acct || "Read-only"}</span>
              </div>
            </div>
          </div>

          <div className="statsGrid statsGridCompact">
            <div className="statCard">
              <span className="statLabel">Visible proposals</span>
              <span className="statValue">{filtered.length}</span>
            </div>
            <div className="statCard">
              <span className="statLabel">Governance access</span>
              <span className="statValue">{gate.ok ? "Ready" : "Locked"}</span>
            </div>
            <div className="statCard">
              <span className="statLabel">Current mode</span>
              <span className="statValue">{acct ? "Participant" : "Read-only"}</span>
            </div>
          </div>
        </div>
      </section>

      <ErrorBanner message={err?.msg} details={err?.details} onRetry={load} onDismiss={() => setErr(null)} />

      <section className="card">
        <div className="cardBody formStack">
          <div className="sectionHead">
            <div>
              <div className="eyebrow">Browse</div>
              <h2 className="cardTitle">Current proposals</h2>
            </div>
            <div className="statusSummary">
              <button className="btn" onClick={() => void load()}>
                Refresh
              </button>
              <button className="btn" onClick={() => nav("/home")}>
                Home
              </button>
            </div>
          </div>

          <label className="fieldLabel">
            Search
            <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search by id or title…" />
          </label>

          <div className="pageStack">
            {filtered.length === 0 ? (
              <div className="cardDesc">No proposals returned yet.</div>
            ) : (
              filtered.map((p) => {
                const id = proposalIdOf(p);
                const titleText = proposalTitleOf(p);
                const bodyText = proposalBodyOf(p);

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
                          <span className="statusPill">{proposalStatusOf(p)}</span>
                        </div>
                      </div>

                      {bodyText ? (
                        <div className="feedBodyText">{bodyText}</div>
                      ) : (
                        <div className="cardDesc">No description provided.</div>
                      )}

                      <div className="buttonRow">
                        <button
                          className="btn"
                          onClick={() => nav(`/proposal/${encodeURIComponent(id)}`)}
                          disabled={!id}
                        >
                          Open proposal
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

      <section className="grid2">
        <article className="card">
          <div className="cardBody formStack">
            <div className="sectionHead">
              <div>
                <div className="eyebrow">Create</div>
                <h2 className="cardTitle">Draft a proposal</h2>
              </div>
              <div className="statusSummary">
                <span className="statusPill">Tx GOV_PROPOSAL_CREATE</span>
              </div>
            </div>

            {!gate.ok ? <div className="inlineError">Gated: {gate.reason}</div> : null}

            <label className="fieldLabel">
              <span style={{ display: "flex", gap: 8, alignItems: "center" }}>
                <input
                  type="checkbox"
                  checked={useAdvancedPayload}
                  onChange={(e) => setUseAdvancedPayload(e.target.checked)}
                />
                Use advanced raw payload JSON
              </span>
            </label>

            {!useAdvancedPayload ? (
              <>
                <label className="fieldLabel">
                  Proposal id
                  <input
                    value={proposalId}
                    onChange={(e) => setProposalId(e.target.value)}
                    placeholder={`proposal:${acct || "@account"}:${Date.now()}`}
                  />
                </label>

                <label className="fieldLabel">
                  Title
                  <input value={title} onChange={(e) => setTitle(e.target.value)} placeholder="Proposal title" />
                </label>

                <label className="fieldLabel">
                  Body
                  <textarea
                    value={body}
                    onChange={(e) => setBody(e.target.value)}
                    rows={8}
                    placeholder="Explain the problem, the change, and the expected impact."
                  />
                </label>
              </>
            ) : (
              <label className="fieldLabel">
                Raw payload JSON
                <textarea
                  value={payloadJson}
                  onChange={(e) => setPayloadJson(e.target.value)}
                  rows={12}
                  className="mono"
                />
              </label>
            )}

            <div className="buttonRow">
              <button className="btn btnPrimary" onClick={() => void createProposal()}>
                Submit proposal
              </button>
            </div>

            <ErrorBanner
              message={createErr?.msg}
              details={createErr?.details}
              onDismiss={() => setCreateErr(null)}
            />

            {createRes ? (
              <details className="detailsPanel">
                <summary>Create result</summary>
                <pre className="codePanel mono">{JSON.stringify(createRes, null, 2)}</pre>
              </details>
            ) : null}
          </div>
        </article>

        <article className="card">
          <div className="cardBody formStack">
            <div className="sectionHead">
              <div>
                <div className="eyebrow">Delegation</div>
                <h2 className="cardTitle">Set your governance delegate</h2>
              </div>
            </div>

            {!gate.ok ? <div className="inlineError">Gated: {gate.reason}</div> : null}

            <label className="fieldLabel">
              <span style={{ display: "flex", gap: 8, alignItems: "center" }}>
                <input
                  type="checkbox"
                  checked={delegateEnabled}
                  onChange={(e) => setDelegateEnabled(e.target.checked)}
                />
                Enable delegation
              </span>
            </label>

            <label className="fieldLabel">
              Delegatee account
              <input
                value={delegateTo}
                onChange={(e) => setDelegateTo(e.target.value)}
                placeholder="@delegate"
                disabled={!delegateEnabled}
              />
            </label>

            <div className="buttonRow">
              <button className="btn btnPrimary" onClick={() => void setDelegation()}>
                Save delegation
              </button>
            </div>

            <ErrorBanner
              message={delegErr?.msg}
              details={delegErr?.details}
              onDismiss={() => setDelegErr(null)}
            />

            {delegRes ? (
              <details className="detailsPanel">
                <summary>Delegation result</summary>
                <pre className="codePanel mono">{JSON.stringify(delegRes, null, 2)}</pre>
              </details>
            ) : null}
          </div>
        </article>
      </section>
    </div>
  );
}
