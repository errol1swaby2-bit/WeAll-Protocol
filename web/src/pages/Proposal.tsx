import React, { useEffect, useMemo, useState } from "react";
import { getApiBaseUrl, weall } from "../api/weall";
import ErrorBanner from "../components/ErrorBanner";
import { nav } from "../lib/router";
import { getSession, getKeypair, submitSignedTx } from "../auth/session";
import { normalizeAccount } from "../auth/keys";

function prettyErr(e: any): { msg: string; details: any } {
  const details = e?.data || e;
  const msg = details?.message || e?.message || "error";
  return { msg, details };
}

type Props = { id: string };

export default function Proposal({ id }: Props): JSX.Element {
  const base = useMemo(() => getApiBaseUrl(), []);
  const [proposal, setProposal] = useState<any | null>(null);
  const [err, setErr] = useState<{ msg: string; details: any } | null>(null);

  const [voteRes, setVoteRes] = useState<any>(null);
  const [voteErr, setVoteErr] = useState<{ msg: string; details: any } | null>(null);

  const session = getSession();
  const acct = session ? normalizeAccount(session.account) : null;
  const canSign = acct ? !!getKeypair(acct)?.secretKeyB64 : false;

  async function load() {
    setErr(null);
    try {
      const r = await weall.proposal(id, base);
      setProposal((r as any)?.proposal || null);
    } catch (e: any) {
      setErr(prettyErr(e));
      setProposal(null);
    }
  }

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id]);

  async function castVote(choice: "yes" | "no" | "abstain") {
    setVoteErr(null);
    setVoteRes(null);

    try {
      if (!acct) throw new Error("not_logged_in");
      if (!canSign) throw new Error("no_local_secret_key");

      // Note: The exact tx type/payload may evolve; this is the MVP wiring.
      // If your canon uses a different vote tx, this will return a server rejection
      // which will be shown in the UI.
      const payload = {
        proposal_id: String((proposal?.proposal_id || proposal?.id || id) ?? id),
        choice,
      };

      const r = await submitSignedTx({
        account: acct,
        tx_type: "GOV_VOTE_CAST",
        payload,
        parent: null,
        base,
      });

      setVoteRes(r);
      await load();
    } catch (e: any) {
      setVoteErr(prettyErr(e));
      setVoteRes(e?.data || null);
    }
  }

  const pid = String(proposal?.proposal_id || proposal?.id || id || "");
  const title = String(proposal?.title || pid || "(proposal)");
  const status = proposal?.status ? String(proposal.status) : "";

  return (
    <div style={{ maxWidth: 980, margin: "0 auto" }}>
      <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
        <button onClick={() => nav("/proposals")}>← Proposals</button>
        <h2 style={{ margin: 0 }}>Proposal</h2>
        <button onClick={load}>Refresh</button>
        <div style={{ flex: 1 }} />
        <span style={{ opacity: 0.7, fontFamily: "monospace", fontSize: 12 }}>{pid}</span>
      </div>

      <div style={{ marginTop: 10 }}>
        <ErrorBanner message={err?.msg} details={err?.details} onRetry={load} onDismiss={() => setErr(null)} />
      </div>

      {proposal ? (
        <div style={{ background: "#fff", border: "1px solid #ddd", borderRadius: 12, padding: 14, marginTop: 12 }}>
          <div style={{ display: "flex", gap: 10, flexWrap: "wrap", alignItems: "baseline" }}>
            <div style={{ fontWeight: 900, fontSize: 18 }}>{title}</div>
            {status ? <span style={{ opacity: 0.8 }}>• {status}</span> : null}
          </div>

          {proposal?.body ? (
            <div style={{ marginTop: 10, whiteSpace: "pre-wrap" }}>{String(proposal.body)}</div>
          ) : (
            <div style={{ marginTop: 10, opacity: 0.7 }}>(no body)</div>
          )}

          <div style={{ marginTop: 12, display: "grid", gap: 10 }}>
            <div style={{ background: "#fafafa", border: "1px solid #eee", borderRadius: 10, padding: 12 }}>
              <div style={{ fontWeight: 800, marginBottom: 6 }}>Vote (signed tx)</div>

              {!acct ? (
                <div style={{ opacity: 0.75 }}>
                  You’re not logged in. Go to <button onClick={() => nav("/poh")}>PoH</button> to bootstrap keys + session.
                </div>
              ) : !canSign ? (
                <div style={{ opacity: 0.75 }}>
                  Logged in as <b>{acct}</b>, but you have <b>no local secret key</b> for signing. (Recovery-mode session)
                </div>
              ) : (
                <div style={{ opacity: 0.75 }}>
                  Logged in as <b>{acct}</b> — ready to sign.
                </div>
              )}

              <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginTop: 10 }}>
                <button onClick={() => castVote("yes")} disabled={!acct || !canSign}>
                  Vote YES
                </button>
                <button onClick={() => castVote("no")} disabled={!acct || !canSign}>
                  Vote NO
                </button>
                <button onClick={() => castVote("abstain")} disabled={!acct || !canSign}>
                  Abstain
                </button>
              </div>

              <div style={{ marginTop: 10 }}>
                <ErrorBanner message={voteErr?.msg} details={voteErr?.details} onDismiss={() => setVoteErr(null)} />
              </div>

              {voteRes ? (
                <div style={{ marginTop: 10 }}>
                  <div style={{ fontWeight: 700, marginBottom: 6 }}>Result</div>
                  <pre style={{ margin: 0, whiteSpace: "pre-wrap" }}>{JSON.stringify(voteRes, null, 2)}</pre>
                </div>
              ) : null}
            </div>

            <details style={{ background: "#fafafa", border: "1px solid #eee", borderRadius: 10, padding: 12 }}>
              <summary style={{ cursor: "pointer", fontWeight: 800 }}>Raw proposal JSON</summary>
              <pre style={{ marginTop: 10, whiteSpace: "pre-wrap" }}>{JSON.stringify(proposal, null, 2)}</pre>
            </details>
          </div>
        </div>
      ) : (
        <div style={{ marginTop: 14, opacity: 0.75 }}>(proposal not loaded)</div>
      )}
    </div>
  );
}
