import React, { useEffect, useMemo, useState } from "react";

import { getApiBaseUrl, weall } from "../api/weall";
import ErrorBanner from "../components/ErrorBanner";
import MediaGallery from "../components/MediaGallery";
import { getAuthHeaders, getSession, submitSignedTx } from "../auth/session";
import { normalizeAccount } from "../auth/keys";
import { checkGates, summarizeAccountState } from "../lib/gates";
import { nav } from "../lib/router";
import { useAccount } from "../context/AccountContext";
import { useTxQueue } from "../hooks/useTxQueue";

function prettyErr(e: any): { msg: string; details: any } {
  const details = e?.body || e?.data || e;
  const msg = details?.message || e?.error?.message || e?.message || "error";
  return { msg, details };
}

function fmtTs(v: any): string {
  const n = Number(v);
  if (!Number.isFinite(n) || n <= 0) return "—";
  try {
    return new Date(n).toLocaleString();
  } catch {
    return String(v);
  }
}

function extractEvidenceMedia(evidence: any): any[] {
  if (!evidence || typeof evidence !== "object") return [];
  const out: any[] = [];

  const pushCid = (cid: string, kind = "file") => {
    const c = String(cid || "").trim();
    if (!c) return;
    out.push({ cid: c, kind, name: c });
  };

  if (typeof evidence.video_cid === "string") pushCid(evidence.video_cid, "video");
  if (typeof evidence.cid === "string") pushCid(evidence.cid, "file");

  if (Array.isArray(evidence.media)) {
    for (const item of evidence.media) out.push(item);
  }

  return out;
}

function statusTone(statusRaw: any): "done" | "active" | "todo" {
  const s = String(statusRaw || "").toLowerCase();
  if (["complete", "completed", "finalized", "approved", "passed", "closed"].includes(s)) {
    return "done";
  }
  if (["open", "pending", "assigned", "accepted", "scheduled", "review", "in_progress"].includes(s)) {
    return "active";
  }
  return "todo";
}

function SectionCard({
  eyebrow,
  title,
  children,
  right,
}: {
  eyebrow: string;
  title: string;
  children: React.ReactNode;
  right?: React.ReactNode;
}): JSX.Element {
  return (
    <article className="card">
      <div className="cardBody formStack">
        <div className="sectionHead">
          <div>
            <div className="eyebrow">{eyebrow}</div>
            <h2 className="cardTitle">{title}</h2>
          </div>
          {right}
        </div>
        {children}
      </div>
    </article>
  );
}

export default function JurorDashboard(): JSX.Element {
  const apiBase = useMemo(() => getApiBaseUrl(), []);
  const session = getSession();
  const account = session ? normalizeAccount(session.account) : "";
  const { refresh: refreshAccountContext } = useAccount();
  const tx = useTxQueue();

  const [acctState, setAcctState] = useState<any | null>(null);
  const [tier2Cases, setTier2Cases] = useState<any[]>([]);
  const [tier3Cases, setTier3Cases] = useState<any[]>([]);
  const [tier3Sessions, setTier3Sessions] = useState<any[]>([]);
  const [expanded, setExpanded] = useState<Record<string, any>>({});
  const [participants, setParticipants] = useState<Record<string, any[]>>({});
  const [tab, setTab] = useState<"tier2" | "tier3">("tier2");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<{ msg: string; details: any } | null>(null);
  const [result, setResult] = useState<any | null>(null);

  const gate = checkGates({
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

  async function loadQueues(): Promise<void> {
    if (!account) return;

    setBusy(true);
    setErr(null);

    try {
      const headers = getAuthHeaders(account);
      const [t2, t3, sess] = await Promise.all([
        weall.pohTier2JurorCases(account, apiBase, headers).catch(() => ({ cases: [] })),
        weall.pohTier3Assigned(account, apiBase, headers).catch(() => ({ cases: [] })),
        weall.pohTier3Sessions(apiBase, headers).catch(() => ({ sessions: [] })),
        refreshAccount(),
      ]);

      setTier2Cases(Array.isArray(t2?.cases) ? t2.cases : []);
      setTier3Cases(Array.isArray(t3?.cases) ? t3.cases : []);
      setTier3Sessions(Array.isArray(sess?.sessions) ? sess.sessions : []);
    } catch (e: any) {
      setErr(prettyErr(e));
    } finally {
      setBusy(false);
    }
  }

  async function loadCase(kind: "tier2" | "tier3", caseId: string): Promise<void> {
    if (!account || !caseId) return;

    setBusy(true);
    setErr(null);

    try {
      const headers = getAuthHeaders(account);
      const detail =
        kind === "tier2"
          ? await weall.pohTier2Case(caseId, apiBase, headers)
          : await weall.pohTier3Case(caseId, apiBase, headers);

      setExpanded((prev) => ({ ...prev, [caseId]: detail }));

      if (kind === "tier3") {
        const sessionRec = sessionForCase(caseId);
        const sessionId = String(sessionRec?.session_id || "");
        if (sessionId) {
          const partRes = await weall
            .pohTier3SessionParticipants(sessionId, apiBase, headers)
            .catch(() => ({ participants: [] }));
          setParticipants((prev) => ({
            ...prev,
            [sessionId]: Array.isArray(partRes?.participants) ? partRes.participants : [],
          }));
        }
      }
    } catch (e: any) {
      setErr(prettyErr(e));
    } finally {
      setBusy(false);
    }
  }

  function sessionForCase(caseId: string): any | null {
    for (const s of tier3Sessions) {
      if (String(s?.case_id || "") === String(caseId)) return s;
    }
    return null;
  }

  async function submitSkeletonTx(
    skel: any,
    title: string,
    successMessage: string,
  ): Promise<void> {
    if (!account) throw new Error("not_logged_in");
    if (!skel?.tx) throw new Error("invalid_tx_skeleton");

    const r = await tx.runTx({
      title,
      pendingMessage: "Submitting juror action…",
      successMessage,
      errorMessage: (e) => prettyErr(e).msg,
      getTxId: (res: any) => res?.result?.tx_id,
      task: async () => {
        const txSkel = skel.tx;
        const payload = { ...(txSkel.payload || {}) };

        if (typeof payload.ts_ms === "number" && payload.ts_ms === 0) {
          payload.ts_ms = Date.now();
        }

        const res = await submitSignedTx({
          account,
          tx_type: String(txSkel.tx_type || ""),
          payload,
          parent: txSkel.parent ?? null,
          base: apiBase,
        });

        return res;
      },
    });

    setResult(r);
    await refreshAccount();
    await refreshAccountContext();
    await loadQueues();
  }

  async function tier2Accept(caseId: string): Promise<void> {
    const headers = getAuthHeaders(account);
    const skel = await weall.pohTier2TxJurorAccept({ case_id: caseId }, apiBase, headers);
    await submitSkeletonTx(skel, "Accept Tier 2 case", "Tier 2 case accepted.");
  }

  async function tier2Decline(caseId: string): Promise<void> {
    const headers = getAuthHeaders(account);
    const skel = await weall.pohTier2TxJurorDecline({ case_id: caseId }, apiBase, headers);
    await submitSkeletonTx(skel, "Decline Tier 2 case", "Tier 2 case declined.");
  }

  async function tier2Review(caseId: string, verdict: "pass" | "fail"): Promise<void> {
    const note = window.prompt("Optional note", "") || "";
    const headers = getAuthHeaders(account);
    const body: any = { case_id: caseId, verdict };
    if (note.trim()) body.note = note.trim();
    const skel = await weall.pohTier2TxReview(body, apiBase, headers);
    await submitSkeletonTx(
      skel,
      "Submit Tier 2 verdict",
      verdict === "pass" ? "Tier 2 case passed." : "Tier 2 case failed.",
    );
  }

  async function tier3Accept(caseId: string): Promise<void> {
    const headers = getAuthHeaders(account);
    const skel = await weall.pohTier3TxJurorAccept({ case_id: caseId }, apiBase, headers);
    await submitSkeletonTx(skel, "Accept Tier 3 case", "Tier 3 case accepted.");
  }

  async function tier3Decline(caseId: string): Promise<void> {
    const headers = getAuthHeaders(account);
    const skel = await weall.pohTier3TxJurorDecline({ case_id: caseId }, apiBase, headers);
    await submitSkeletonTx(skel, "Decline Tier 3 case", "Tier 3 case declined.");
  }

  async function tier3Attendance(caseId: string, attended: boolean): Promise<void> {
    const headers = getAuthHeaders(account);
    const skel = await weall.pohTier3TxAttendance(
      { case_id: caseId, juror_id: account, attended },
      apiBase,
      headers,
    );
    await submitSkeletonTx(
      skel,
      "Record Tier 3 attendance",
      attended ? "Attendance marked present." : "Attendance marked absent.",
    );
  }

  async function tier3Verdict(caseId: string, verdict: "pass" | "fail"): Promise<void> {
    const note = window.prompt("Optional verdict note", "") || "";
    const headers = getAuthHeaders(account);
    const body: any = { case_id: caseId, verdict };
    if (note.trim()) body.note = note.trim();
    const skel = await weall.pohTier3TxVerdict(body, apiBase, headers);
    await submitSkeletonTx(
      skel,
      "Submit Tier 3 verdict",
      verdict === "pass" ? "Tier 3 case passed." : "Tier 3 case failed.",
    );
  }

  useEffect(() => {
    void loadQueues();
  }, [account]);

  const tier = Number(acctState?.poh_tier ?? 0);
  const accountSummary = acctState ? summarizeAccountState(acctState) : "(state unknown)";
  const showing = tab === "tier2" ? tier2Cases : tier3Cases;

  return (
    <div className="pageStack">
      <section className="card heroCard">
        <div className="cardBody heroBody compactHero">
          <div className="heroSplit">
            <div>
              <div className="eyebrow">Juror workspace</div>
              <h1 className="heroTitle heroTitleSm">Review assigned human verification work</h1>
              <p className="heroText">
                This page keeps Tier 2 evidence review and Tier 3 live-session follow-through in one
                place so juror work feels operational instead of hidden behind raw endpoints.
              </p>
            </div>

            <div className="heroInfoPanel">
              <div className="heroInfoTitle">Juror readiness</div>
              <div className="heroInfoList">
                <span className={`statusPill ${account ? "ok" : ""}`}>
                  {account ? "Session present" : "No session"}
                </span>
                <span className={`statusPill ${tier >= 3 ? "ok" : ""}`}>
                  Tier {tier}
                </span>
                <span className={`statusPill ${gate.ok ? "ok" : ""}`}>
                  {gate.ok ? "Juror-ready" : "Gated"}
                </span>
                <span className="statusPill">{accountSummary}</span>
              </div>
            </div>
          </div>

          <div className="heroActions">
            <button className={`btn ${tab === "tier2" ? "btnPrimary" : ""}`} onClick={() => setTab("tier2")}>
              Tier 2 cases
            </button>
            <button className={`btn ${tab === "tier3" ? "btnPrimary" : ""}`} onClick={() => setTab("tier3")}>
              Tier 3 live cases
            </button>
            <button className="btn" onClick={() => void loadQueues()} disabled={busy || !account}>
              {busy ? "Refreshing…" : "Refresh"}
            </button>
            <button className="btn" onClick={() => nav("/poh")}>
              Open PoH
            </button>
          </div>
        </div>
      </section>

      <ErrorBanner
        message={err?.msg}
        details={err?.details}
        onRetry={() => void loadQueues()}
        onDismiss={() => setErr(null)}
      />

      {!account ? (
        <div className="card">
          <div className="cardBody formStack">
            <div className="emptyPanel">
              <strong>No local session is active.</strong>
              <span>Restore your session in Settings or PoH before using juror actions.</span>
              <div className="buttonRow">
                <button className="btn btnPrimary" onClick={() => nav("/settings")}>
                  Open settings
                </button>
              </div>
            </div>
          </div>
        </div>
      ) : null}

      {!gate.ok && account ? (
        <div className="card">
          <div className="cardBody formStack">
            <div className="emptyPanel">
              <strong>Juror actions are gated.</strong>
              <span>{gate.reason}</span>
            </div>
          </div>
        </div>
      ) : null}

      <SectionCard
        eyebrow={tab === "tier2" ? "Tier 2" : "Tier 3"}
        title={tab === "tier2" ? "Assigned evidence reviews" : "Assigned live-session cases"}
        right={<span className={`statusPill ${showing.length ? "ok" : ""}`}>{showing.length} case(s)</span>}
      >
        {showing.length === 0 ? (
          <div className="cardDesc">No assigned cases right now.</div>
        ) : (
          <div className="pageStack">
            {showing.map((c) => {
              const caseId = String(c?.case_id || c?.id || "");
              const detail = expanded[caseId]?.case || expanded[caseId] || null;
              const evidence = detail?.evidence || c?.evidence || {};
              const evidenceMedia = extractEvidenceMedia(evidence);
              const sessionRec = tab === "tier3" ? sessionForCase(caseId) : null;
              const sessionId = String(sessionRec?.session_id || "");
              const sessionParticipants = sessionId ? participants[sessionId] || [] : [];

              return (
                <article key={caseId || Math.random()} className="card">
                  <div className="cardBody formStack">
                    <div className="sectionHead">
                      <div>
                        <div className="eyebrow">Case</div>
                        <h3 className="cardTitle">{caseId || "(missing case id)"}</h3>
                      </div>
                      <div className="statusSummary">
                        <span className={`statusPill ${statusTone(c?.status) === "done" ? "ok" : ""}`}>
                          {String(c?.status || "unknown")}
                        </span>
                        {c?.outcome ? <span className="statusPill">{String(c.outcome)}</span> : null}
                      </div>
                    </div>

                    <div className="statsGrid statsGridCompact">
                      <div className="statCard">
                        <span className="statLabel">Applicant</span>
                        <span className="statValue mono">{String(c?.account_id || c?.applicant || "—")}</span>
                      </div>
                      <div className="statCard">
                        <span className="statLabel">Opened</span>
                        <span className="statValue">{fmtTs(c?.created_ts_ms || c?.init_ts_ms)}</span>
                      </div>
                      <div className="statCard">
                        <span className="statLabel">Finalized</span>
                        <span className="statValue">{fmtTs(c?.finalized_ts_ms)}</span>
                      </div>
                    </div>

                    {tab === "tier2" ? (
                      <div className="buttonRow buttonRowWide">
                        <button className="btn" onClick={() => void loadCase("tier2", caseId)} disabled={busy || !caseId}>
                          Load details
                        </button>
                        <button className="btn" onClick={() => void tier2Accept(caseId)} disabled={busy || !gate.ok}>
                          Accept
                        </button>
                        <button className="btn" onClick={() => void tier2Decline(caseId)} disabled={busy || !gate.ok}>
                          Decline
                        </button>
                        <button className="btn btnPrimary" onClick={() => void tier2Review(caseId, "pass")} disabled={busy || !gate.ok}>
                          Pass
                        </button>
                        <button className="btn" onClick={() => void tier2Review(caseId, "fail")} disabled={busy || !gate.ok}>
                          Fail
                        </button>
                      </div>
                    ) : (
                      <div className="buttonRow buttonRowWide">
                        <button className="btn" onClick={() => void loadCase("tier3", caseId)} disabled={busy || !caseId}>
                          Load details
                        </button>
                        <button className="btn" onClick={() => void tier3Accept(caseId)} disabled={busy || !gate.ok}>
                          Accept
                        </button>
                        <button className="btn" onClick={() => void tier3Decline(caseId)} disabled={busy || !gate.ok}>
                          Decline
                        </button>
                        <button className="btn" onClick={() => void tier3Attendance(caseId, true)} disabled={busy || !gate.ok}>
                          Mark attended
                        </button>
                        <button className="btn" onClick={() => void tier3Attendance(caseId, false)} disabled={busy || !gate.ok}>
                          Mark absent
                        </button>
                        <button className="btn btnPrimary" onClick={() => void tier3Verdict(caseId, "pass")} disabled={busy || !gate.ok}>
                          Pass
                        </button>
                        <button className="btn" onClick={() => void tier3Verdict(caseId, "fail")} disabled={busy || !gate.ok}>
                          Fail
                        </button>
                      </div>
                    )}

                    {evidenceMedia.length ? (
                      <MediaGallery base={apiBase} media={evidenceMedia} />
                    ) : null}

                    {tab === "tier3" && sessionRec ? (
                      <div className="infoCard">
                        <div className="feedMediaTitle">Live session</div>
                        <div className="feedMediaMeta mono">
                          {String(sessionRec?.session_id || "(missing session id)")}
                        </div>
                        <div className="feedMediaMeta">
                          status: {String(sessionRec?.status || "unknown")} • created: {fmtTs(sessionRec?.created_ts_ms)}
                        </div>
                        {sessionRec?.join_url ? (
                          <div className="buttonRow" style={{ marginTop: 10 }}>
                            <a className="btn" href={String(sessionRec.join_url)} target="_blank" rel="noreferrer">
                              Join session
                            </a>
                          </div>
                        ) : null}
                      </div>
                    ) : null}

                    {tab === "tier3" && sessionParticipants.length ? (
                      <div className="infoCard">
                        <div className="feedMediaTitle">Participants</div>
                        <div className="milestoneList">
                          {sessionParticipants.map((p, idx) => (
                            <span key={`${String(p?.account_id || p?.juror_id || idx)}`} className="miniTag">
                              {String(p?.account_id || p?.juror_id || p?.role || "participant")}
                            </span>
                          ))}
                        </div>
                      </div>
                    ) : null}

                    {detail ? (
                      <details className="detailsPanel">
                        <summary>Case detail</summary>
                        <pre className="codePanel mono">{JSON.stringify(detail, null, 2)}</pre>
                      </details>
                    ) : null}
                  </div>
                </article>
              );
            })}
          </div>
        )}
      </SectionCard>

      {result ? (
        <SectionCard eyebrow="Last action" title="Submission result">
          <pre className="codePanel mono">{JSON.stringify(result, null, 2)}</pre>
        </SectionCard>
      ) : null}
    </div>
  );
}
