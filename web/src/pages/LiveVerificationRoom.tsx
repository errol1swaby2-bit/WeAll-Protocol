import React, { useEffect, useMemo, useState } from "react";

import { getAuthHeaders, getSession, submitSignedTx } from "../auth/session";
import { getApiBaseUrl, weall } from "../api/weall";
import { liveRoomTransportNotice, liveRoomUrlFromCommitment } from "../lib/liveRoom";
import { nav } from "../lib/router";

type LiveJuror = {
  juror_id?: string;
  role?: string;
  accepted?: boolean;
  attended?: boolean;
  attended_ts_ms?: number | null;
  verdict?: string | null;
};

type LiveCase = {
  case_id?: string;
  account_id?: string;
  status?: string;
  room_commitment?: string | null;
  session_commitment?: string | null;
  prompt_commitment?: string | null;
  finalized_ts_ms?: number | null;
  outcome?: string | null;
  tier_awarded?: number | null;
  poh_nft_token_id?: string | null;
  jurors?: LiveJuror[];
};

type LiveSession = {
  session_id?: string;
  case_id?: string;
  status?: string;
  join_url?: string | null;
  room_commitment?: string | null;
};

type PresenceRecord = {
  session_id?: string;
  case_id?: string;
  account_id?: string;
  role?: string;
  status?: string;
  camera_enabled?: boolean | null;
  mic_enabled?: boolean | null;
  display_name?: string | null;
  joined_ts_ms?: number | null;
  last_seen_ts_ms?: number | null;
  left_ts_ms?: number | null;
  authority?: string;
};

function normalizeAccount(raw?: string | null): string {
  return String(raw || "").trim();
}

function prettyError(e: unknown): string {
  if (e && typeof e === "object") {
    const anyErr = e as any;
    const payload = anyErr.payload;
    if (payload && typeof payload === "object") {
      const msg = String(payload?.error?.message || payload?.message || "").trim();
      if (msg) return msg;
      const detail = payload?.detail;
      if (typeof detail === "string" && detail.trim()) return detail.trim();
    }
    if (typeof anyErr.message === "string" && anyErr.message.trim()) return anyErr.message.trim();
  }
  return "This live verification action could not be completed.";
}

function statusLabel(value?: string | null): string {
  const s = String(value || "").trim().toLowerCase();
  if (!s) return "Unknown";
  if (s === "awarded") return "Approved";
  if (s === "rejected") return "Rejected";
  if (s === "requested") return "Requested";
  if (s === "init") return "Session ready";
  return s.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

function countVerdicts(jurors: LiveJuror[] = []): { pass: number; fail: number; attended: number; accepted: number; interacting: number } {
  return jurors.reduce(
    (acc, juror) => {
      if (juror.accepted) acc.accepted += 1;
      if (juror.attended) acc.attended += 1;
      if (String(juror.role || "") === "interacting") acc.interacting += 1;
      const verdict = String(juror.verdict || "").toLowerCase();
      if (verdict === "pass") acc.pass += 1;
      if (verdict === "fail") acc.fail += 1;
      return acc;
    },
    { pass: 0, fail: 0, attended: 0, accepted: 0, interacting: 0 },
  );
}

function cardTitleForRole(isSubject: boolean, juror?: LiveJuror | null): string {
  if (isSubject) return "Your live verification room";
  if (juror) return "Assigned reviewer room";
  return "Live verification room";
}

function TechnicalCommitments({ liveCase }: { liveCase: LiveCase | null }): JSX.Element | null {
  if (!liveCase) return null;
  return (
    <details className="advancedDetails">
      <summary>View technical room commitments</summary>
      <dl className="kvList">
        <div><dt>Case</dt><dd>{liveCase.case_id || "—"}</dd></div>
        <div><dt>Session commitment</dt><dd>{liveCase.session_commitment || "—"}</dd></div>
        <div><dt>Room commitment</dt><dd>{liveCase.room_commitment || "—"}</dd></div>
        <div><dt>Prompt commitment</dt><dd>{liveCase.prompt_commitment || "—"}</dd></div>
      </dl>
    </details>
  );
}

export default function LiveVerificationRoom({ caseId }: { caseId: string }): JSX.Element {
  const apiBase = useMemo(() => getApiBaseUrl(), []);
  const session = getSession();
  const account = normalizeAccount(session?.account);
  const headers = useMemo(() => (account ? getAuthHeaders(account) : undefined), [account]);

  const [liveCase, setLiveCase] = useState<LiveCase | null>(null);
  const [sessions, setSessions] = useState<LiveSession[]>([]);
  const [chainParticipants, setChainParticipants] = useState<any[]>([]);
  const [presence, setPresence] = useState<PresenceRecord[]>([]);
  const [busy, setBusy] = useState<string>("");
  const [error, setError] = useState<string>("");
  const [notice, setNotice] = useState<string>("");
  const [cameraEnabled, setCameraEnabled] = useState<boolean>(true);
  const [micEnabled, setMicEnabled] = useState<boolean>(true);
  const [showEmbeddedRoom, setShowEmbeddedRoom] = useState<boolean>(false);
  const [operatorToken, setOperatorToken] = useState<string>(() => {
    try {
      return localStorage.getItem("weall.operator.poh.token") || "";
    } catch {
      return "";
    }
  });

  const sessionForCase = useMemo(() => {
    return sessions.find((item) => String(item.case_id || "") === String(caseId)) || null;
  }, [sessions, caseId]);

  const sessionId = String(sessionForCase?.session_id || (caseId ? `session:${caseId}` : "")).trim();
  const roomUrl = String(sessionForCase?.join_url || liveRoomUrlFromCommitment(liveCase?.room_commitment || sessionForCase?.room_commitment)).trim();
  const jurors = Array.isArray(liveCase?.jurors) ? liveCase.jurors : [];
  const myJuror = jurors.find((j) => normalizeAccount(j.juror_id) === account) || null;
  const isSubject = !!account && normalizeAccount(liveCase?.account_id) === account;
  const verdicts = countVerdicts(jurors);
  const isFinal = ["awarded", "rejected", "finalized"].includes(String(liveCase?.status || "").toLowerCase());
  const canAcceptDecline = !!myJuror && !myJuror.accepted && !isFinal;
  const canCheckIn = !!myJuror && myJuror.accepted === true && myJuror.attended !== true && !isFinal;
  const canVote = !!myJuror && myJuror.accepted === true && myJuror.attended === true && String(myJuror.role || "") === "interacting" && !myJuror.verdict && !isFinal;
  const canPresenceCheckIn = !!account && (isSubject || !!myJuror) && !!sessionId;

  async function load(): Promise<void> {
    if (!caseId) return;
    setBusy((b) => b || "Loading live room…");
    setError("");
    try {
      const [caseRes, sessionRes] = await Promise.all([
        weall.pohLiveCase(caseId, apiBase, headers),
        weall.pohLiveSessions(apiBase, headers).catch(() => ({ sessions: [] })),
      ]);
      setLiveCase(caseRes?.case || null);
      const nextSessions = Array.isArray(sessionRes?.sessions) ? sessionRes.sessions : [];
      setSessions(nextSessions);
    } catch (e) {
      setError(prettyError(e));
    } finally {
      setBusy("");
    }
  }

  async function loadRoomSidecars(nextSessionId = sessionId): Promise<void> {
    if (!nextSessionId) return;
    try {
      const [participantsRes, presenceRes] = await Promise.all([
        weall.pohLiveSessionParticipants(nextSessionId, apiBase, headers).catch(() => ({ participants: [] })),
        weall.pohLiveSessionPresence(nextSessionId, apiBase, headers).catch(() => ({ presence: [] })),
      ]);
      setChainParticipants(Array.isArray(participantsRes?.participants) ? participantsRes.participants : []);
      setPresence(Array.isArray(presenceRes?.presence) ? presenceRes.presence : []);
    } catch {
      // Room sidecars are helpful, not authoritative. Keep the case visible.
    }
  }

  useEffect(() => {
    void load();
  }, [caseId, apiBase]);

  useEffect(() => {
    if (!sessionId) return;
    void loadRoomSidecars(sessionId);
  }, [sessionId, apiBase]);

  useEffect(() => {
    if (!sessionId) return;
    const id = window.setInterval(() => {
      void load();
      void loadRoomSidecars(sessionId);
    }, 12_000);
    return () => window.clearInterval(id);
  }, [sessionId, caseId, apiBase]);

  async function updatePresence(status: "joined" | "left" | "reconnect" | "heartbeat"): Promise<void> {
    if (!account || !sessionId) return;
    const payload = {
      account_id: account,
      status,
      camera_enabled: cameraEnabled,
      mic_enabled: micEnabled,
      display_name: account,
      ts_ms: Date.now(),
    };
    await weall.pohLiveSessionPresenceUpdate(sessionId, payload, apiBase, headers);
    await loadRoomSidecars(sessionId);
  }

  async function submitSkeletonTx(skeleton: any, success: string): Promise<void> {
    const tx = skeleton?.tx;
    if (!account) throw new Error("Sign in before completing this live verification action.");
    if (!tx?.tx_type) throw new Error("Live verification transaction skeleton is missing a transaction type.");
    const payload = { ...(tx.payload || {}) };
    if (typeof payload.ts_ms === "number" && payload.ts_ms === 0) payload.ts_ms = Date.now();
    await submitSignedTx({ account, tx_type: String(tx.tx_type), payload, parent: tx.parent ?? null, base: apiBase });
    setNotice(success);
    await load();
    await loadRoomSidecars(sessionId);
  }

  async function runAction(label: string, task: () => Promise<void>): Promise<void> {
    setBusy(label);
    setError("");
    setNotice("");
    try {
      await task();
    } catch (e) {
      setError(prettyError(e));
    } finally {
      setBusy("");
    }
  }

  async function acceptCase(): Promise<void> {
    await runAction("Accepting live review…", async () => {
      const skeleton = await weall.pohLiveTxJurorAccept({ case_id: caseId }, apiBase, headers);
      await submitSkeletonTx(skeleton, "Live verification review accepted.");
    });
  }

  async function declineCase(): Promise<void> {
    await runAction("Declining live review…", async () => {
      const skeleton = await weall.pohLiveTxJurorDecline({ case_id: caseId }, apiBase, headers);
      await submitSkeletonTx(skeleton, "Live verification review declined.");
    });
  }

  async function checkIntoRoom(): Promise<void> {
    await runAction("Checking into live room…", async () => {
      await updatePresence("joined");
      if (myJuror) {
        const skeleton = await weall.pohLiveTxAttendance({ case_id: caseId, juror_id: account, attended: true }, apiBase, headers);
        await submitSkeletonTx(skeleton, "Live room attendance recorded on-chain.");
      } else {
        setNotice("Live room presence updated. Verification authority still requires signed juror attendance and verdicts.");
      }
      setShowEmbeddedRoom(true);
    });
  }

  async function submitVerdict(verdict: "pass" | "fail"): Promise<void> {
    await runAction(verdict === "pass" ? "Submitting approval…" : "Submitting rejection…", async () => {
      const skeleton = await weall.pohLiveTxVerdict({ case_id: caseId, verdict }, apiBase, headers);
      await submitSkeletonTx(skeleton, verdict === "pass" ? "Approval vote recorded." : "Rejection vote recorded.");
    });
  }

  async function finalizeCase(): Promise<void> {
    await runAction("Requesting finalization…", async () => {
      const token = operatorToken.trim();
      if (!token) throw new Error("Enter the operator PoH token before requesting system finalization.");
      try {
        localStorage.setItem("weall.operator.poh.token", token);
      } catch {
        // ignore local storage failures
      }
      await weall.pohOperatorLiveFinalize({ case_id: caseId }, apiBase, token);
      setNotice("Live verification finalization was queued. Refresh after the next block to confirm the final result.");
      await load();
    });
  }

  const title = cardTitleForRole(isSubject, myJuror);

  return (
    <main className="pageStack liveRoomPage">
      <section className="card liveRoomHero">
        <div className="cardBody formStack">
          <div className="sectionHead">
            <div>
              <div className="eyebrow">Live account verification</div>
              <h1 className="pageTitle">{title}</h1>
              <p className="cardDesc">Use this room to join the live session, check in, record attendance, and complete reviewer voting while keeping video transport only and non-authoritative.</p>
            </div>
            <button className="btn" onClick={() => nav("/verification")}>Back to verification</button>
          </div>
          <div className="statusGrid">
            <div className="statusCard"><span>Status</span><strong>{statusLabel(liveCase?.status)}</strong></div>
            <div className="statusCard"><span>Attendance</span><strong>{verdicts.attended}/{verdicts.accepted || jurors.length}</strong></div>
            <div className="statusCard"><span>Votes</span><strong>{verdicts.pass} approve / {verdicts.fail} reject</strong></div>
            <div className="statusCard"><span>Tier result</span><strong>{liveCase?.tier_awarded ? `Tier ${liveCase.tier_awarded}` : "Pending"}</strong></div>
          </div>
          <p className="noticeText">{liveRoomTransportNotice()}</p>
          {error ? <div className="errorBanner">{error}</div> : null}
          {notice ? <div className="successBanner">{notice}</div> : null}
          {busy ? <div className="actionStatus">{busy}</div> : null}
        </div>
      </section>

      <section className="liveRoomGrid">
        <article className="card liveVideoCard">
          <div className="cardBody formStack">
            <div className="sectionHead">
              <div>
                <div className="eyebrow">Video room</div>
                <h2 className="cardTitle">Conference feed</h2>
              </div>
              {roomUrl ? <a className="btn" href={roomUrl} target="_blank" rel="noreferrer">Open room</a> : null}
            </div>
            {roomUrl && showEmbeddedRoom ? (
              <iframe
                className="liveRoomFrame"
                src={roomUrl}
                title="WeAll Live Verification Room"
                allow="camera; microphone; fullscreen; display-capture"
              />
            ) : (
              <div className="videoPlaceholder">
                <strong>{roomUrl ? "Room ready" : "Self-hosted room URL not configured"}</strong>
                <p>{roomUrl ? "Check in to embed the room here, or open it in a separate tab." : "Set VITE_WEALL_LIVE_ROOM_BASE_URL to use an embedded self-hosted video transport such as Jitsi or LiveKit."}</p>
              </div>
            )}
            <div className="toggleRow">
              <label><input type="checkbox" checked={cameraEnabled} onChange={(e) => setCameraEnabled(e.currentTarget.checked)} /> Camera on</label>
              <label><input type="checkbox" checked={micEnabled} onChange={(e) => setMicEnabled(e.currentTarget.checked)} /> Mic on</label>
            </div>
            <div className="buttonRow">
              <button className="btn btnPrimary" disabled={!canPresenceCheckIn || !!busy} onClick={checkIntoRoom}>Join / check in</button>
              <button className="btn" disabled={!account || !sessionId || !!busy} onClick={() => runAction("Updating presence…", () => updatePresence("left"))}>Mark left</button>
              <button className="btn" disabled={!sessionId || !!busy} onClick={() => loadRoomSidecars(sessionId)}>Refresh room</button>
            </div>
          </div>
        </article>

        <aside className="card">
          <div className="cardBody formStack">
            <div className="eyebrow">Participant state</div>
            <h2 className="cardTitle">People in this session</h2>
            <div className="participantList">
              <div className="participantItem">
                <strong>{liveCase?.account_id || "Subject"}</strong>
                <span>Verification subject</span>
              </div>
              {jurors.map((juror) => {
                const presenceRec = presence.find((p) => normalizeAccount(p.account_id) === normalizeAccount(juror.juror_id));
                return (
                  <div className="participantItem" key={String(juror.juror_id)}>
                    <strong>{juror.juror_id}</strong>
                    <span>{juror.role || "juror"} · {juror.accepted ? "accepted" : "pending"} · {juror.attended ? "attended" : "not checked in"}</span>
                    <small>{presenceRec ? `${presenceRec.status || "present"} · camera ${presenceRec.camera_enabled ? "on" : "off"} · mic ${presenceRec.mic_enabled ? "on" : "off"}` : "No room presence yet"}</small>
                  </div>
                );
              })}
              {chainParticipants.length ? <small>Chain participant records: {chainParticipants.length}</small> : null}
            </div>
          </div>
        </aside>
      </section>

      <section className="liveRoomGrid">
        <article className="card">
          <div className="cardBody formStack">
            <div className="eyebrow">Reviewer action</div>
            <h2 className="cardTitle">In-call reviewer controls</h2>
            {!myJuror ? (
              <p className="cardDesc">You are not assigned as a reviewer for this case. You can join only if you are the verification subject or an assigned reviewer.</p>
            ) : (
              <>
                <p className="cardDesc">Reviewer role: <strong>{myJuror.role || "juror"}</strong>. Verdict buttons unlock only after you accept and record attendance on-chain.</p>
                <div className="buttonRow">
                  <button className="btn" disabled={!canAcceptDecline || !!busy} onClick={acceptCase}>Accept review</button>
                  <button className="btn" disabled={!canAcceptDecline || !!busy} onClick={declineCase}>Decline</button>
                  <button className="btn btnPrimary" disabled={!canCheckIn || !!busy} onClick={checkIntoRoom}>Record attendance</button>
                </div>
                <div className="buttonRow">
                  <button className="btn btnPrimary" disabled={!canVote || !!busy} onClick={() => submitVerdict("pass")}>Approve live verification</button>
                  <button className="btn" disabled={!canVote || !!busy} onClick={() => submitVerdict("fail")}>Reject live verification</button>
                </div>
                {!canVote && !isFinal ? <p className="helpText">To vote, you must be an interacting reviewer, accept the case, and record live-room attendance first.</p> : null}
              </>
            )}
          </div>
        </article>

        <article className="card">
          <div className="cardBody formStack">
            <div className="eyebrow">Finalization</div>
            <h2 className="cardTitle">Trusted Verified Person result</h2>
            <p className="cardDesc">The page shows approval only after the chain-finalized live verification result awards Tier 2.</p>
            <div className="statusGrid">
              <div className="statusCard"><span>Outcome</span><strong>{liveCase?.outcome || "Pending"}</strong></div>
              <div className="statusCard"><span>Token</span><strong>{liveCase?.poh_nft_token_id || "—"}</strong></div>
            </div>
            <label className="fieldLabel">Operator PoH token</label>
            <input className="input" type="password" value={operatorToken} onChange={(e) => setOperatorToken(e.currentTarget.value)} placeholder="Required only for system finalization" />
            <div className="buttonRow">
              <button className="btn btnPrimary" disabled={isFinal || !!busy || !operatorToken.trim()} onClick={finalizeCase}>Queue finalization</button>
              <button className="btn" disabled={!!busy} onClick={load}>Refresh result</button>
            </div>
            <TechnicalCommitments liveCase={liveCase} />
          </div>
        </article>
      </section>
    </main>
  );
}
