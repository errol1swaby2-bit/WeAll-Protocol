import React, { useEffect, useMemo, useRef, useState } from "react";

import { getAuthHeaders, getSession, submitSignedTx } from "../auth/session";
import { getApiBaseUrl, weall } from "../api/weall";
import { liveRoomDescriptorText, liveRoomEmbedEnabled, liveRoomTransportNotice, liveRoomUrlFromCommitment } from "../lib/liveRoom";
import { createWeAllPeerConnection, getWeAllLocalMedia, iceServerDiagnostics, loadWeAllIceServersJson, normalizeWeAllIceServers, saveWeAllIceServersJson, shouldCreateOffer, stopWeAllMediaStream, WeAllWebRTCSignal } from "../lib/webrtcLiveRoom";
import { nav } from "../lib/router";
import { REVIEW_CENTER_LABEL } from "../lib/reviewLanes";

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
  const statusOnlyMode = typeof window !== "undefined" && new URLSearchParams(String(window.location.hash || "").split("?")[1] || "").get("mode") === "status";
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
  const [casePendingSync, setCasePendingSync] = useState<boolean>(false);
  const [cameraEnabled, setCameraEnabled] = useState<boolean>(true);
  const [micEnabled, setMicEnabled] = useState<boolean>(true);
  const [showEmbeddedRoom, setShowEmbeddedRoom] = useState<boolean>(liveRoomEmbedEnabled());
  const [operatorToken, setOperatorToken] = useState<string>("");
  const [p2pRunning, setP2pRunning] = useState<boolean>(false);
  const [p2pStatus, setP2pStatus] = useState<string>("idle");
  const [p2pSignalsSent, setP2pSignalsSent] = useState<number>(0);
  const [p2pSignalsReceived, setP2pSignalsReceived] = useState<number>(0);
  const [p2pError, setP2pError] = useState<string>("");
  const [localStream, setLocalStream] = useState<MediaStream | null>(null);
  const [remoteStreams, setRemoteStreams] = useState<Record<string, MediaStream>>({});
  const [iceServers, setIceServers] = useState<RTCIceServer[]>([]);
  const [iceConfigText, setIceConfigText] = useState<string>(() => loadWeAllIceServersJson());
  const localVideoRef = useRef<HTMLVideoElement | null>(null);
  const localStreamRef = useRef<MediaStream | null>(null);
  const peerConnectionsRef = useRef<Map<string, RTCPeerConnection>>(new Map());
  const signalSeqRef = useRef<number>(0);
  const processedSignalsRef = useRef<Set<string>>(new Set());
  const pendingIceCandidatesRef = useRef<Map<string, RTCIceCandidateInit[]>>(new Map());
  const lastOfferAtRef = useRef<Map<string, number>>(new Map());
  const [peerStates, setPeerStates] = useState<Record<string, string>>({});

  async function loadRelayConfig(): Promise<void> {
    try {
      const res = await weall.pohLiveWebRTCRelayConfig(apiBase, headers);
      setIceServers(normalizeWeAllIceServers(res?.ice_servers));
    } catch {
      setIceServers([]);
    }
  }

  useEffect(() => {
    void loadRelayConfig();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [apiBase, account]);

  const sessionForCase = useMemo(() => {
    return sessions.find((item) => String(item.case_id || "") === String(caseId)) || null;
  }, [sessions, caseId]);

  const sessionId = String(sessionForCase?.session_id || (caseId ? `session:${caseId}` : "")).trim();
  const roomUrl = String(sessionForCase?.join_url || liveRoomUrlFromCommitment(liveCase?.room_commitment || sessionForCase?.room_commitment)).trim();
  const p2pRoomDescriptor = liveRoomDescriptorText(liveCase?.room_commitment || sessionForCase?.room_commitment);
  const jurors = Array.isArray(liveCase?.jurors) ? liveCase.jurors : [];
  const myJuror = jurors.find((j) => normalizeAccount(j.juror_id) === account) || null;
  const isSubject = !!account && normalizeAccount(liveCase?.account_id) === account;
  const verdicts = countVerdicts(jurors);
  const isFinal = ["awarded", "rejected", "finalized"].includes(String(liveCase?.status || "").toLowerCase());
  const canAcceptDecline = !!myJuror && !myJuror.accepted && !isFinal;
  const canCheckIn = !!myJuror && myJuror.accepted === true && myJuror.attended !== true && !isFinal;
  const canVote = !!myJuror && myJuror.accepted === true && myJuror.attended === true && String(myJuror.role || "") === "interacting" && !myJuror.verdict && !isFinal;
  const canPresenceCheckIn = !!account && (isSubject || !!myJuror) && !!sessionId;
  const readOnlyStatusView = statusOnlyMode && !isSubject && !myJuror;
  const p2pParticipantAccounts = useMemo(() => {
    const out = new Set<string>();
    const subject = normalizeAccount(liveCase?.account_id);
    if (subject) out.add(subject);
    jurors.forEach((j) => {
      const jid = normalizeAccount(j.juror_id);
      if (jid) out.add(jid);
    });
    chainParticipants.forEach((p: any) => {
      const participant = normalizeAccount(p?.account_id || p?.account || p?.juror_id);
      if (participant) out.add(participant);
    });
    presence.forEach((p) => {
      const participant = normalizeAccount(p.account_id);
      if (participant) out.add(participant);
    });
    return Array.from(out).sort();
  }, [liveCase?.account_id, jurors, chainParticipants, presence]);
  const p2pRemoteAccounts = useMemo(() => {
    return p2pParticipantAccounts.filter((item) => normalizeAccount(item) && normalizeAccount(item) !== account);
  }, [p2pParticipantAccounts, account]);
  const remoteStreamEntries = useMemo(() => Object.entries(remoteStreams), [remoteStreams]);
  const missingRemoteAccounts = useMemo(() => {
    const seen = new Set(remoteStreamEntries.map(([peer]) => normalizeAccount(peer)));
    return p2pRemoteAccounts.filter((peer) => !seen.has(normalizeAccount(peer)));
  }, [p2pRemoteAccounts, remoteStreamEntries]);
  const iceDiag = useMemo(() => iceServerDiagnostics(iceServers), [iceServers]);

  function saveIceConfig(): void {
    try {
      const normalized = saveWeAllIceServersJson(iceConfigText);
      setIceServers(normalized);
      setP2pStatus(iceConfigText.trim() ? "ICE/TURN configuration saved for this browser" : "Using build default ICE configuration");
    } catch (e) {
      setP2pError(`Invalid ICE/TURN JSON: ${prettyError(e)}`);
    }
  }

  async function load(): Promise<void> {
    if (!caseId) return;
    setBusy((b) => b || "Loading live room…");
    setError("");
    try {
      const [caseRes, sessionRes] = await Promise.all([
        weall.pohLiveCase(caseId, apiBase, headers),
        weall.pohLiveSessions(apiBase, headers).catch(() => ({ sessions: [] })),
      ]);
      setCasePendingSync(false);
      setLiveCase(caseRes?.case || null);
      const nextSessions = Array.isArray(sessionRes?.sessions) ? sessionRes.sessions : [];
      setSessions(nextSessions);
    } catch (e) {
      const message = prettyError(e);
      if (message === "live_case_not_found" || message.includes("live_case_not_found")) {
        // Batch 417: the verification page may navigate to the deterministic
        // case id before observer-local state has caught up with genesis.
        // Keep polling instead of stranding the user on a dead room page.
        setCasePendingSync(true);
        setError("");
      } else {
        setError(message);
      }
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
    if (!caseId || liveCase?.case_id) return undefined;
    const id = window.setInterval(() => {
      void load();
    }, 2500);
    return () => window.clearInterval(id);
  }, [caseId, apiBase, liveCase?.case_id]);

  useEffect(() => {
    if (!sessionId) return;
    void loadRoomSidecars(sessionId);
  }, [sessionId, apiBase]);

  useEffect(() => {
    if (localVideoRef.current && localStream) {
      localVideoRef.current.srcObject = localStream;
    }
    if (localStream) {
      peerConnectionsRef.current.forEach((pc) => {
        const existingTrackIds = new Set(pc.getSenders().map((sender) => sender.track?.id).filter(Boolean));
        localStream.getTracks().forEach((track) => {
          if (!existingTrackIds.has(track.id)) pc.addTrack(track, localStream);
        });
      });
    }
  }, [localStream]);

  useEffect(() => {
    if (!p2pRunning || !sessionId) return undefined;
    const id = window.setInterval(() => {
      void pollWebRTCSignals();
    }, 2500);
    return () => window.clearInterval(id);
  }, [p2pRunning, sessionId, apiBase, account]);

  useEffect(() => {
    return () => {
      stopWeAllMediaStream(localStreamRef.current);
      peerConnectionsRef.current.forEach((pc) => pc.close());
      peerConnectionsRef.current.clear();
      pendingIceCandidatesRef.current.clear();
      processedSignalsRef.current.clear();
      lastOfferAtRef.current.clear();
    };
  }, []);

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

  function signalDedupeKey(signal: WeAllWebRTCSignal): string {
    const id = String(signal.signal_id || "").trim();
    if (id) return id;
    const candidate = signal.candidate ? JSON.stringify(signal.candidate) : "";
    return [signal.session_id || sessionId, signal.from_account || "", signal.to_account || "", signal.type || "", signal.sdp || "", candidate].join("|");
  }

  function rememberPeerState(peer: string, state: string): void {
    const remote = normalizeAccount(peer);
    if (!remote) return;
    setPeerStates((prev) => ({ ...prev, [remote]: state }));
  }

  function resetPeerConnection(peer: string): void {
    const remote = normalizeAccount(peer);
    const pc = peerConnectionsRef.current.get(remote);
    if (pc) {
      try { pc.close(); } catch { /* ignore */ }
    }
    peerConnectionsRef.current.delete(remote);
    pendingIceCandidatesRef.current.delete(remote);
    setRemoteStreams((prev) => {
      const next = { ...prev };
      delete next[remote];
      return next;
    });
  }

  function canRetryOffer(peer: string, force = false): boolean {
    if (force) return true;
    const remote = normalizeAccount(peer);
    const last = lastOfferAtRef.current.get(remote) || 0;
    const now = Date.now();
    if (now - last < 3500) return false;
    lastOfferAtRef.current.set(remote, now);
    return true;
  }

  async function flushPendingIceCandidates(peer: string, pc: RTCPeerConnection): Promise<void> {
    const remote = normalizeAccount(peer);
    const pending = pendingIceCandidatesRef.current.get(remote) || [];
    if (!pending.length || !pc.remoteDescription) return;
    pendingIceCandidatesRef.current.delete(remote);
    for (const candidate of pending) {
      try {
        await pc.addIceCandidate(candidate);
      } catch (e) {
        setP2pError(`Could not apply pending ICE from ${remote}: ${prettyError(e)}`);
      }
    }
  }

  async function addOrQueueIceCandidate(peer: string, candidate: RTCIceCandidateInit): Promise<void> {
    const remote = normalizeAccount(peer);
    const pc = getOrCreatePeerConnection(remote);
    if (!pc.remoteDescription) {
      const rows = pendingIceCandidatesRef.current.get(remote) || [];
      rows.push(candidate);
      pendingIceCandidatesRef.current.set(remote, rows.slice(-24));
      rememberPeerState(remote, "queued remote ICE until description arrives");
      return;
    }
    await pc.addIceCandidate(candidate);
  }

  async function sendWebRTCSignal(payload: Partial<WeAllWebRTCSignal> & { type: WeAllWebRTCSignal["type"] }): Promise<void> {
    if (!account || !sessionId) return;
    await weall.pohLiveWebRTCSignalSend(
      sessionId,
      {
        account_id: account,
        type: payload.type,
        to_account: payload.to_account || undefined,
        sdp: payload.sdp || undefined,
        candidate: payload.candidate || undefined,
        ts_ms: Date.now(),
      },
      apiBase,
      headers,
    );
    setP2pSignalsSent((n) => n + 1);
  }

  async function ensureLocalP2PMedia(): Promise<MediaStream> {
    if (localStreamRef.current) return localStreamRef.current;
    const stream = await getWeAllLocalMedia({ camera: cameraEnabled, mic: micEnabled });
    localStreamRef.current = stream;
    setLocalStream(stream);
    return stream;
  }

  function rememberRemoteStream(peer: string, stream: MediaStream): void {
    setRemoteStreams((prev) => ({ ...prev, [peer]: stream }));
  }

  function getOrCreatePeerConnection(peer: string): RTCPeerConnection {
    const remote = normalizeAccount(peer);
    const existing = peerConnectionsRef.current.get(remote);
    if (existing) return existing;
    const pc = createWeAllPeerConnection({
      onIceCandidate: (candidate) => sendWebRTCSignal({ type: "ice", to_account: remote, candidate }),
      onRemoteStream: (stream) => {
        rememberRemoteStream(remote, stream);
        rememberPeerState(remote, "remote media flowing");
      },
      onStateChange: (state) => {
        setP2pStatus(`peer ${remote}: ${state}`);
        rememberPeerState(remote, String(state));
        if (["failed", "disconnected", "closed"].includes(String(state))) {
          lastOfferAtRef.current.delete(remote);
        }
      },
    }, iceServers);
    if (localStreamRef.current) {
      localStreamRef.current.getTracks().forEach((track) => pc.addTrack(track, localStreamRef.current as MediaStream));
    }
    peerConnectionsRef.current.set(remote, pc);
    return pc;
  }

  async function createOfferForPeer(peer: string, opts: { force?: boolean; reason?: string } = {}): Promise<void> {
    const remote = normalizeAccount(peer);
    if (!remote || remote === account) return;
    if (!canRetryOffer(remote, !!opts.force)) return;
    await ensureLocalP2PMedia();
    let pc = getOrCreatePeerConnection(remote);
    if (["closed", "failed"].includes(pc.connectionState)) {
      resetPeerConnection(remote);
      pc = getOrCreatePeerConnection(remote);
    }
    if (pc.signalingState !== "stable") {
      rememberPeerState(remote, `waiting for stable signaling before offer (${pc.signalingState})`);
      return;
    }
    rememberPeerState(remote, opts.reason ? `sending offer: ${opts.reason}` : "sending offer");
    const offer = await pc.createOffer({ iceRestart: opts.force === true });
    await pc.setLocalDescription(offer);
    await sendWebRTCSignal({ type: "offer", to_account: remote, sdp: offer.sdp || "" });
  }

  async function recoverMissingPeerMedia(reason = "missing remote media"): Promise<void> {
    if (!p2pRunning || !account) return;
    for (const peer of missingRemoteAccounts) {
      const remote = normalizeAccount(peer);
      if (!remote || !shouldCreateOffer(account, remote)) continue;
      await createOfferForPeer(remote, { reason });
    }
  }

  async function handleWebRTCSignal(signal: WeAllWebRTCSignal): Promise<void> {
    const from = normalizeAccount(signal.from_account);
    if (!from || from === account) return;
    const key = signalDedupeKey(signal);
    if (processedSignalsRef.current.has(key)) return;
    processedSignalsRef.current.add(key);
    if (processedSignalsRef.current.size > 500) {
      processedSignalsRef.current = new Set(Array.from(processedSignalsRef.current).slice(-250));
    }
    await ensureLocalP2PMedia();
    let pc = getOrCreatePeerConnection(from);
    try {
      if (signal.type === "hello") {
        rememberPeerState(from, "peer hello received");
        if (account && shouldCreateOffer(account, from)) await createOfferForPeer(from, { reason: "peer hello" });
        return;
      }
      if (signal.type === "offer" && signal.sdp) {
        if (pc.signalingState !== "stable") {
          try {
            await pc.setLocalDescription({ type: "rollback" } as RTCSessionDescriptionInit);
          } catch {
            resetPeerConnection(from);
            pc = getOrCreatePeerConnection(from);
          }
        }
        await pc.setRemoteDescription({ type: "offer", sdp: signal.sdp });
        await flushPendingIceCandidates(from, pc);
        const answer = await pc.createAnswer();
        await pc.setLocalDescription(answer);
        await sendWebRTCSignal({ type: "answer", to_account: from, sdp: answer.sdp || "" });
        rememberPeerState(from, "answered peer offer");
        return;
      }
      if (signal.type === "answer" && signal.sdp) {
        if (pc.signalingState === "have-local-offer") {
          await pc.setRemoteDescription({ type: "answer", sdp: signal.sdp });
          await flushPendingIceCandidates(from, pc);
          rememberPeerState(from, "peer answer applied");
        }
        return;
      }
      if (signal.type === "ice" && signal.candidate) {
        await addOrQueueIceCandidate(from, signal.candidate);
        return;
      }
      if (signal.type === "leave") {
        resetPeerConnection(from);
        rememberPeerState(from, "peer left");
      }
    } catch (e) {
      const msg = prettyError(e);
      rememberPeerState(from, `signal error: ${msg}`);
      setP2pError(`Could not apply ${signal.type} from ${from}: ${msg}`);
    }
  }

  async function pollWebRTCSignals(): Promise<void> {
    if (!sessionId || !account) return;
    const res = await weall.pohLiveWebRTCSignals(sessionId, signalSeqRef.current, apiBase, headers);
    const signals = Array.isArray(res?.signals) ? res.signals as WeAllWebRTCSignal[] : [];
    const nextSeq = Number(res?.next_seq || signalSeqRef.current);
    const inboundSignals = signals.filter((signal) => normalizeAccount(signal.from_account) !== account);
    if (inboundSignals.length) setP2pSignalsReceived((n) => n + inboundSignals.length);
    for (const signal of signals) {
      await handleWebRTCSignal(signal);
    }
    if (Number.isFinite(nextSeq)) signalSeqRef.current = Math.max(signalSeqRef.current, nextSeq);
    await recoverMissingPeerMedia("poll recovery");
  }

  async function ensureP2PRoomStarted(): Promise<void> {
    if (!canPresenceCheckIn) throw new Error("Only the subject or assigned reviewers can join the P2P room.");
    setP2pError("");
    await ensureLocalP2PMedia();
    await updatePresence("joined");
    setP2pRunning(true);
    setP2pStatus("p2p signaling active");
    await sendWebRTCSignal({ type: "hello" });
    for (const peer of p2pRemoteAccounts) {
      await sendWebRTCSignal({ type: "hello", to_account: peer });
      if (account && shouldCreateOffer(account, peer)) await createOfferForPeer(peer, { force: true, reason: "room start" });
    }
    await pollWebRTCSignals();
    window.setTimeout(() => void pollWebRTCSignals(), 750);
    window.setTimeout(() => void pollWebRTCSignals(), 1750);
    window.setTimeout(() => void recoverMissingPeerMedia("startup recovery"), 3000);
    window.setTimeout(() => void recoverMissingPeerMedia("startup recovery"), 6500);
  }

  useEffect(() => {
    if (!p2pRunning || !sessionId || !account) return undefined;
    const id = window.setInterval(() => {
      void pollWebRTCSignals().catch((e) => setP2pError(prettyError(e)));
    }, 2000);
    return () => window.clearInterval(id);
  }, [p2pRunning, sessionId, account, p2pRemoteAccounts.join("|")]);

  async function startP2PRoom(): Promise<void> {
    await runAction("Starting decentralized P2P room…", async () => {
      await ensureP2PRoomStarted();
    }).catch((e) => {
      setP2pError(prettyError(e));
      throw e;
    });
  }

  async function stopP2PRoom(): Promise<void> {
    await runAction("Stopping P2P room…", async () => {
      await sendWebRTCSignal({ type: "leave" });
      peerConnectionsRef.current.forEach((pc) => pc.close());
      peerConnectionsRef.current.clear();
      pendingIceCandidatesRef.current.clear();
      processedSignalsRef.current.clear();
      lastOfferAtRef.current.clear();
      stopWeAllMediaStream(localStreamRef.current);
      localStreamRef.current = null;
      setLocalStream(null);
      setRemoteStreams({});
      setPeerStates({});
      pendingIceCandidatesRef.current.clear();
      processedSignalsRef.current.clear();
      lastOfferAtRef.current.clear();
      setP2pRunning(false);
      setP2pStatus("stopped");
      await updatePresence("left");
    });
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
    const shouldEmbed = liveRoomEmbedEnabled();
    const externalRoomUrl = roomUrl && !shouldEmbed ? roomUrl : "";
    if (externalRoomUrl) {
      window.open(externalRoomUrl, "_blank", "noopener,noreferrer");
    }
    await runAction("Checking into live room…", async () => {
      await updatePresence("joined");
      if (myJuror) {
        const skeleton = await weall.pohLiveTxAttendance({ case_id: caseId, juror_id: account, attended: true }, apiBase, headers);
        await submitSkeletonTx(skeleton, "Live room attendance recorded on-chain.");
      } else {
        setNotice("Live room presence updated. Verification authority still requires signed juror attendance and verdicts.");
      }
      if (!roomUrl) {
        try {
          await ensureP2PRoomStarted();
          setNotice("Live room attendance recorded and P2P media started. Keep this page open while the other participant joins.");
        } catch (mediaError) {
          setP2pError(prettyError(mediaError));
          setNotice("Live room attendance was recorded. Start P2P media when camera/microphone access is ready.");
        }
      }
      if (shouldEmbed) {
        setShowEmbeddedRoom(true);
      } else if (roomUrl) {
        setNotice("Live room opened in a separate tab. Keep this page open for chain-recorded attendance and reviewer votes.");
      }
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
      await weall.pohOperatorLiveFinalize({ case_id: caseId }, apiBase, token);
      setNotice("Live verification finalization was queued. Refresh after the next block to confirm the final result.");
      await load();
    });
  }

  const title = statusOnlyMode && !isSubject && !myJuror ? "Live verification status" : cardTitleForRole(isSubject, myJuror);

  return (
    <main className="pageStack liveRoomPage">
      <section className="card liveRoomHero">
        <div className="cardBody formStack">
          <div className="sectionHead">
            <div>
              <div className="eyebrow">Live account verification</div>
              <h1 className="pageTitle">{title}</h1>
              <p className="cardDesc">
                {statusOnlyMode && !isSubject && !myJuror
                  ? "This read-only status view is for pending live verification records before the current account receives a reviewer assignment. Live room transport controls unlock only for the subject or assigned reviewers."
                  : "Use this room to join the live session, check in, record attendance, and complete reviewer voting while keeping video transport only and non-authoritative."}
              </p>
            </div>
            <div className="buttonRow">
              <button className="btn" onClick={() => nav("/reviews?lane=poh_live_review")}>Back to {REVIEW_CENTER_LABEL}</button>
              <button className="btn" onClick={() => nav("/verification")}>Back to verification</button>
            </div>
          </div>
          <div className="statusGrid">
            <div className="statusCard"><span>Status</span><strong>{statusLabel(liveCase?.status)}</strong></div>
            <div className="statusCard"><span>Attendance</span><strong>{verdicts.attended}/{verdicts.accepted || jurors.length}</strong></div>
            <div className="statusCard"><span>Votes</span><strong>{verdicts.pass} approve / {verdicts.fail} reject</strong></div>
            <div className="statusCard"><span>Tier result</span><strong>{liveCase?.tier_awarded ? `Tier ${liveCase.tier_awarded}` : "Pending"}</strong></div>
          </div>
          <p className="noticeText">{liveRoomTransportNotice()}</p>
          {casePendingSync ? (
            <div className="actionStatus">
              Live request accepted. Waiting for the live case and session to sync into this frontend…
            </div>
          ) : null}
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
                <h2 className="cardTitle">{readOnlyStatusView ? "Read-only live status" : "Conference feed"}</h2>
              </div>
              {!readOnlyStatusView && roomUrl ? <a className="btn" href={roomUrl} target="_blank" rel="noreferrer">Open room</a> : null}
            </div>
            {readOnlyStatusView ? (
              <div className="videoPlaceholder">
                <strong>Read-only status view</strong>
                <p>This account is not the subject or an assigned reviewer for this live verification case, so room transport, Open room links, embedded video, and P2P media controls stay hidden.</p>
                <p>Use the status cards and technical commitments to verify that the case exists without implying live-room authority.</p>
              </div>
            ) : roomUrl && liveRoomEmbedEnabled() && showEmbeddedRoom ? (
              <iframe
                className="liveRoomFrame"
                src={roomUrl}
                title="WeAll Live Verification Room"
                allow="camera; microphone; fullscreen; display-capture"
              />
            ) : roomUrl ? (
              <div className="videoPlaceholder">
                <strong>Compatibility room link ready</strong>
                <p>Open the self-hosted transport in a separate tab. This page records attendance, verdicts, and finalization on-chain.</p>
              </div>
            ) : (
              <div className="p2pRoomPanel">
                <div className="videoPlaceholder">
                  <strong>Decentralized P2P WebRTC room</strong>
                  <p>Browser media runs peer-to-peer using case-scoped signaling. Relays/ICE servers are transport fallback only and cannot grant verification.</p>
                  <small>Status: {p2pStatus}</small>
                  <small>Optional STUN/TURN relay discovery: {iceServers.length ? `${iceServers.length} configured relay set(s)` : "direct P2P first"}</small>
                  <small>Expected participants: {p2pParticipantAccounts.length ? p2pParticipantAccounts.join(", ") : "waiting for chain assignment"}</small>
                  <small>Remote feeds: {remoteStreamEntries.length}/{p2pRemoteAccounts.length} · waiting {missingRemoteAccounts.length} · signals sent {p2pSignalsSent} · received {p2pSignalsReceived} · ICE {iceDiag.count} server(s) {iceDiag.hasTurn ? "with TURN" : "no TURN"}</small>
                  {Object.keys(peerStates).length ? <small>Peer states: {Object.entries(peerStates).map(([peer, state]) => `${peer}=${state}`).join(" · ")}</small> : null}
                  {p2pError ? <small className="errorText">{p2pError}</small> : null}
                </div>
                <div className="p2pVideoGrid">
                  <div className="p2pVideoTile">
                    <video ref={localVideoRef} autoPlay playsInline muted />
                    <span>{account || "Local participant"}</span>
                  </div>
                  {remoteStreamEntries.map(([peer, stream]) => (
                    <div className="p2pVideoTile" key={peer}>
                      <video
                        autoPlay
                        playsInline
                        ref={(node) => {
                          if (node && node.srcObject !== stream) node.srcObject = stream;
                        }}
                      />
                      <span>{peer}</span>
                    </div>
                  ))}
                  {missingRemoteAccounts.map((peer) => (
                    <div className="p2pVideoTile" key={`waiting:${peer}`}>
                      <div className="videoPlaceholder">Waiting for media from {peer}. Keep both tabs open and use Poll P2P if the remote camera is not visible yet.{peerStates[peer] ? ` State: ${peerStates[peer]}` : ""}</div>
                      <span>{peer}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
            {!readOnlyStatusView && p2pRoomDescriptor ? (
              <details className="advancedDetails" open={!roomUrl}>

            <p className="text-sm text-slate-600">Use the decentralized P2P room descriptor below to establish the WebRTC session; verification still depends only on chain-recorded attendance, verdicts, and finalization.</p>
                <summary>Decentralized P2P room descriptor</summary>
                <pre className="jsonBlock">{p2pRoomDescriptor}</pre>
              </details>
            ) : null}
            {!readOnlyStatusView ? (
              <>
                <div className="toggleRow">
                  <label><input type="checkbox" checked={cameraEnabled} onChange={(e) => setCameraEnabled(e.currentTarget.checked)} /> Camera on</label>
                  <label><input type="checkbox" checked={micEnabled} onChange={(e) => setMicEnabled(e.currentTarget.checked)} /> Mic on</label>
                </div>
                <div className="buttonRow">
                  <button className="btn btnPrimary" disabled={!canPresenceCheckIn || !!busy} onClick={checkIntoRoom}>Join / check in + start media</button>
                  <button className="btn" disabled={!canPresenceCheckIn || !!busy || !!roomUrl || p2pRunning} onClick={startP2PRoom}>Start P2P media</button>
                  <button className="btn" disabled={!p2pRunning || !!busy} onClick={() => runAction("Polling P2P signals…", pollWebRTCSignals)}>Poll P2P</button>
                  <button className="btn" disabled={!p2pRunning || !!busy} onClick={stopP2PRoom}>Stop P2P</button>
                  <button className="btn" disabled={!account || !sessionId || !!busy} onClick={() => runAction("Updating presence…", () => updatePresence("left"))}>Mark left</button>
                  <button className="btn" disabled={!sessionId || !!busy} onClick={() => loadRoomSidecars(sessionId)}>Refresh room</button>
                </div>
              </>
            ) : null}
            {!readOnlyStatusView ? <details className="advancedDetails">
              <summary>TURN / relay config</summary>
              <p className="cardDesc">External networks often need TURN. These browser-local settings are transport-only and never become verification authority.</p>
              <textarea value={iceConfigText} onChange={(e) => setIceConfigText(e.target.value)} rows={4} placeholder='[{"urls":"turn:turn.example.org","username":"user","credential":"pass"}]' />
              <div className="buttonRow"><button className="btn" onClick={saveIceConfig}>Save ICE/TURN config</button></div>
              {iceDiag.relayRecommended ? <div className="calloutInfo">No TURN relay is configured. Same-LAN tests may work, but external participants will likely need TURN.</div> : null}
            </details> : null}
            {!readOnlyStatusView ? <div className="inCallVotingPanel" data-testid="webrtc-live-voting">
              <div className="eyebrow">In-call chain voting</div>
              <h3 className="cardTitle">Reviewer vote inside the WebRTC room</h3>
              {!myJuror ? (
                <p className="cardDesc">Voting controls appear here for assigned reviewers. The video room remains transport only.</p>
              ) : (
                <>
                  <p className="cardDesc">Use these controls without leaving the WebRTC page. Accept the assignment, record attendance, then cast the live verification vote.</p>
                  <div className="statusGrid">
                    <div className="statusCard"><span>Your assignment</span><strong>{myJuror.accepted ? "Accepted" : "Pending"}</strong></div>
                    <div className="statusCard"><span>Your attendance</span><strong>{myJuror.attended ? "Recorded" : "Needed"}</strong></div>
                    <div className="statusCard"><span>Your vote</span><strong>{myJuror.verdict ? statusLabel(myJuror.verdict) : "Not cast"}</strong></div>
                  </div>
                  <div className="buttonRow">
                    <button className="btn" disabled={!canAcceptDecline || !!busy} onClick={acceptCase}>Accept review</button>
                    <button className="btn" disabled={!canAcceptDecline || !!busy} onClick={declineCase}>Decline</button>
                    <button className="btn btnPrimary" disabled={!canCheckIn || !!busy} onClick={checkIntoRoom}>Record attendance</button>
                  </div>
                  <div className="buttonRow">
                    <button className="btn btnPrimary" disabled={!canVote || !!busy} onClick={() => submitVerdict("pass")}>Approve live verification</button>
                    <button className="btn" disabled={!canVote || !!busy} onClick={() => submitVerdict("fail")}>Reject live verification</button>
                  </div>
                  {!canVote && !isFinal ? <p className="helpText">Voting unlocks only for an assigned interacting reviewer after review acceptance and on-chain attendance.</p> : null}
                </>
              )}
            </div> : null}
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
