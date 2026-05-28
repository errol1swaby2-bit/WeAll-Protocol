export type WeAllWebRTCSignalType = "hello" | "offer" | "answer" | "ice" | "leave";

export type WeAllWebRTCSignal = {
  seq?: number;
  signal_id?: string;
  session_id?: string;
  case_id?: string;
  from_account: string;
  to_account?: string | null;
  type: WeAllWebRTCSignalType;
  sdp?: string | null;
  candidate?: RTCIceCandidateInit | null;
  ts_ms?: number;
  authority?: "transport_only_ephemeral" | string;
};

export type WeAllPeerConnectionCallbacks = {
  onIceCandidate: (candidate: RTCIceCandidateInit) => void | Promise<void>;
  onRemoteStream: (stream: MediaStream) => void;
  onStateChange?: (state: RTCPeerConnectionState) => void;
};


export function loadWeAllIceServersJson(): string {
  try {
    return typeof localStorage !== "undefined" ? String(localStorage.getItem("weall.p2p.iceServersJson") || "") : "";
  } catch {
    return "";
  }
}

export function saveWeAllIceServersJson(value: string): RTCIceServer[] {
  const text = String(value || "").trim();
  if (!text) {
    try {
      if (typeof localStorage !== "undefined") localStorage.removeItem("weall.p2p.iceServersJson");
    } catch {
      // ignore browser storage failures; caller still falls back to build defaults
    }
    return [];
  }
  const parsed = JSON.parse(text);
  const normalized = normalizeWeAllIceServers(parsed);
  try {
    if (typeof localStorage !== "undefined") localStorage.setItem("weall.p2p.iceServersJson", JSON.stringify(normalized));
  } catch {
    // ignore browser storage failures; caller still uses the parsed value in memory
  }
  return normalized;
}

export function parseIceServersFromEnv(): RTCIceServer[] {
  let json = String(import.meta.env.VITE_WEALL_P2P_ICE_SERVERS_JSON || "").trim();
  try {
    const stored = typeof localStorage !== "undefined" ? String(localStorage.getItem("weall.p2p.iceServersJson") || "").trim() : "";
    if (stored) json = stored;
  } catch {
    // ignore storage failures
  }
  if (json) {
    try {
      const parsed = JSON.parse(json);
      return Array.isArray(parsed) ? parsed as RTCIceServer[] : [];
    } catch {
      return [];
    }
  }
  const urls = String(import.meta.env.VITE_WEALL_P2P_STUN_URLS || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
  return urls.length ? [{ urls }] : [];
}

export function normalizeWeAllIceServers(value: unknown): RTCIceServer[] {
  if (!Array.isArray(value)) return [];
  return value
    .filter((item): item is RTCIceServer => !!item && typeof item === "object" && "urls" in item)
    .map((item) => item as RTCIceServer);
}

export function configuredWeAllIceServers(extra?: RTCIceServer[]): RTCIceServer[] {
  return extra && extra.length ? extra : parseIceServersFromEnv();
}

export function iceServerDiagnostics(extra?: RTCIceServer[]): { count: number; hasTurn: boolean; hasStun: boolean; relayRecommended: boolean } {
  const servers = configuredWeAllIceServers(extra);
  const urls = servers.flatMap((server) => Array.isArray(server.urls) ? server.urls : [server.urls]).map((url) => String(url || "").toLowerCase());
  return {
    count: servers.length,
    hasTurn: urls.some((url) => url.startsWith("turn:" ) || url.startsWith("turns:")),
    hasStun: urls.some((url) => url.startsWith("stun:")),
    relayRecommended: !urls.some((url) => url.startsWith("turn:" ) || url.startsWith("turns:")),
  };
}

export function weallWebRTCAvailable(): boolean {
  return typeof window !== "undefined" && typeof RTCPeerConnection !== "undefined" && !!navigator.mediaDevices?.getUserMedia;
}

export function createWeAllPeerConnection(callbacks: WeAllPeerConnectionCallbacks, iceServers?: RTCIceServer[]): RTCPeerConnection {
  const pc = new RTCPeerConnection({ iceServers: configuredWeAllIceServers(iceServers) });
  pc.onicecandidate = (event) => {
    if (event.candidate) void callbacks.onIceCandidate(event.candidate.toJSON());
  };
  pc.ontrack = (event) => {
    const [stream] = event.streams;
    // Some browsers/tests deliver the track without a populated streams array.
    // Do not drop the remote participant's media in that case; materialize a
    // stream from the track so the conference tile can render it.
    if (stream) {
      callbacks.onRemoteStream(stream);
      return;
    }
    if (event.track) callbacks.onRemoteStream(new MediaStream([event.track]));
  };
  pc.onconnectionstatechange = () => {
    callbacks.onStateChange?.(pc.connectionState);
  };
  return pc;
}

export async function getWeAllLocalMedia(options: { camera: boolean; mic: boolean }): Promise<MediaStream> {
  if (!weallWebRTCAvailable()) {
    throw new Error("WebRTC media capture is not available in this browser.");
  }
  if (!options.camera && !options.mic) {
    throw new Error("Turn on camera or microphone before starting the P2P room.");
  }
  try {
    return await navigator.mediaDevices.getUserMedia({ video: options.camera, audio: options.mic });
  } catch (firstError) {
    // Same-machine/two-tab rehearsals commonly fail the second camera capture.
    // Keep the participant visible with audio-only fallback when possible.
    if (options.camera && options.mic) {
      try {
        return await navigator.mediaDevices.getUserMedia({ video: false, audio: true });
      } catch {
        throw firstError;
      }
    }
    throw firstError;
  }
}

export function stopWeAllMediaStream(stream?: MediaStream | null): void {
  if (!stream) return;
  stream.getTracks().forEach((track) => {
    try {
      track.stop();
    } catch {
      // ignore track stop failures
    }
  });
}

export function participantSortKey(account: string): string {
  return String(account || "").trim().toLowerCase();
}

export function shouldCreateOffer(localAccount: string, remoteAccount: string): boolean {
  return participantSortKey(localAccount) < participantSortKey(remoteAccount);
}
