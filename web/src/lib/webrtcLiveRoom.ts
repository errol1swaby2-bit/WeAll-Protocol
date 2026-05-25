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

export function parseIceServersFromEnv(): RTCIceServer[] {
  const json = String(import.meta.env.VITE_WEALL_P2P_ICE_SERVERS_JSON || "").trim();
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
    if (stream) callbacks.onRemoteStream(stream);
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
  return navigator.mediaDevices.getUserMedia({
    video: options.camera,
    audio: options.mic,
  });
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
