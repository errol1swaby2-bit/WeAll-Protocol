// centralized URL transport is a compatibility escape hatch; decentralized p2p-webrtc remains the default.
export type WeAllP2PLiveRoomDescriptor = {
  version: "weall-live-room-v1";
  transport: "p2p-webrtc";
  authority: "weall-chain";
  room_id: string;
  room_commitment: string;
  signaling: "case-scoped-presence";
  relay_policy: "community-relay-fallback-only";
  storage_policy: "no-raw-recording-by-default";
  privacy: "subject-and-assigned-reviewers-only";
  notes: string[];
};

const DEFAULT_TRANSPORT_MODE = "p2p";
const LEGACY_CENTRALIZED_ROOM_BASE_URL = "";
const TRUSTED_DEV_LOCAL_ROOM_RE = /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?(\/|$)/;

function normalizeBaseUrl(raw?: string): string {
  const value = String(raw || "").trim().replace(/\/+$/, "");
  if (!value) return LEGACY_CENTRALIZED_ROOM_BASE_URL;
  return value;
}

export function liveRoomTransportMode(): string {
  const raw = String(import.meta.env.VITE_WEALL_LIVE_ROOM_TRANSPORT_MODE || DEFAULT_TRANSPORT_MODE)
    .trim()
    .toLowerCase();
  return raw === "centralized-url" ? "centralized-url" : "p2p";
}

function centralizedUrlOptInEnabled(): boolean {
  const raw = String(import.meta.env.VITE_WEALL_ALLOW_CENTRALIZED_LIVE_ROOM_URL || "").trim().toLowerCase();
  return raw === "1" || raw === "true" || raw === "yes" || raw === "on";
}

function isSelfHostedOrAccessControlled(value: string): boolean {
  if (!value) return false;
  if (TRUSTED_DEV_LOCAL_ROOM_RE.test(value)) return true;
  try {
    const url = new URL(value);
    const host = url.hostname.toLowerCase();
    if (host === "meet.jit.si" || host.endsWith(".jit.si")) return false;
    // Centralized URL transport is a compatibility escape hatch only. The
    // default WeAll live verification room is decentralized peer-to-peer;
    // hosted rooms must be explicit, self-hosted, and access controlled.
    return url.protocol === "https:" && !host.includes("meet.jit.si");
  } catch {
    return false;
  }
}

export function liveRoomBaseUrl(): string {
  if (liveRoomTransportMode() !== "centralized-url" || !centralizedUrlOptInEnabled()) return "";
  const base = normalizeBaseUrl(import.meta.env.VITE_WEALL_LIVE_ROOM_BASE_URL);
  return isSelfHostedOrAccessControlled(base) ? base : "";
}

export function liveRoomEmbedEnabled(): boolean {
  if (liveRoomTransportMode() !== "centralized-url") return false;
  const raw = String(import.meta.env.VITE_WEALL_LIVE_ROOM_EMBED || "").trim().toLowerCase();
  return raw === "1" || raw === "true" || raw === "yes" || raw === "on";
}

export function liveRoomNameFromCommitment(roomCommitment?: string | null): string {
  const clean = String(roomCommitment || "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]/g, "");
  const suffix = clean.slice(0, 24);
  return suffix ? `weall-live-${suffix}` : "";
}

export function liveRoomUrlFromCommitment(roomCommitment?: string | null, baseUrl = liveRoomBaseUrl()): string {
  if (liveRoomTransportMode() !== "centralized-url") return "";
  const roomName = liveRoomNameFromCommitment(roomCommitment);
  const base = normalizeBaseUrl(baseUrl);
  if (!roomName || !base) return "";
  return `${base}/${encodeURIComponent(roomName)}`;
}

export function liveRoomDescriptorFromCommitment(
  roomCommitment?: string | null,
): WeAllP2PLiveRoomDescriptor | null {
  const roomId = liveRoomNameFromCommitment(roomCommitment);
  const commitment = String(roomCommitment || "").trim();
  if (!roomId || !commitment) return null;
  return {
    version: "weall-live-room-v1",
    transport: "p2p-webrtc",
    authority: "weall-chain",
    room_id: roomId,
    room_commitment: commitment,
    signaling: "case-scoped-presence",
    relay_policy: "community-relay-fallback-only",
    storage_policy: "no-raw-recording-by-default",
    privacy: "subject-and-assigned-reviewers-only",
    notes: [
      "The live room is a peer-to-peer transport descriptor, not an authority source.",
      "Discovery/signaling must be case-scoped to the subject and assigned reviewers.",
      "Relay/TURN nodes are fallback transport only and cannot grant verification.",
      "Tier 2 is granted only by chain-recorded attendance, verdicts, and finalization.",
    ],
  };
}

export function liveRoomDescriptorText(roomCommitment?: string | null): string {
  const descriptor = liveRoomDescriptorFromCommitment(roomCommitment);
  return descriptor ? JSON.stringify(descriptor, null, 2) : "";
}

export function liveRoomTransportNotice(): string {
  return "This live room is decentralized peer-to-peer transport only. Discovery, relay, and media transport are non-authoritative; verification is granted only by chain-recorded attendance, reviewer verdicts, and finalization.";
}
