const DEFAULT_SELF_HOSTED_ROOM_BASE_URL = "";

function normalizeBaseUrl(raw?: string): string {
  const value = String(raw || "").trim().replace(/\/+$/, "");
  if (!value) return DEFAULT_SELF_HOSTED_ROOM_BASE_URL;
  return value;
}

export function liveRoomBaseUrl(): string {
  return normalizeBaseUrl(import.meta.env.VITE_WEALL_LIVE_ROOM_BASE_URL);
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
  const roomName = liveRoomNameFromCommitment(roomCommitment);
  const base = normalizeBaseUrl(baseUrl);
  if (!roomName || !base) return "";
  return `${base}/${encodeURIComponent(roomName)}`;
}

export function liveRoomTransportNotice(): string {
  return "This live room is self-hosted transport only. Verification is granted only by chain-recorded attendance, juror verdicts, and finalization.";
}
