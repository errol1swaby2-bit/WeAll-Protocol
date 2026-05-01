function envString(name: string, fallback = ""): string {
  const raw = (import.meta.env[name] as string | undefined) ?? fallback;
  return String(raw ?? "").trim();
}

function envBool(name: string, fallback = false): boolean {
  const raw = envString(name, fallback ? "1" : "0").toLowerCase();
  return raw === "1" || raw === "true" || raw === "yes" || raw === "on";
}

function envInt(name: string, fallback: number): number {
  const raw = envString(name, String(fallback));
  const n = Number.parseInt(raw, 10);
  return Number.isFinite(n) ? n : fallback;
}

export function getTier2VideoUploadEnabled(): boolean {
  return envBool("VITE_WEALL_ENABLE_POH_TIER2_VIDEO_UPLOAD", false);
}

export function getBootstrapLiveEnabled(): boolean {
  return envBool("VITE_WEALL_ENABLE_BOOTSTRAP_LIVE", false);
}

export function getMediaReplicationTarget(): number {
  return Math.max(1, envInt("VITE_WEALL_MEDIA_REPLICATION_FACTOR", 2));
}

export function getDurableOperatorTarget(): number {
  return Math.max(1, envInt("VITE_WEALL_MEDIA_DURABLE_OPERATOR_COUNT", 2));
}

export function getFrontendCapabilities() {
  return {
    pohTier2VideoUploadEnabled: getTier2VideoUploadEnabled(),
    bootstrapLiveEnabled: getBootstrapLiveEnabled(),
    mediaReplicationTarget: getMediaReplicationTarget(),
    mediaDurableOperatorTarget: getDurableOperatorTarget(),
  };
}
