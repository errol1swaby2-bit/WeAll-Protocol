/**
 * URL stages are navigational presentation only. They never confer PoH tier,
 * case finality, reviewer access or permission to replay a signed request.
 * All sensitive evidence remains in memory and is NOT written to route/URL.
 */
export type AsyncPohGuideStep = "explain" | "prepare" | "record" | "review" | "submit" | "track";
export type LivePohGuideStep = "explain" | "request" | "track";

const ASYNC_PREFIX = "/verification/async/";
const LIVE_PREFIX = "/verification/live/journey/";

const ASYNC_STAGES: ReadonlySet<string> = new Set(["explain", "prepare", "record", "review", "submit", "track"]);
const LIVE_STAGES: ReadonlySet<string> = new Set(["explain", "request", "track"]);

export function asyncPohRoute(step: AsyncPohGuideStep): string {
  return ASYNC_PREFIX + step;
}

export function livePohRoute(step: LivePohGuideStep): string {
  return LIVE_PREFIX + step;
}

export function parseAsyncPohRoute(path: string): AsyncPohGuideStep | null {
  const clean = String(path || "").split("?")[0];
  const segment = clean.startsWith(ASYNC_PREFIX) ? clean.slice(ASYNC_PREFIX.length) : "";
  return ASYNC_STAGES.has(segment) ? segment as AsyncPohGuideStep : null;
}

export function parseLivePohJourneyRoute(path: string): LivePohGuideStep | null {
  const clean = String(path || "").split("?")[0];
  const segment = clean.startsWith(LIVE_PREFIX) ? clean.slice(LIVE_PREFIX.length) : "";
  return LIVE_STAGES.has(segment) ? segment as LivePohGuideStep : null;
}

export type AsyncPohRouteReadiness = {
  basicAccountCreated: boolean;
  prepared: boolean;
  recordedValid: boolean;
  consentAndEvidenceValid: boolean;
  pendingJournal: boolean;
  recordingActive: boolean;
};

/**
 * Direct links and browser history cannot resurrect missing in-memory video.
 * A pending journal sends the user to track, never to a new signed request.
 * A browser-back attempt during active capture cannot abandon controls.
 */
export function allowedAsyncPohStep(
  requested: AsyncPohGuideStep,
  readiness: AsyncPohRouteReadiness,
): AsyncPohGuideStep {
  if (readiness.pendingJournal) return "track";
  if (readiness.recordingActive) return "record";
  if (requested === "explain" || requested === "track") return requested;
  if (!readiness.basicAccountCreated) return "explain";
  if (requested === "prepare") return requested;
  if (!readiness.prepared) return "prepare";
  if (requested === "record") return requested;
  if (!readiness.recordedValid) return "record";
  if (requested === "review") return requested;
  if (requested === "submit" && readiness.consentAndEvidenceValid) return requested;
  return "review";
}

export function allowedLivePohStep(
  requested: LivePohGuideStep,
  tier: number,
  pendingJournal: boolean,
  requestBusy: boolean,
): LivePohGuideStep {
  if (pendingJournal || requestBusy) return "track";
  if (requested === "explain" || requested === "track") return requested;
  return tier >= 1 && tier < 2 ? "request" : "explain";
}
