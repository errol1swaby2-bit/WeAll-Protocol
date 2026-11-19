/**
 * Browser-memory-only practice for the current group election read model.
 * Never sign, serialize, persist, transmit or claim secrecy for these rankings.
 * The present canonical signed ballot envelope contains BOTH voter and ranking.
 */
export type BallotPlanningElection = {
  election_id: string;
  group_id: string;
  status: string;
  source: string;
  candidates: string[] | null;
  observed_height: number | null;
  start_height: number | null;
  end_height: number | null;
  ballot_transport_disclosure?: string;
  ballot_transport_privacy_verified?: boolean;
  secret_ballot_supported?: boolean;
  ballot_submission_authorized?: boolean;
};

export type LocalBallotPlanningGate = {
  canPrepare: boolean;
  canSubmit: false;
  explanation: string;
};

const REQUIRED_DISCLOSURE = "signed_envelope_contains_signer_and_plaintext_ranking";

export function localBallotPlanningGate(
  election: BallotPlanningElection | null,
  groupId: string,
): LocalBallotPlanningGate {
  const blocked = (explanation: string): LocalBallotPlanningGate =>
    ({ canPrepare: false, canSubmit: false, explanation });
  if (!election || !groupId.trim() || election.group_id !== groupId ||
      !election.election_id.trim() ||
      election.source !== "canonical_group_emissary_elections_snapshot") {
    return blocked("The election identity or canonical group scope is not verified.");
  }
  if (election.ballot_transport_disclosure !== REQUIRED_DISCLOSURE ||
      election.ballot_transport_privacy_verified !== false ||
      election.secret_ballot_supported !== false ||
      election.ballot_submission_authorized !== false) {
    return blocked("The required no-submission privacy disclosure is missing or inconsistent.");
  }
  if (election.status !== "open") {
    return blocked("This election is not open in the returned canonical record.");
  }
  const candidates = election.candidates;
  if (!Array.isArray(candidates) || !candidates.length ||
      candidates.some(item => typeof item !== "string" || !item.trim()) ||
      new Set(candidates).size !== candidates.length) {
    return blocked("Canonical candidate IDs are unavailable, empty or ambiguous.");
  }
  const heights = [election.observed_height, election.start_height, election.end_height];
  if (!heights.every(value => typeof value === "number" && Number.isSafeInteger(value) && value >= 0)) {
    return blocked("The election's canonical block-height window is incomplete.");
  }
  const [observed, start, end] = heights as number[];
  if (end <= start || observed < start || observed >= end) {
    return blocked("This observed block height is outside the election window.");
  }
  return {
    canPrepare: true,
    canSubmit: false,
    explanation: "Local ranking practice only. A signed transaction would disclose the voter and plaintext ranking.",
  };
}

export function rankCandidate(ranking: readonly string[], candidate: string, allowed: readonly string[]): string[] {
  if (!allowed.includes(candidate) || ranking.includes(candidate)) return [...ranking];
  return [...ranking, candidate];
}

export function unrankCandidate(ranking: readonly string[], candidate: string): string[] {
  return ranking.filter(entry => entry !== candidate);
}

export function moveRankedCandidate(
  ranking: readonly string[], candidate: string, direction: -1 | 1,
): string[] {
  const i = ranking.indexOf(candidate);
  const target = i + direction;
  if (i < 0 || target < 0 || target >= ranking.length) return [...ranking];
  const moved = [...ranking];
  [moved[i], moved[target]] = [moved[target], moved[i]];
  return moved;
}
