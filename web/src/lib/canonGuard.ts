// src/lib/canonGuard.ts
//
// Canon guard:
// - Caches canon_source_sha256 for the current browser tab (sessionStorage)
// - Detects mid-session changes
// - Provides an assertion helper to block writes if canon mismatches
//

const BASELINE_KEY = "weall.canon.baseline_sha256";
const MISMATCH_KEY = "weall.canon.mismatch_flag";

export type CanonObservation = {
  baseline: string;
  current: string;
  changed: boolean;
};

export function getCanonBaseline(): string | null {
  try {
    return sessionStorage.getItem(BASELINE_KEY);
  } catch {
    return null;
  }
}

export function setCanonBaseline(hash: string): void {
  try {
    sessionStorage.setItem(BASELINE_KEY, hash);
  } catch {
    // ignore storage failures (private mode / disabled storage)
  }
}

export function clearCanonBaseline(): void {
  try {
    sessionStorage.removeItem(BASELINE_KEY);
    sessionStorage.removeItem(MISMATCH_KEY);
  } catch {
    // ignore
  }
}

/**
 * Convenience: reset all canon guard state.
 */
export function resetCanonGuard(): void {
  clearCanonBaseline();
}

export function getCanonMismatchFlag(): boolean {
  try {
    return sessionStorage.getItem(MISMATCH_KEY) === "1";
  } catch {
    return false;
  }
}

function setMismatchFlag(): void {
  try {
    sessionStorage.setItem(MISMATCH_KEY, "1");
  } catch {
    // ignore
  }
}

/**
 * Observe a canon hash:
 * - If there is no baseline yet, sets it to current.
 * - If baseline differs from current, marks mismatch and returns changed=true.
 */
export function observeCanon(currentHash: string): CanonObservation {
  const current = (currentHash ?? "").trim();
  if (!current) {
    const baseline = getCanonBaseline() ?? "";
    return { baseline, current, changed: false };
  }

  const baselineExisting = getCanonBaseline();
  if (!baselineExisting) {
    setCanonBaseline(current);
    return { baseline: current, current, changed: false };
  }

  const baseline = baselineExisting.trim();
  const changed = baseline !== current;

  if (changed) setMismatchFlag();

  return { baseline, current, changed };
}

export function hasCanonMismatch(currentHash: string): boolean {
  const baseline = getCanonBaseline();
  const current = (currentHash ?? "").trim();
  if (!baseline || !current) return false;
  return baseline.trim() !== current;
}

/**
 * Use this before any write/mutation request.
 * If canon mismatched mid-session, throw to prevent unsafe writes.
 */
export function assertCanonUnchangedForWrites(currentHash: string): void {
  const baseline = getCanonBaseline();
  const current = (currentHash ?? "").trim();

  // If we don't have a baseline or current hash, we can't enforce safely.
  // We allow the write for now; callers may choose to be stricter later.
  if (!baseline || !current) return;

  if (baseline.trim() !== current) {
    setMismatchFlag();
    throw new Error(
      "Canon mismatch detected (canon_source_sha256 changed mid-session). Writes are blocked to prevent submitting transactions to an unexpected canon."
    );
  }
}
