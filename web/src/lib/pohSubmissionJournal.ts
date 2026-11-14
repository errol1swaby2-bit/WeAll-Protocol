/**
 * Non-secret, account-scoped PoH submission warning journal.
 *
 * This journal is a UX safety interlock, NOT an on-chain receipt, durable
 * evidence backup, nonce allocator or proof that a transaction was admitted.
 * It deliberately persists no video, challenge phrase, key, ciphertext CID,
 * signature, token, session bearer or encryption envelope.
 *
 * A browser crash after an external request is indeterminate: the caller
 * must reconcile the original case through a trusted node, never auto-retry.
 */
export type PohJournalKind = "async" | "live";
export type PohJournalPhase =
  | "upload_started"
  | "encrypted_uploaded"
  | "signed_started"
  | "signed_returned";

export type PohSubmissionJournal = {
  version: 1;
  account: string;
  nodeBase: string;
  kind: PohJournalKind;
  phase: PohJournalPhase;
  caseId: string;
  txId: string;
  updatedAtMs: number;
};

export type PohJournalRead =
  | { status: "none" }
  | { status: "pending"; record: PohSubmissionJournal }
  | { status: "unavailable" };

const PREFIX = "weall.poh_submission_pending_v1::";
const PHASES: ReadonlySet<string> = new Set([
  "upload_started",
  "encrypted_uploaded",
  "signed_started",
  "signed_returned",
]);

export function pohJournalKey(account: string, kind: PohJournalKind): string {
  const safeAccount = String(account || "").trim();
  if (!safeAccount || !["async", "live"].includes(kind)) throw new Error("invalid_poh_journal_scope");
  return PREFIX + kind + "::" + encodeURIComponent(safeAccount);
}

export function normalizePohJournalBase(base: string): string {
  const raw = String(base || "").trim();
  return raw === "/" ? "/" : raw.replace(/\/+$/, "");
}

function validRecord(value: unknown, account: string, kind: PohJournalKind): value is PohSubmissionJournal {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  return (
    record.version === 1 &&
    record.account === account &&
    record.kind === kind &&
    typeof record.nodeBase === "string" &&
    record.nodeBase.length > 0 &&
    record.nodeBase.length < 2048 &&
    typeof record.phase === "string" &&
    PHASES.has(record.phase) &&
    typeof record.caseId === "string" &&
    record.caseId.length < 512 &&
    (record.caseId.length > 0 || kind === "live") &&
    typeof record.txId === "string" &&
    (record.txId === "" || /^tx:[0-9a-f]{64}$/.test(record.txId)) &&
    typeof record.updatedAtMs === "number" &&
    Number.isSafeInteger(record.updatedAtMs) &&
    record.updatedAtMs > 0
  );
}

export function readPohSubmissionJournal(account: string, kind: PohJournalKind): PohJournalRead {
  try {
    const key = pohJournalKey(account, kind);
    const raw = localStorage.getItem(key);
    if (raw === null) return { status: "none" };
    const parsed: unknown = JSON.parse(raw);
    if (!validRecord(parsed, account, kind)) return { status: "unavailable" };
    // Rebuild a whitelisted record; unknown or secret fields are never propagated.
    return {
      status: "pending",
      record: {
        version: 1,
        account,
        nodeBase: parsed.nodeBase,
        kind,
        phase: parsed.phase,
        caseId: parsed.caseId,
        txId: parsed.txId,
        updatedAtMs: parsed.updatedAtMs,
      },
    };
  } catch {
    // Storage denied/corrupt is unknown, not permission to submit.
    return { status: "unavailable" };
  }
}

export function savePohSubmissionJournal(input: {
  account: string;
  nodeBase: string;
  kind: PohJournalKind;
  phase: PohJournalPhase;
  caseId: string;
  txId?: string;
}): PohSubmissionJournal {
  const { account, kind } = input;
  const prior = readPohSubmissionJournal(account, kind);
  if (prior.status === "unavailable") throw new Error("poh_journal_unavailable");
  const nodeBase = normalizePohJournalBase(input.nodeBase);
  const caseId = String(input.caseId || "").trim();
  const txId = String(input.txId || "").trim();
  if (!nodeBase || !PHASES.has(input.phase) || (kind === "async" && !caseId)) {
    throw new Error("invalid_poh_journal_entry");
  }
  if (prior.status === "pending" && (
    prior.record.nodeBase !== nodeBase ||
    (prior.record.caseId && prior.record.caseId !== caseId)
  )) {
    throw new Error("poh_journal_reconciliation_required");
  }
  const next: PohSubmissionJournal = {
    version: 1,
    account,
    nodeBase,
    kind,
    phase: input.phase,
    caseId,
    txId: txId || (prior.status === "pending" ? prior.record.txId : ""),
    updatedAtMs: Date.now(),
  };
  if (!validRecord(next, account, kind)) throw new Error("invalid_poh_journal_entry");
  try {
    localStorage.setItem(pohJournalKey(account, kind), JSON.stringify(next));
  } catch {
    throw new Error("poh_journal_write_unavailable");
  }
  const saved = readPohSubmissionJournal(account, kind);
  if (saved.status !== "pending" || saved.record.caseId !== caseId || saved.record.phase !== input.phase) {
    throw new Error("poh_journal_write_unavailable");
  }
  return saved.record;
}

/**
 * Clear only after the caller has observed this exact case in a successful
 * canonical history response from the same configured node, or upon a real
 * authoritative account-tier advancement. Never clear on empty, timeout,
 * HTTP 202, client success, a local expected ID, or a failed status read.
 */
export function clearReconciledPohJournal(
  account: string,
  kind: PohJournalKind,
  nodeBase: string,
  confirmedCaseId: string,
): boolean {
  const current = readPohSubmissionJournal(account, kind);
  if (current.status !== "pending") return false;
  if (!confirmedCaseId || current.record.caseId !== confirmedCaseId) return false;
  if (current.record.nodeBase !== normalizePohJournalBase(nodeBase)) return false;
  try {
    localStorage.removeItem(pohJournalKey(account, kind));
    return readPohSubmissionJournal(account, kind).status === "none";
  } catch {
    return false;
  }
}
