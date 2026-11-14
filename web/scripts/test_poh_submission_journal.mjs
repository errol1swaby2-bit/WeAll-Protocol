import assert from "node:assert/strict";
import {
  clearReconciledPohJournal,
  pohJournalKey,
  readPohSubmissionJournal,
  savePohSubmissionJournal,
} from "../src/lib/pohSubmissionJournal.ts";

const data = new Map();
let blockWrites = false;
globalThis.localStorage = {
  getItem(key) {
    return data.has(key) ? data.get(key) : null;
  },
  setItem(key, value) {
    if (blockWrites) throw new Error("storage disabled");
    data.set(key, value);
  },
  removeItem(key) {
    if (blockWrites) throw new Error("storage disabled");
    data.delete(key);
  },
};

const alice = "@alice_poh_journal";
const base = "https://original.node.example";
assert.deepEqual(readPohSubmissionJournal(alice, "async"), { status: "none" });

const started = savePohSubmissionJournal({
  account: alice,
  nodeBase: base + "/",
  kind: "async",
  phase: "upload_started",
  caseId: "pohasync:alice_poh_journal:async-EXAMPLE",
});
assert.equal(started.nodeBase, base);
assert.equal(started.txId, "");
const raw = data.get(pohJournalKey(alice, "async"));
assert.deepEqual(Object.keys(JSON.parse(raw)).sort(), [
  "account", "caseId", "kind", "nodeBase", "phase", "txId", "updatedAtMs", "version",
].sort());
assert.ok(!raw.includes("privateKey"));
assert.ok(!raw.includes("evidence_cid"));
assert.ok(!raw.includes("ciphertext"));
assert.ok(!raw.includes("video"));

const uploaded = savePohSubmissionJournal({
  account: alice,
  nodeBase: base,
  kind: "async",
  phase: "encrypted_uploaded",
  caseId: started.caseId,
});
assert.equal(uploaded.phase, "encrypted_uploaded");
assert.throws(() => savePohSubmissionJournal({
  account: alice,
  nodeBase: base,
  kind: "async",
  phase: "upload_started",
  caseId: "pohasync:alice_poh_journal:async-OTHER",
}), /poh_journal_reconciliation_required/);
assert.throws(() => savePohSubmissionJournal({
  account: alice,
  nodeBase: "https://another.node.example",
  kind: "async",
  phase: "signed_started",
  caseId: started.caseId,
}), /poh_journal_reconciliation_required/);

assert.equal(clearReconciledPohJournal(alice, "async", base, "some-other-case"), false);
assert.equal(clearReconciledPohJournal(alice, "async", "https://another.node.example", started.caseId), false);
assert.equal(readPohSubmissionJournal(alice, "async").status, "pending");
assert.equal(clearReconciledPohJournal(alice, "async", base, started.caseId), true);
assert.deepEqual(readPohSubmissionJournal(alice, "async"), { status: "none" });

// Live requests start before a case identifier can be derived from a signed nonce.
savePohSubmissionJournal({
  account: alice,
  nodeBase: base,
  kind: "live",
  phase: "signed_started",
  caseId: "",
});
assert.equal(clearReconciledPohJournal(alice, "live", base, "made-up-id"), false);
const txId = "tx:" + "a".repeat(64);
savePohSubmissionJournal({
  account: alice,
  nodeBase: base,
  kind: "live",
  phase: "signed_returned",
  caseId: "pohlive:alice_poh_journal:13",
  txId,
});
assert.equal(readPohSubmissionJournal(alice, "live").record?.txId, txId);
assert.equal(readPohSubmissionJournal("@bob_poh_journal", "live").status, "none");
assert.equal(clearReconciledPohJournal(alice, "live", base, "pohlive:alice_poh_journal:13"), true);

// Unknown/malformed and storage-denied states must fail closed, never empty.
const key = pohJournalKey(alice, "async");
data.set(key, "{not valid JSON");
assert.equal(readPohSubmissionJournal(alice, "async").status, "unavailable");
assert.throws(() => savePohSubmissionJournal({
  account: alice,
  nodeBase: base,
  kind: "async",
  phase: "upload_started",
  caseId: "new-case",
}), /poh_journal_unavailable/);
data.delete(key);
blockWrites = true;
assert.throws(() => savePohSubmissionJournal({
  account: alice,
  nodeBase: base,
  kind: "async",
  phase: "upload_started",
  caseId: "new-case",
}), /poh_journal_write_unavailable/);
blockWrites = false;

console.log("PASS: non-secret PoH interrupted submission journal, scope and fail-closed reconciliation");
