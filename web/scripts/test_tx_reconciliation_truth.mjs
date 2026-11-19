import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import ts from "typescript";

const source = readFileSync(new URL("../src/lib/txReconciliation.ts", import.meta.url), "utf8");
const compiled = ts.transpileModule(source, {
  compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022, strict: true },
}).outputText;
const { describeReadModelObservation } = await import(
  `data:text/javascript;base64,${Buffer.from(compiled).toString("base64")}`
);

const txId = "tx:canonical-original";
assert.equal(describeReadModelObservation(txId, null), null);

for (const phase of ["confirmed", "submitted", "failed", "unknown"]) {
  const observed = describeReadModelObservation(txId, { phase, detail: "Local object is visible." });
  assert.equal(observed.txId, txId, `${phase} may not change canonical identity`);
  assert.notEqual(observed.status, "confirmed", `${phase} may not independently finalize`);
  assert.notEqual(observed.status, "failed", `${phase} is not a canonical rejection`);
  assert.match(observed.detail, /transaction|signed action|canonical/i);
}

const seen = describeReadModelObservation(txId, { phase: "confirmed", txId });
assert.equal(seen.status, "refreshing");
assert.equal(seen.keepPolling, true, "domain object visible -> keep checking original receipt");
assert.match(seen.detail, /successful canonical apply receipt/);

const legacyFailure = describeReadModelObservation(txId, { phase: "failed" });
assert.equal(legacyFailure.status, "recorded", "domain failure is not a signed failed-apply receipt");
assert.equal(legacyFailure.keepPolling, true);

const mismatch = describeReadModelObservation(txId, {
  phase: "confirmed", txId: "tx:different-action",
});
assert.equal(mismatch.status, "recorded", "mismatched tx id fails closed");
assert.equal(mismatch.keepPolling, false);
assert.equal(mismatch.txId, txId);
assert.match(mismatch.detail, /different action ID/);

const unknown = describeReadModelObservation(txId, { phase: "unknown" });
assert.equal(unknown.keepPolling, false);

const provider = readFileSync(new URL("../src/components/TxQueueProvider.tsx", import.meta.url), "utf8");
const reconcileStart = provider.indexOf("  const applyReconciledPhase = useCallback(");
const reconcileEnd = provider.indexOf("  const monitorFinality = useCallback(", reconcileStart);
assert.ok(reconcileStart > -1 && reconcileEnd > reconcileStart);
const reconcileCode = provider.slice(reconcileStart, reconcileEnd);
assert.ok(reconcileCode.includes("describeReadModelObservation"), "Provider must use validated nonterminal reconciliation");
assert.ok(!reconcileCode.includes("markSuccess"), "Read-model callback may not mark success");
assert.ok(!reconcileCode.includes('mutationFromArgs(mutation, "confirmed"'), "Read-model callback may not issue confirmed mutation");
assert.ok(!reconcileCode.includes("markError"), "Domain rejection may not impersonate apply failure");

const monitorStart = provider.indexOf("  const monitorFinality = useCallback(");
const monitorEnd = provider.indexOf("  const runTx = useCallback(", monitorStart);
assert.ok(monitorStart > -1 && monitorEnd > monitorStart);
const monitorCode = provider.slice(monitorStart, monitorEnd);
assert.ok(monitorCode.includes("normalized.phase === \"confirmed\""), "Canonical success must be handled");
assert.ok(monitorCode.includes("normalized.phase === \"failed\""), "Canonical rejected receipt must be terminal failed");
assert.ok(monitorCode.includes("markError(args.id"), "Rejected receipt must render a failed toast");
assert.ok(monitorCode.includes("weall.txStatus(args.txId, base)"), "Late reconciliation must re-read original tx id");
assert.ok(!monitorCode.includes("secondReconcile"), "Repeated domain reads alone may not claim finality");

const noIdStart = provider.indexOf("        } else if (!txId) {");
const noIdEnd = provider.indexOf("\n        return result;", noIdStart);
assert.ok(noIdStart > -1 && noIdEnd > noIdStart);
const noIdCode = provider.slice(noIdStart, noIdEnd);
assert.ok(noIdCode.includes("markRecorded"), "Submission without tx ID stays unverified");
assert.ok(!noIdCode.includes("markSuccess"), "No-ID path may not report final success");
assert.ok(!noIdCode.includes('\"confirmed\"'), "No-ID path may not emit a confirmed mutation");

console.log("OK: all reconciliation routes remain pending without canonical receipts");
