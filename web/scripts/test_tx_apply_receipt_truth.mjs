import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import ts from "typescript";

// Run the actual production normalizer without requiring a signer/local browser.
// The function is pure, so extracting its exact source preserves runtime logic.
const source = readFileSync(new URL("../src/lib/status.ts", import.meta.url), "utf8");
const start = source.indexOf("export function normalizeTxStatus(");
const end = source.indexOf("\nfunction deriveAuthorityLevel(", start);
assert.ok(start > 0 && end > start, "Canonical transaction normalizer must exist");
const isolated = source.slice(start, end);
const compiled = ts.transpileModule(isolated, {
  compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 },
}).outputText;
const { normalizeTxStatus } = await import(
  `data:text/javascript;base64,${Buffer.from(compiled).toString("base64")}`
);

const txId = "tx:sample";
function check(raw, expectedPhase, expectedTerminal, label) {
  const result = normalizeTxStatus(raw, txId);
  assert.equal(result.txId, txId, label);
  assert.equal(result.phase, expectedPhase, label);
  assert.equal(result.terminal, expectedTerminal, label);
  return result;
}

const applied = check(
  { status: "confirmed", apply_ok: true, local_state_synced: true, height: 3, block_id: "a".repeat(64) },
  "confirmed",
  true,
  "Successful canonical receipt and local synchronization",
);
assert.match(applied.detail, /successful apply receipt/);

const rejected = check(
  { status: "confirmed", apply_ok: false, local_state_synced: true, code: "apply_rejected" },
  "failed",
  true,
  "Contradictory confirmation must never hide failed apply receipt",
);
assert.match(rejected.detail, /failed|rejected/i);

for (const value of [undefined, null, "true", 1]) {
  const missing = check(
    { status: "confirmed", apply_ok: value, local_state_synced: true },
    "submitted",
    false,
    "Missing or nonboolean successful apply evidence cannot be final",
  );
  assert.match(missing.detail, /apply receipt/i);
}

check(
  { status: "confirmed", apply_ok: true, local_state_synced: false },
  "submitted",
  false,
  "Upstream confirmed but local observer state unsynchronized",
);
check(
  { status: "local_confirmed", apply_ok: true, local_state_synced: false },
  "submitted",
  false,
  "Local inclusion without upstream agreement remains non-final",
);
check({ status: "pending" }, "submitted", false, "Mempool is not confirmation");
check({ status: "rejected", apply_ok: false }, "failed", true, "Canonical rejected status");
check({ status: "failed" }, "failed", true, "Terminal failure");
check({ status: "unknown" }, "unknown", false, "No receipt evidence");
check({ status: "accepted" }, "submitted", false, "HTTP acceptance is not finality");
check({ status: "confirmed", apply_ok: false, local_state_synced: false }, "failed", true, "Failure receipt overrides sync ambiguity");

const transactions = readFileSync(new URL("../src/pages/TransactionsPage.tsx", import.meta.url), "utf8");
const mempoolRemovalRow = transactions.split("\\n").find((line) => line.includes('label: "Removed from mempool"'));
assert.ok(mempoolRemovalRow, "Lifecycle timeline must show mempool-removal status explicitly");
assert.ok(mempoolRemovalRow.includes('done: false') && mempoolRemovalRow.includes('evidence: "unavailable"'),
  "Do not claim mempool removal from confirmation without a specific removal proof");

console.log("OK: frontend transaction finality requires successful apply receipt and local sync");
