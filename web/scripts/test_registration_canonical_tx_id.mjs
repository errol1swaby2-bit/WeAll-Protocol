import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";
import { fileURLToPath } from "node:url";
import ts from "typescript";

const webRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const source = fs.readFileSync(path.join(webRoot, "src/lib/accountSetupRegistration.ts"), "utf8");
const start = source.indexOf("function canonicalRegistrationValue(");
const end = source.indexOf("export type RegistrationStatus", start);
assert.ok(start >= 0 && end > start, "The production registration identity helpers must exist");

// Compile the actual production helpers, not a copy of their implementation.
const isolated = source.slice(start, end).replace("export async function", "async function");
const transpiled = ts.transpileModule(isolated, {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.None },
}).outputText;
const context = { crypto: webcrypto, TextEncoder };
const canonicalRegistrationTxId = vm.runInNewContext(
  transpiled + "\ncanonicalRegistrationTxId",
  context,
);
assert.equal(typeof canonicalRegistrationTxId, "function");

const first = {
  chain_id: "weall-testnet",
  tx_type: "ACCOUNT_REGISTER",
  signer: "@alice",
  nonce: 1,
  parent: null,
  payload: {
    pubkey: "MLDSA-PUBLIC",
    recovery_pubkey: "RECOVERY-KEY",
    work: { counter: 7, difficulty: 3 },
    evidence_kem_pubkey: "KEM-PUBLIC",
  },
  sig: "signature-is-not-part-of-transaction-identity",
};
const firstId = "tx:283b9c3407b4c0118e03fa768a734ec80e2e2579499f45b96b243ed91747eab5";
assert.equal(await canonicalRegistrationTxId(first), firstId);
assert.equal(
  await canonicalRegistrationTxId({ ...first, sig: "another signature", signature: { sig: "abc" } }),
  firstId,
  "Signature profile and bytes must not change canonical transaction identity",
);
assert.notEqual(
  await canonicalRegistrationTxId({ ...first, nonce: 2 }),
  firstId,
  "Nonce is committed into the transaction identity",
);
assert.notEqual(
  await canonicalRegistrationTxId({ ...first, payload: { ...first.payload, pubkey: "ANOTHER-KEY" } }),
  firstId,
  "Payload is committed into the transaction identity",
);

// This independent vector was computed from runtime/tx_id.py's Python JSON
// contract: sort_keys=True, separators=(',', ':'), ensure_ascii=False.
const unicode = {
  chain_id: "chain-β",
  tx_type: "ACCOUNT_REGISTER",
  signer: "@ab",
  nonce: 31,
  parent: "tx:abc",
  payload: { z: [true, null, "é"], a: { δ: "✓", a: 4 } },
};
assert.equal(
  await canonicalRegistrationTxId(unicode),
  "tx:d5145709d5061d59a3d31cabb0407d97ed1c7d99d1fa7990baeff8b33abaf1b3",
);
await assert.rejects(
  () => canonicalRegistrationTxId({ ...first, nonce: Number.NaN }),
  /invalid_registration_identity_envelope/,
);
await assert.rejects(
  () => canonicalRegistrationTxId({ ...first, payload: { pubkey: undefined } }),
  /invalid_registration_identity_undefined/,
);
await assert.rejects(
  () => canonicalRegistrationTxId({ ...first, tx_type: "ACCOUNT_SESSION_KEY_ISSUE" }),
  /invalid_registration_identity_envelope/,
);

console.log("F1b canonical registration transaction ID vectors passed");
