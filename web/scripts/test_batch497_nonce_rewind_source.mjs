import fs from "node:fs";

const src = fs.readFileSync(new URL("../src/auth/session.ts", import.meta.url), "utf8");

const required = [
  "type NonceConflictHint",
  "function nonceConflictHintFromError",
  "function rewindNonceReservationFromError",
  "hint.expected > 0 && hint.got > hint.expected",
  "setReservedNonce(signer, hint.expected - 1)",
  "const rewoundNext = rewindNonceReservationFromError(signer, error)",
];

for (const needle of required) {
  if (!src.includes(needle)) {
    throw new Error(`missing Batch 497 nonce rewind source marker: ${needle}`);
  }
}

console.log("Batch 497 nonce rewind source checks passed");
