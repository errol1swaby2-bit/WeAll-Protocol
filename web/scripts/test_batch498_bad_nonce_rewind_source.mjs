#!/usr/bin/env node
import fs from "node:fs";

function assertIncludes(haystack, needle, message) {
  if (!haystack.includes(needle)) {
    throw new Error(message + "\nMissing: " + needle);
  }
}

function assertNotIncludes(haystack, needle, message) {
  if (haystack.includes(needle)) {
    throw new Error(message + "\nUnexpected: " + needle);
  }
}

const session = fs.readFileSync("src/auth/session.ts", "utf8");
const txAction = fs.readFileSync("src/lib/txAction.ts", "utf8");
const txFeedback = fs.readFileSync("src/lib/txFeedback.ts", "utf8");
const txQueue = fs.readFileSync("src/components/TxQueueProvider.tsx", "utf8");

assertIncludes(
  session,
  'payload?.error?.details?.details?.details',
  "bad_nonce parser must inspect the nested backend shape that carries expected/got",
);

assertIncludes(
  session,
  'candidate?.expected ?? nestedDetails?.expected',
  "bad_nonce parser must read expected from nested details",
);

assertIncludes(
  session,
  'candidate?.got ?? nestedDetails?.got',
  "bad_nonce parser must read got from nested details",
);

assertIncludes(
  session,
  'setReservedNonce(signer, hint.expected - 1);',
  "nonce rewind must lower the browser reservation to expected-1",
);

const nonceActionBlock = txAction.slice(txAction.indexOf('["bad_nonce"'), txAction.indexOf('if (code === "signer_submission_busy"'));
assertIncludes(
  nonceActionBlock,
  '"backend_failure"',
  "actionable nonce errors must not be displayed as recorded backend actions",
);
assertNotIncludes(
  nonceActionBlock,
  '"recorded_not_yet_visible"',
  "actionable nonce errors must not keep the action in recorded/updating state",
);

const nonceFeedbackBlock = txFeedback.slice(txFeedback.indexOf('code.includes("nonce")'), txFeedback.indexOf('if (\n    code.includes("duplicate_submission_blocked")'));
assertIncludes(
  nonceFeedbackBlock,
  '"backend_failure"',
  "toast feedback must classify nonce errors as failed/retryable, not recorded",
);
assertNotIncludes(
  nonceFeedbackBlock,
  '"recorded_not_yet_visible"',
  "toast feedback must not mark nonce failures as recorded",
);

const sessionRepairBlock = txQueue.slice(txQueue.indexOf("function shouldAttemptSessionRepair"), txQueue.indexOf("function isTransientToastStatus"));
assertIncludes(
  sessionRepairBlock,
  'code.includes("nonce")',
  "session repair must explicitly ignore nonce errors before generic 403 repair",
);
assertIncludes(
  sessionRepairBlock,
  "return false;",
  "session repair must not convert bad_nonce 403 into a session reissue path",
);

console.log("Batch 498 bad nonce rewind source checks passed");
