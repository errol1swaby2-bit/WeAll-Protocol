import { readFileSync } from 'node:fs';

const gate = readFileSync(new URL('../../Weall-Protocol/src/weall/runtime/gate_expr.py', import.meta.url), 'utf8');
const session = readFileSync(new URL('../src/auth/session.ts', import.meta.url), 'utf8');

function assertContains(haystack, needle, label) {
  if (!haystack.includes(needle)) {
    throw new Error(`missing ${label}: ${needle}`);
  }
}

assertContains(gate, 'Leaving a group is self-removal, not moderation.', 'self-leave comment');
assertContains(gate, 'return True', 'self-leave allowance');
assertContains(session, 'Never lower the', 'stale observer nonce comment');
assertContains(session, 'Math.max(getReservedNonce(acct), Math.floor(onChain))', 'non-lowering nonce sync');
assertContains(session, 'function nonceConflictNonceFromError', 'nonce conflict extraction');
assertContains(session, 'timeoutMs: 5_000', 'bounded nonce wait');

console.log('Batch 496 group leave/nonce source checks passed');
