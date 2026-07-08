import fs from 'node:fs';

function read(path) {
  return fs.readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');
}

function assertIncludes(src, needle, label) {
  if (!src.includes(needle)) throw new Error(`${label}: missing ${needle}`);
}

const account = read('src/pages/Account.tsx');
const api = read('src/api/weall.ts');
const session = read('src/auth/session.ts');
const keys = read('src/auth/keys.ts');

for (const token of [
  'accountOperatorPromotionStatus',
  '/operator-promotion-status',
  'backend operator-promotion-status',
  'Generate node key',
  'Register node device',
  'Submit node-operator enrollment',
  'Waiting for protocol activation',
  'Baseline active',
  'Validator opt-in available',
  'Validator opt-in recorded; readiness/reputation pending',
  'Storage opt-in recorded; capacity proof pending',
  'Production service reboot available',
  'Validator reboot blocked until authority active',
]) {
  assertIncludes(account + api, token, 'operator promotion state source');
}

for (const token of [
  'submitSignedTx',
  'canonicalTxMessage',
  'BROWSER_PQ_SIG_PROFILE',
  'pq-mldsa-v1',
]) {
  assertIncludes(session + keys, token, 'browser account-authority signing path');
}

console.log('OK: operator promotion state source checks passed');
