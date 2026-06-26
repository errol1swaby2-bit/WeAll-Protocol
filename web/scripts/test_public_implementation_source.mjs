import fs from 'node:fs';
import path from 'node:path';

const root = path.resolve(process.cwd(), '..');
const read = (p) => fs.readFileSync(path.join(root, p), 'utf8');
const exists = (p) => fs.existsSync(path.join(root, p));

const economics = read('Weall-Protocol/src/weall/api/routes_public_parts/economics.py');
const consensus = read('Weall-Protocol/src/weall/api/routes_public_parts/consensus.py');
const live = read('web/src/pages/LiveVerificationRoom.tsx');

const checks = [
  [economics.includes('/economics/activation/readiness'), 'missing activation readiness route'],
  [economics.includes('/economics/transfer/preview'), 'missing transfer preview route'],
  [economics.includes('/treasury/status'), 'missing treasury status route'],
  [consensus.includes('/consensus/block-production/proof'), 'missing block proof route'],
  [!exists('web/src/lib/' + 'message' + 'Crypto.ts'), 'removed non-public social crypto module returned'],
  [!exists('web/src/pages/' + 'Mess' + 'aging.tsx'), 'removed non-public social page returned'],
  [live.includes('TURN / relay config'), 'missing TURN config UI'],
  [live.includes('iceServerDiagnostics'), 'missing ICE diagnostics'],
];
for (const [ok, msg] of checks) { if (!ok) throw new Error(msg); }
console.log('batch458-461 public implementation source checks passed');
