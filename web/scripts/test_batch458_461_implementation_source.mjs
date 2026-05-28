import fs from 'node:fs';
import path from 'node:path';

const root = path.resolve(process.cwd(), '..');
const read = (p) => fs.readFileSync(path.join(root, p), 'utf8');

const economics = read('Weall-Protocol/src/weall/api/routes_public_parts/economics.py');
const consensus = read('Weall-Protocol/src/weall/api/routes_public_parts/consensus.py');
const crypto = read('web/src/lib/messageCrypto.ts');
const messaging = read('web/src/pages/Messaging.tsx');
const live = read('web/src/pages/LiveVerificationRoom.tsx');

const checks = [
  [economics.includes('/economics/activation/readiness'), 'missing activation readiness route'],
  [economics.includes('/economics/transfer/preview'), 'missing transfer preview route'],
  [economics.includes('/treasury/status'), 'missing treasury status route'],
  [consensus.includes('/consensus/block-production/proof'), 'missing block proof route'],
  [crypto.includes('exportMessagingIdentityBackup'), 'missing key backup export'],
  [crypto.includes('importMessagingIdentityBackup'), 'missing key backup import'],
  [crypto.includes('revokeLocalMessagingDevice'), 'missing local device revocation'],
  [messaging.includes('Device key lifecycle'), 'missing messaging device UI'],
  [live.includes('TURN / relay config'), 'missing TURN config UI'],
  [live.includes('iceServerDiagnostics'), 'missing ICE diagnostics'],
];

for (const [ok, msg] of checks) {
  if (!ok) throw new Error(msg);
}
console.log('batch458-461 implementation source checks passed');
