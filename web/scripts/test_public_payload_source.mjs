import fs from 'node:fs';
import path from 'node:path';

const root = path.resolve(process.cwd(), '..');
const read = (p) => fs.readFileSync(path.join(root, p), 'utf8');
const exists = (p) => fs.existsSync(path.join(root, p));

const identity = read('Weall-Protocol/src/weall/runtime/apply/identity.py');
const policy = read('Weall-Protocol/src/weall/runtime/public_protocol_policy.py');
const schema = read('Weall-Protocol/src/weall/runtime/tx_schema.py');

if (!policy.includes('OPAQUE_PROTOCOL_PAYLOAD_UNSUPPORTED')) throw new Error('missing public payload policy code');
if (!policy.includes('PUBLIC_READ_VISIBILITY_REQUIRED')) throw new Error('missing public read policy code');
if (!identity.includes('public_protocol_policy_violation')) throw new Error('identity applier must enforce public payload policy directly');
if (schema.includes(['DIRECT','MESSAGE'].join('_'))) throw new Error('tx schema must not retain removed communication tx models');
if (exists('web/src/lib/' + 'message' + 'Crypto.ts')) throw new Error('removed non-public social crypto module returned');
if (exists('web/src/pages/' + 'Mess' + 'aging.tsx')) throw new Error('removed non-public social page returned');

console.log('batch450 public payload source checks passed');
