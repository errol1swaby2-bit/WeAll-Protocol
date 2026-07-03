import fs from 'node:fs';

const dashboard = fs.readFileSync(new URL('../src/pages/NodeDashboard.tsx', import.meta.url), 'utf8');
const transactions = fs.readFileSync(new URL('../src/pages/TransactionsPage.tsx', import.meta.url), 'utf8');
const api = fs.readFileSync(new URL('../src/api/weall.ts', import.meta.url), 'utf8');

const requiredDashboard = [
  'publicBetaBlockerReport',
  'Public beta blockers',
  'Public beta remains blocked',
  'Public beta blocker snapshot',
  'Blocked capabilities',
  'Next allowed claim',
  'Governance lifecycle clock',
  'Dispute lifecycle clock',
  'Reviewer civic loop',
];
const requiredTransactions = [
  'lifecycleSteps',
  'Accepted locally',
  'Gossiped / pending',
  'Included in block',
  'Finalized',
  'Removed from mempool',
  'Propagation lifecycle',
];
const requiredApi = [
  '/v1/status/testnet-capabilities',
  '/v1/status/launch-matrix',
  '/v1/status/mempool',
];

const missing = [];
for (const token of requiredDashboard) if (!dashboard.includes(token)) missing.push(`NodeDashboard missing ${token}`);
for (const token of requiredTransactions) if (!transactions.includes(token)) missing.push(`TransactionsPage missing ${token}`);
for (const token of requiredApi) if (!api.includes(token)) missing.push(`weall api missing ${token}`);

if (missing.length) {
  console.error(missing.join('\n'));
  process.exit(1);
}
console.log('OK: Batch 618 public beta blocker and tx propagation source checks passed');
