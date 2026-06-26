import fs from 'node:fs';
import path from 'node:path';

const root = path.resolve(process.cwd());
const account = fs.readFileSync(path.join(root, 'src/pages/Account.tsx'), 'utf8');
const dashboard = fs.readFileSync(path.join(root, 'src/pages/NodeDashboard.tsx'), 'utf8');

const requiredAccount = [
  'REVIEWER_LANE_OPT_IN',
  'NODE_OPERATOR_HELPER_OPT_IN',
  'reviewerLaneLabels',
  'content_review',
  'dispute_review',
  'poh_async_review',
  'poh_live_review',
  'Helper Execution Responsibility',
  'helperOptedIn',
];

const requiredDashboard = [
  'Operator wizard',
  'Fix readiness blockers in order',
  'incidentTimeline',
  'Helper responsibility',
  'Storage/IPFS capacity',
  'Backend-derived',
];

const missing = [];
for (const needle of requiredAccount) {
  if (!account.includes(needle)) missing.push(`Account.tsx missing ${needle}`);
}
for (const needle of requiredDashboard) {
  if (!dashboard.includes(needle)) missing.push(`NodeDashboard.tsx missing ${needle}`);
}
if (account.includes('tx_type: "ROLE_JUROR_ENROLL"') && account.includes('content_review: { opted_in: true }')) {
  missing.push('Account.tsx still appears to use broad ROLE_JUROR_ENROLL lane activation');
}

if (missing.length) {
  console.error(missing.join('\n'));
  process.exit(1);
}
console.log('OK: Batch 616 responsibility control surface source checks passed');
