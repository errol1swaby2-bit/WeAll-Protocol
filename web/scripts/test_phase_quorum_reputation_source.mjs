import fs from 'node:fs';

function read(path) {
  return fs.readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');
}

const files = {
  api: read('src/api/weall.ts'),
  proposal: read('src/pages/Proposal.tsx'),
  dispute: read('src/pages/DisputeDetail.tsx'),
  account: read('src/pages/Account.tsx'),
};

const checks = [
  [files.api.includes('proposalPhaseStatus'), 'API client must expose proposalPhaseStatus'],
  [files.api.includes('/v1/gov/proposals/${encodeURIComponent(id)}/phase-status'), 'API client must use governance phase-status endpoint'],
  [files.api.includes('disputePhaseStatus'), 'API client must expose disputePhaseStatus'],
  [files.api.includes('/v1/disputes/${encodeURIComponent(id)}/phase-status'), 'API client must use dispute phase-status endpoint'],
  [files.api.includes('accountReputationProgressionStatus'), 'API client must expose reputation progression status'],
  [files.proposal.includes('Quorum progress:'), 'Proposal UI must show quorum progress'],
  [files.proposal.includes('Ends at block'), 'Proposal UI must explain block-height or quorum ending'],
  [files.proposal.includes('phase-open eligible snapshot stays fixed'), 'Proposal UI must explain fixed eligible snapshot'],
  [files.proposal.includes('online users are not a quorum denominator'), 'Proposal UI must reject online-user quorum'],
  [files.dispute.includes('Quorum progress:'), 'Dispute UI must show quorum progress'],
  [files.dispute.includes('phase-open eligible snapshot'), 'Dispute UI must label phase-open snapshot'],
  [files.dispute.includes('phase-status quorum'), 'Dispute UI must use backend phase-status quorum wording'],
  [files.account.includes('Reputation progress'), 'Account UI must show reputation progress'],
  [files.account.includes('Meaningful actions available without spam'), 'Account UI must avoid spammy reputation guidance'],
  [files.account.includes('Daily/epoch reputation cap reached'), 'Account UI must show capped reputation actions'],
  [files.account.includes('This action does not increase reputation again'), 'Account UI must explain repeated action cap/dedupe'],
];

const failed = checks.filter(([ok]) => !ok).map(([, message]) => message);
if (failed.length) {
  console.error(failed.join('\n'));
  process.exit(1);
}
console.log('OK: phase quorum and reputation progression source checks passed');
