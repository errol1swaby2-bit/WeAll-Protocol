import { readFileSync } from 'node:fs';

function read(path) {
  return readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');
}

const proposal = read('src/pages/Proposal.tsx');
const dispute = read('src/pages/DisputeDetail.tsx');
const timeline = read('src/components/ProcedureTimeline.tsx');
const clock = read('src/lib/procedureClock.ts');

const checks = [
  [proposal.includes('ProcedureTimeline'), 'Proposal detail must render the constitutional procedure timeline.'],
  [proposal.includes('Version history') && proposal.includes('Deliberation comments'), 'Proposal detail must expose version history and deliberation comments.'],
  [proposal.includes('frozen_version') || proposal.includes('Frozen voting version'), 'Proposal detail must surface the frozen voting version.'],
  [proposal.includes('GOV_PROPOSAL_COMMENT') && proposal.includes('submitProposalComment') && proposal.includes('Submit comment'), 'Proposal detail must let users submit protocol-visible deliberation comments.'],
  [dispute.includes('ProcedureTimeline'), 'Dispute detail must render the constitutional procedure timeline.'],
  [dispute.includes('appeal_deadline_height') && dispute.includes('Appeals filed'), 'Dispute detail must expose appeal deadline and appeal records.'],
  [dispute.includes('DISPUTE_APPEAL') && dispute.includes('fileAppeal') && dispute.includes('File appeal'), 'Dispute detail must let users file appeals during the appeal window.'],
  [timeline.includes('Finalized block height is authority'), 'Procedure timeline must state that block height, not frontend time, is authority.'],
  [clock.includes('targetBlockIntervalMs') && clock.includes('blocksRemaining'), 'Procedure clock helper must derive display from block height and target interval.'],
];

const failed = checks.filter(([ok]) => !ok).map(([, message]) => message);
if (failed.length) {
  console.error(failed.join('\n'));
  process.exit(1);
}
console.log('constitutional procedure UI source checks passed');
