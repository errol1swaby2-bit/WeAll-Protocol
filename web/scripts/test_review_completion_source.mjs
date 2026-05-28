#!/usr/bin/env node
import fs from 'node:fs';

function read(path) {
  return fs.readFileSync(path, 'utf8');
}

function assert(condition, message) {
  if (!condition) {
    console.error(`FAIL: ${message}`);
    process.exit(1);
  }
}

const dispute = read('src/pages/DisputeDetail.tsx');
const pending = read('src/lib/pendingWork.ts');
const juror = read('src/pages/JurorDashboard.tsx');

assert(dispute.includes('const headers = account ? getAuthHeaders(account) : undefined;'), 'Dispute detail must build viewer auth headers before loading dispute detail.');
assert(dispute.includes('weall.dispute(id, apiBase, headers)'), 'Dispute detail must load dispute detail with viewer auth headers.');
assert(dispute.includes('weall.disputeVotes(id, apiBase, headers)'), 'Dispute detail must load dispute votes with viewer auth headers.');
assert(pending.includes('function reportStageNeedsReviewerAction'), 'Pending work must distinguish reviewer-actionable stages from appeal/history stages.');
assert(pending.includes('if (vote || !reportStageNeedsReviewerAction(stage)) return null;'), 'Pending work must remove already-voted and non-reviewer-actionable reports.');
assert(juror.includes('function reportNeedsCurrentReviewer'), 'Juror dashboard must centralize active reviewer report filtering.');
assert(juror.includes('if (disputeCurrentVote(item, account)) return false;'), 'Juror dashboard must hide already-voted reports from active queue.');
assert(juror.includes('if (!reportStageNeedsReviewerAction(item?.stage || item?.status)) return false;'), 'Juror dashboard must hide appeal/final/history reports from active queue.');

console.log('review completion source checks passed');
