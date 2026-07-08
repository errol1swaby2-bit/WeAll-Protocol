import fs from 'node:fs';

function read(path) {
  return fs.readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');
}
function assertIncludes(src, needle, label) {
  if (!src.includes(needle)) {
    throw new Error(`${label} missing ${needle}`);
  }
}
function assertOrdered(src, first, second, label) {
  const a = src.indexOf(first);
  const b = src.indexOf(second);
  if (a < 0 || b < 0 || a >= b) {
    throw new Error(`${label} expected ${first} before ${second}`);
  }
}

const systemTxEngine = fs.readFileSync(new URL('../../Weall-Protocol/src/weall/runtime/system_tx_engine.py', import.meta.url), 'utf8');
assertIncludes(systemTxEngine, 'schedule_content_review_assignment_system_txs', 'system scheduler');
assertIncludes(systemTxEngine, 'CONTENT_REVIEW_LANE', 'system scheduler');
assertIncludes(systemTxEngine, 'eligible_reviewer_ids', 'system scheduler');
assertIncludes(systemTxEngine, 'content_review_assignment_scheduler', 'system scheduler');
assertIncludes(systemTxEngine, 'DISPUTE_JUROR_ASSIGN', 'system scheduler');
assertOrdered(systemTxEngine, 'schedule_content_review_assignment_system_txs(state', 'items = _select_due_items_with_indexes', 'system scheduler');

const disputeApply = fs.readFileSync(new URL('../../Weall-Protocol/src/weall/runtime/apply/dispute.py', import.meta.url), 'utf8');
assertIncludes(disputeApply, 'stage in {"", "open", "unassigned"}', 'dispute assign apply');
assertIncludes(disputeApply, 'assignment_blocked_reason"] = ""', 'dispute assign apply');

for (const page of [
  'src/pages/Account.tsx',
  'src/pages/DisputeDetail.tsx',
  'src/pages/DisputeReview.tsx',
  'src/pages/Disputes.tsx',
  'src/pages/JurorDashboard.tsx',
]) {
  const src = read(page);
  assertIncludes(src, 'window.setInterval', page);
  assertIncludes(src, 'document.hidden', page);
  assertIncludes(src, 'window.clearInterval', page);
}

console.log('OK: live rehearsal assignment and state refresh source checks passed');
