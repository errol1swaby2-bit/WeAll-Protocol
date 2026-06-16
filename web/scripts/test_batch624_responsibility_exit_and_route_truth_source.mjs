#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';

const ROOT = path.resolve(import.meta.dirname, '..');
const read = (rel) => fs.readFileSync(path.join(ROOT, rel), 'utf8');
const fail = (msg) => {
  console.error(`FAIL: ${msg}`);
  process.exit(1);
};
const assert = (cond, msg) => { if (!cond) fail(msg); };

const account = read('src/pages/Account.tsx');
assert(account.includes('REVIEWER_LANE_OPT_OUT'), 'Account must expose reviewer lane opt-out transaction');
assert(account.includes('Opt out of ${row.label}') || account.includes('Opt out of'), 'Reviewer lane cards must expose opt-out language');
assert(account.includes('Pause all reviewer duties'), 'Account must expose whole reviewer-role pause language');
assert(account.includes('ROLE_JUROR_SUSPEND'), 'Account must wire whole reviewer pause to ROLE_JUROR_SUSPEND');
assert(account.includes('ROLE_VALIDATOR_SUSPEND'), 'Account must wire validator pause to ROLE_VALIDATOR_SUSPEND');
assert(account.includes('ROLE_NODE_OPERATOR_SUSPEND'), 'Account must wire broad node operator pause to ROLE_NODE_OPERATOR_SUSPEND');
assert(account.includes('Helper-specific opt-out not yet available in UI'), 'Helper exit boundary must be explicit');
assert(account.includes('Storage-specific opt-out not yet available in UI'), 'Storage exit boundary must be explicit');

const home = read('src/pages/Home.tsx');
assert(home.includes('derivePendingWork'), 'Home must use shared pending work derivation');
assert(!home.includes('const accountLower = account.toLowerCase()'), 'Home must not manually count assigned disputes by local accountLower logic');
assert(!home.includes('jurors.some'), 'Home must not manually inspect jurors instead of pendingWork helpers');

const juror = read('src/pages/JurorDashboard.tsx');
assert(juror.includes('function viewLiveVerificationStatus'), 'Review Center must split pending live status view from live-room join');
assert(juror.includes('?mode=status'), 'Pending live status view must route in read-only status mode');
assert(juror.includes('View verification status'), 'Pending live session CTA must remain status-oriented');
assert(juror.includes('Open live room is only available after a live PoH reviewer assignment is active'), 'Legacy live-room language must be explanatory, not the pending CTA');

const live = read('src/pages/LiveVerificationRoom.tsx');
assert(live.includes('statusOnlyMode'), 'Live room must recognize read-only status mode');
assert(live.includes('Open live room controls unlock only for the subject or assigned reviewers'), 'Live status mode must explain authority boundary');

const app = read('src/App.tsx');
assert(app.includes('HomeDashboard') && !app.includes('const Home = lazy'), 'App must use the HomeDashboard route wrapper');
assert(app.includes('PohPage') && !app.includes('AccountVerificationPage = lazy'), 'App must use the PohPage route wrapper');

const router = read('src/lib/router.ts');
assert(router.includes('const canonicalAlias = ROUTE_ALIASES[r]'), 'matchRoute must canonicalize through ROUTE_ALIASES');
assert(!router.includes('r === "/reviews" || r === "/juror"'), 'matchRoute must not hard-code /juror alias outside ROUTE_ALIASES');
assert(!router.includes('r === "/advanced" || r === "/tools"'), 'matchRoute must not hard-code /tools alias outside ROUTE_ALIASES');

const disputeDetail = read('src/pages/DisputeDetail.tsx');
assert(disputeDetail.includes('detailCtaLabel'), 'Dispute detail must derive assignment-state CTA labels');
assert(disputeDetail.includes('Inspect report only'), 'Unassigned report detail must not overclaim review workspace access');
assert(disputeDetail.includes('Continue to assignment response'), 'Assigned-but-not-accepted report detail must route to assignment response wording');
assert(!disputeDetail.includes('handle assignment posture here'), 'Report detail must not claim assignment posture is handled on the detail page');

const feedView = read('src/components/FeedView.tsx');
assert(feedView.includes('Feed sort controls'), 'Feed must expose visible sort controls');
assert(feedView.includes('Balanced backend ranking'), 'Feed must expose balanced backend ranking control');
assert(feedView.includes('Production backend ranking'), 'Feed must expose production backend ranking control');
assert(feedView.includes('setSort'), 'Feed sort controls must update frontend state');

console.log('OK: Batch 624 responsibility exit, pending work, route alias, live status, and feed-sort source checks passed');
