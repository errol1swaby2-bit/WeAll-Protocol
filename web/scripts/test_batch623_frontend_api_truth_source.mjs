import fs from 'node:fs';

function read(path) {
  return fs.readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');
}

function assertIncludes(src, needle, label) {
  if (!src.includes(needle)) throw new Error(`${label}: missing ${needle}`);
}

function assertNotIncludes(src, needle, label) {
  if (src.includes(needle)) throw new Error(`${label}: stale/unsafe wording remains: ${needle}`);
}

const api = read('src/api/weall.ts');
const account = read('src/pages/Account.tsx');
const reviewCenter = read('src/pages/JurorDashboard.tsx');
const lanes = read('src/lib/reviewLanes.ts');
const router = read('src/lib/router.ts');
const app = read('src/App.tsx');
const config = read('src/lib/config.ts');
const proposals = read('src/pages/Proposals.tsx');
const proposalCreate = read('src/pages/ProposalCreate.tsx');
const feedLib = read('src/lib/feed.ts');
const feedView = read('src/components/FeedView.tsx');
const liveRoom = read('src/pages/JurorDashboard.tsx') + '\n' + read('src/pages/LiveVerificationRoom.tsx');

assertIncludes(api, 'accountReviewerStatus', 'reviewer status API client');
assertIncludes(api, '/reviewer-status', 'reviewer status API route');
assertIncludes(account, 'weall.accountReviewerStatus', 'Account uses reviewer truth endpoint');
assertIncludes(reviewCenter, 'weall.accountReviewerStatus', 'Review Center uses reviewer truth endpoint');
assertIncludes(account + reviewCenter, '/v1/accounts/{account}/reviewer-status', 'UI labels reviewer truth source');
assertNotIncludes(account, 'asRecord(asRecord(jurorRecord.responsibilities).reviewer)', 'Account must not infer reviewer lanes from redacted account roles');
assertNotIncludes(reviewCenter, 'asRecord(asRecord(jurorRecord.responsibilities).reviewer)', 'Review Center must not infer reviewer lanes from redacted account roles');

assertIncludes(lanes, 'DISPUTE_REVIEW_REQUIRED_FOR_ACCEPT_OR_VOTE', 'content review lane must not imply dispute voting authority');
assertIncludes(lanes, 'does not grant dispute juror accept/vote authority', 'content_review authority boundary');
assertIncludes(lanes, 'Dispute juror review', 'dispute review lane remains explicit');

assertIncludes(router, 'ROUTE_ALIASES', 'route aliases documented separately');
assertIncludes(router, '"/juror": "/reviews"', 'legacy juror alias documented');
assertIncludes(router, '{ href: "/reports", label: "Reports"', 'Reports normal nav item present');
assertIncludes(app, 'case "/reports":', 'Reports route rendered by App');

assertIncludes(config, 'canShowAdvancedMode', 'central advanced-mode helper');
assertIncludes(proposals, 'canShowAdvancedMode()', 'Proposals uses config-gated advanced helper');
assertIncludes(proposalCreate, 'canShowAdvancedMode()', 'ProposalCreate uses config-gated advanced helper');
assertNotIncludes(proposals + proposalCreate, 'loadSettings().showAdvancedMode', 'raw advanced setting must not bypass production config');

assertIncludes(feedLib, 'response reports the ranking mode used', 'feed lib documents backend ranking truth');
assertIncludes(feedView, 'rankingInfo', 'FeedView stores backend ranking metadata');
assertIncludes(feedView, 'Backend ranking mode', 'FeedView displays backend ranking mode');
assertIncludes(feedView, 'No personalized recommendation ranking is claimed unless the backend explicitly reports it', 'FeedView avoids personalization overclaim');
assertIncludes(api, 'ranking: params?.ranking || params?.rank', 'API client passes explicit ranking when requested');

assertIncludes(liveRoom, 'View verification status', 'unassigned live sessions do not invite room entry');
assertNotIncludes(liveRoom, 'Open live room</button>', 'pending unassigned live sessions must not say Open live room');

console.log('OK: Batch 623 frontend/API truth-source coherence checks passed');
