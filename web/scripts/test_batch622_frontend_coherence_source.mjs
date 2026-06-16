import fs from 'node:fs';

function read(path) {
  return fs.readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');
}

function assertIncludes(src, needle, label) {
  if (!src.includes(needle)) {
    throw new Error(`${label}: missing ${needle}`);
  }
}

function assertNotIncludes(src, needle, label) {
  if (src.includes(needle)) {
    throw new Error(`${label}: stale/unsafe wording remains: ${needle}`);
  }
}

const router = read('src/lib/router.ts');
const reviewLanes = read('src/lib/reviewLanes.ts');
const reviewCenter = read('src/pages/JurorDashboard.tsx');
const account = read('src/pages/Account.tsx');
const disputes = read('src/pages/Disputes.tsx');
const disputeReview = read('src/pages/DisputeReview.tsx');
const liveRoom = read('src/pages/LiveVerificationRoom.tsx');
const feed = read('src/pages/Feed.tsx');
const feedView = read('src/components/FeedView.tsx');
const feedLib = read('src/lib/feed.ts');
const api = read('src/api/weall.ts');
const dashboard = read('src/pages/NodeDashboard.tsx');
const validatorWizard = read('src/components/ValidatorReadinessWizard.tsx');
const transactions = read('src/pages/TransactionsPage.tsx');
const txFeedback = read('src/lib/txFeedback.ts');
const settings = read('src/pages/Settings.tsx');
const settingsLib = read('src/lib/settings.ts');
const css = read('src/styles.css');

const allFrontend = [router, reviewLanes, reviewCenter, account, disputes, disputeReview, liveRoom, feed, feedView, feedLib].join('\n');

for (const token of [
  'Review Center',
  'Lane-separated review duties',
  'path: "/reviews"',
  'label: "Review Center"',
  'title: "Review Center"',
]) {
  assertIncludes(router, token, 'navigation route coherence');
}

for (const token of [
  'content_review',
  'dispute_review',
  'poh_async_review',
  'poh_live_review',
  'Content review',
  'Dispute juror review',
  'PoH async review',
  'PoH live review',
  'Tier-2 human status is eligibility only',
  'not bundled with content disputes',
]) {
  assertIncludes(reviewLanes, token, 'review lane contract');
}

for (const token of [
  'REVIEW_CENTER_LABEL',
  'REVIEW_LANES.filter',
  'Choose the correct review lane',
  'Content disputes are not silently mixed with PoH reviews',
  'Tier-2 human status is eligibility, not consent',
  '/reviews?lane=poh_async_review',
  '/reviews?lane=poh_live_review',
  'Backend truth source',
  'Opt-in boundary',
  'Time limit / penalty',
]) {
  assertIncludes(reviewCenter, token, 'Review Center lane separation');
}

for (const token of [
  'REVIEW_LANES.filter',
  'Open {REVIEW_CENTER_LABEL}',
  'Choose exact review lanes',
]) {
  assertIncludes(account, token, 'Account reviewer opt-in linkage');
}

for (const token of [
  'Back to Review Center',
  'Back to {REVIEW_CENTER_LABEL}',
  'Review Center lists lane-specific work',
  'poh_live_review',
]) {
  assertIncludes(disputeReview + liveRoom, token, 'lane pages link back to Review Center');
}

for (const token of [
  'Latest protocol activity',
  'Recent public activity',
  'FEED_ALGORITHM_SUMMARY',
  'FEED_PUBLIC_BETA_BLOCKER',
  'Why items appear',
  'Why this appears',
  'newest-first protocol activity',
  'not a personalized recommendation algorithm',
  'No personalized recommendation ranking is claimed',
]) {
  assertIncludes(feed + feedView + feedLib, token, 'feed truthfulness');
}

for (const token of [
  '/v1/feed',
  '/v1/accounts/${encodeURIComponent(account)}/feed',
  '/v1/groups/${encodeURIComponent(id)}/feed',
  '/v1/disputes/eligible',
  '/v1/disputes/current',
  '/v1/poh/async/juror-cases',
  '/v1/poh/live/assigned',
  '/v1/status/mempool',
  '/v1/storage/ipfs/ops',
  '/v1/tx/catalog',
]) {
  assertIncludes(api, token, 'frontend API truth map');
}

for (const token of [
  'Public beta remains blocked',
  'This dashboard never claims public beta, public validator, or production readiness',
  'Helper production remains',
  'Storage/IPFS capacity',
  'validator/helper/storage readiness',
]) {
  assertIncludes(dashboard + validatorWizard, token, 'NodeDashboard responsibility/readiness boundaries');
}

for (const token of [
  'Accepted locally',
  'Gossiped / pending',
  'Pending in mempool',
  'Included in block',
  'Finalized',
  'Removed from mempool',
  'peer propagation',
]) {
  assertIncludes(transactions, token, 'transaction lifecycle labels');
}
assertIncludes(txFeedback, 'case "unknown":\n      return "recorded";', 'unknown tx state is not treated as failure');

for (const token of [
  '--accent-rgb',
  '--accent-2-rgb',
  '--accent-focus',
  'setAccentVars',
  '<label',
  ':focus-visible',
  '@media (prefers-reduced-motion: reduce)',
]) {
  assertIncludes(settings + settingsLib + css, token, 'settings/accent/accessibility surface');
}

for (const stale of ['Review Queue', 'review queue', 'All cases', 'all cases']) {
  assertNotIncludes(allFrontend, stale, 'generic mixed review surface');
}
for (const overclaim of ['Recommended for you', 'For you feed', 'personalized feed algorithm', 'algorithmic personalized feed']) {
  assertNotIncludes(feed + feedView + feedLib, overclaim, 'feed recommendation overclaim');
}

console.log('OK: Batch 622 frontend coherence source checks passed');
