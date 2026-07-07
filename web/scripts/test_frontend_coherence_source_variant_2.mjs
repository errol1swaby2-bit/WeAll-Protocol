#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';

const ROOT = path.resolve(import.meta.dirname, '..');
const read = (rel) => fs.readFileSync(path.join(ROOT, rel), 'utf8');
const fail = (msg) => { console.error(`FAIL: ${msg}`); process.exit(1); };
const assert = (cond, msg) => { if (!cond) fail(msg); };
const includes = (src, needle, msg) => assert(src.includes(needle), `${msg}: missing ${needle}`);
const notIncludes = (src, needle, msg) => assert(!src.includes(needle), `${msg}: stale/unsafe ${needle}`);

const home = read('src/pages/Home.tsx');
includes(home, 'pendingWork.items.filter((item) => item.kind === "report" && item.assigned)', 'Home assigned review count must count report assignments only');
includes(home, 'visibleReviewReports', 'Home visible review count must be report-scoped');
notIncludes(home, 'assignedDisputes: pendingWork.counts.assigned', 'Home must not use all assigned pending work as review count');

const lanes = read('src/lib/reviewLanes.ts');
includes(lanes, 'reviewLaneStatusFromTruth', 'Reviewer lane status helper');
includes(lanes, 'Opted in, paused/inactive', 'Reviewer lane paused/inactive state label');
includes(lanes, 'opted_in === true', 'Reviewer lane status must distinguish opted-in state from active state');

const account = read('src/pages/Account.tsx');
includes(account, 'reviewLaneStatusFromTruth', 'Account must use reviewer lane status helper');
includes(account, 'ROLE_JUROR_REINSTATE', 'Account must expose whole reviewer-role resume');
includes(account, 'Resume reviewer duties', 'Account must label reviewer resume action');
includes(account, 'Opted in, paused/inactive', 'Account must surface paused/inactive reviewer lane state');
notIncludes(account, 'active ? "Active" : "Not opted in"', 'Account must not collapse inactive opted-in lanes into not opted in');

const reviewCenter = read('src/pages/JurorDashboard.tsx');
includes(reviewCenter, 'reviewLaneStatusFromTruth', 'Review Center must use reviewer lane status helper');
includes(reviewCenter, 'Open the review workspace to accept and check in', 'Review Center assigned report hint must route acceptance to review workspace');
notIncludes(reviewCenter, 'Open the report detail to accept and check in', 'Review Center must not send assignment acceptance to detail page');

const live = read('src/pages/LiveVerificationRoom.tsx');
includes(live, 'readOnlyStatusView', 'Live room must derive read-only status boundary');
includes(live, 'Open room links, embedded video, and P2P media controls stay hidden', 'Read-only live status must hide transport controls');
includes(live, '!readOnlyStatusView && roomUrl', 'Open room link must be blocked in read-only status mode');
includes(live, '!readOnlyStatusView ? <div className="inCallVotingPanel"', 'In-call voting panel must be hidden in read-only status mode');

const reports = read('src/pages/Disputes.tsx');
includes(reports, 'Accept or decline the assignment from the review workspace', 'Reports queue must point assignment response to review workspace');
includes(reports, 'href: `/reviews/${id}`', 'Assigned report next action must route to review workspace');
notIncludes(reports, 'Accept or decline the assignment from the report detail page', 'Reports queue must not send assignment response to detail page');

const detail = read('src/pages/DisputeDetail.tsx');
includes(detail, 'You are viewing the report in read-only mode', 'Report detail must replace disabled inspect CTA with read-only explanation');
includes(detail, 'showDetailCta', 'Report detail must conditionally render primary CTA');
notIncludes(detail, '? "Inspect report only"', 'Report detail must not show disabled Inspect report only CTA');
notIncludes(detail, 'respond to the assignment here', 'Report detail must not claim assignment response happens on detail page');

const feed = read('src/components/FeedView.tsx') + '\n' + read('src/pages/Feed.tsx');
includes(feed, 'rankingOrderText', 'Feed item explanation must use actual ranking mode');
includes(feed, 'ordered by backend balanced ranking', 'Feed must explain balanced ranking');
includes(feed, 'ordered by backend production ranking', 'Feed must explain production ranking');
notIncludes(feed, 'ordered newest-first by backend state', 'Feed item explanation must not hard-code newest-first');
notIncludes(feed, 'This is newest-first protocol activity', 'Feed hero must not overstate newest-first once sort controls exist');

const contract = read('scripts/contract_check.mjs');
includes(contract, '/reviewer-status', 'Contract check must include reviewer-status endpoint when ACCOUNT is configured');
includes(contract, 'Skipping account checks and reviewer-status contract check', 'Contract check skip message must mention reviewer-status');

console.log('OK: Batch 625 frontend coherence source checks passed');
