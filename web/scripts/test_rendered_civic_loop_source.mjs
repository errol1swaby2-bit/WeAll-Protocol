import fs from 'node:fs';

function read(path) {
  return fs.readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');
}

function assertIncludes(src, needle, label) {
  if (!src.includes(needle)) throw new Error(`${label}: missing ${needle}`);
}

function assertNotIncludes(src, needle, label) {
  if (src.includes(needle)) throw new Error(`${label}: unsafe/stale content remains: ${needle}`);
}

const spec = read('tests/e2e/reviewer_civic_loop_rendered.spec.ts');
const pkg = read('package.json');
const dashboard = read('src/pages/NodeDashboard.tsx');
const router = read('src/lib/router.ts');

for (const route of [
  '/#/login',
  '/profile',
  '/verification',
  '/feed',
  '/groups',
  '/decisions',
  '/reports',
  '/reviews',
  '/activity',
  '/node',
  '/economics',
]) {
  assertIncludes(spec, route, 'rendered reviewer civic-loop rehearsal route coverage');
}

for (const label of [
  'reviewer civic loop renders in order against the configured backend',
  'load-demo-tester-session',
  'configured backend and dev-bootstrap manifest',
  'never unlocks economics by itself',
  'public mainnet ready|mainnet-scale|globally ready for 2350 TPS',
]) {
  assertIncludes(spec, label, 'rendered reviewer civic-loop rehearsal guard');
}

for (const legacy of ['/#/proposals', '/#/disputes', 'Public beta ready', 'Mainnet ready']) {
  assertNotIncludes(spec, legacy, 'rendered reviewer civic-loop rehearsal overclaim/legacy alias');
}

assertIncludes(pkg, 'test:rendered-civic-loop', 'package script for reviewer rendered civic loop');
assertIncludes(pkg, 'reviewer_civic_loop_rendered.spec.ts', 'package script points to reviewer civic-loop spec');
assertIncludes(dashboard, 'Reviewer API evidence map', 'NodeDashboard must keep reviewer API evidence visible for rendered route context');
assertIncludes(router, '{ href: "/decisions", label: "Decisions"', 'canonical decisions nav route');
assertIncludes(router, '{ href: "/reports", label: "Reports"', 'canonical reports nav route');
assertNotIncludes(router, 'ROUTE_ALIASES', 'legacy route aliases must stay removed');
assertNotIncludes(router, '"/proposals"', 'legacy proposals route must stay removed from frontend router');
assertNotIncludes(router, '"/disputes"', 'legacy disputes route must stay removed from frontend router');

console.log('OK: rendered reviewer civic-loop source rehearsal checks passed');
