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

const home = read('src/pages/Home.tsx');
const node = read('src/pages/NodeDashboard.tsx');
const economics = read('src/pages/Economics.tsx');
const proposal = read('src/pages/Proposal.tsx');
const dispute = read('src/pages/DisputeDetail.tsx');
const group = read('src/pages/Group.tsx');
const tx = read('src/pages/TransactionsPage.tsx');
const pkg = read('package.json');

for (const needle of [
  'Average-user launch-prep walkthrough',
  'account state → verification state → public feed → groups → decisions → reports → reviews → activity → node → economics',
  'Every protocol-native social and civic surface is publicly readable; membership gates participation, not visibility.',
  'Record-only upgrade and economics-locked surfaces remain last so reviewers cannot mistake them for live activation.',
]) {
  assertIncludes(home, needle, 'home reviewer civic-loop clarity');
}

for (const needle of [
  'Operator evidence still required: external observer transcript → cross-machine replay transcript → full local proof bundle.',
  'Protocol and constitution upgrade records are scheduled, public, record-only metadata; they do not fetch artifacts, execute migrations, restart nodes, or change economics.',
  'A clean-machine public observer boot transcript is still required before calling the observer experience reviewer-ready.',
]) {
  assertIncludes(node, needle, 'node dashboard evidence-boundary clarity');
}

for (const needle of [
  'No live token value, staking, validator rewards, slashing, treasury spending, or transfers are activated by this page.',
  'browsing this page or recording a protocol/constitution upgrade does not activate economics.',
]) {
  assertIncludes(economics, needle, 'economics lock clarity');
}

for (const needle of [
  'Human time labels are estimates; protocol truth uses committed block heights.',
  'Exact start/end boundaries come from backend state; repeated finalization must remain idempotent.',
]) {
  assertIncludes(proposal, needle, 'proposal lifecycle clarity');
}

for (const needle of [
  'Review windows, appeal windows, missed-vote outcomes, and finalization must follow backend block heights, not browser wall-clock time.',
  'Reviewer notes and outcomes may be public, but raw PoH/video/government identity evidence must not be exposed through this route.',
]) {
  assertIncludes(dispute, needle, 'dispute lifecycle and privacy clarity');
}

assertIncludes(group, 'Candidate lists, candidate votes, term activation, and term expiration must be public group-governance records', 'group emissary clarity');
assertIncludes(tx, 'a transaction is not treated as a final public result until the backend reports block inclusion and the local observer has synced that confirmed state.', 'transaction timeline clarity');
assertIncludes(pkg, 'test:step2-ux-clarity-source', 'package script for step 2 source check');

for (const source of [home, node, economics, proposal, dispute, group, tx]) {
  for (const unsafe of [
    'Public beta ready',
    'Mainnet ready',
    'production ready',
    'live token value is active',
    'automatic software upgrade',
  ]) {
    assertNotIncludes(source, unsafe, 'step 2 overclaim guard');
  }
}

console.log('OK: Step 2 UX clarity source checks passed');
