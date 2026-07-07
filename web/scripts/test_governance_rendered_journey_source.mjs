import fs from 'node:fs';

function read(path) {
  return fs.readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');
}

function assertIncludes(src, needle, label) {
  if (!src.includes(needle)) throw new Error(`${label}: missing ${needle}`);
}

function assertNotIncludes(src, needle, label) {
  if (src.includes(needle)) throw new Error(`${label}: unsafe or overclaiming content remains: ${needle}`);
}

const proposals = read('src/pages/Proposals.tsx');
const proposal = read('src/pages/Proposal.tsx');
const create = read('src/pages/ProposalCreate.tsx');
const timeline = read('src/components/ProcedureTimeline.tsx');
const pkg = read('package.json');
const first15 = fs.readFileSync(new URL('../../Weall-Protocol/docs/testnet/FIRST_15_MINUTES.md', import.meta.url), 'utf8');
const docs = fs.readFileSync(new URL('../../Weall-Protocol/docs/testnet/GOVERNANCE_RENDERED_JOURNEY.md', import.meta.url), 'utf8');

for (const [src, label] of [[proposals, 'proposal list'], [proposal, 'proposal detail'], [create, 'proposal create'], [docs, 'governance docs']]) {
  assertIncludes(src, 'draft → poll → revision → validation → voting → closed → tallied → executed → finalized', `${label} canonical stage ladder`);
}

for (const needle of [
  'Block-height authority',
  'Wall-clock times are display estimates only',
  'Why execution cannot be forced',
  'cannotExecuteReason',
  'executionStateLabel',
  'Open Transactions',
  'Submission output is evidence to follow, not a finalization claim',
]) {
  assertIncludes(proposal, needle, 'proposal detail rendered journey');
}

for (const needle of [
  'multi-option voting uses canonical option IDs',
  'Vote: {opt.label}',
  'castVote(opt.option_id)',
  'Abstain',
]) {
  assertIncludes(proposal, needle, 'multi-option governance voting');
}

for (const needle of [
  'Record-only upgrade boundary',
  'upgrade actions remain record-only',
  'Automatic protocol upgrade, migration, rollback, economics activation, and node restart remain disabled from the frontend',
  'Protocol and constitution upgrade actions are public, governance-parent-bound records only',
]) {
  assertIncludes(proposal, needle, 'upgrade record-only boundary');
}

for (const needle of [
  'Creation is not approval, execution, or finalization.',
  'Decision submission tracked',
  'Transactions page confirms status',
  'Protocol/constitution upgrade action records are public record-only metadata here',
]) {
  assertIncludes(create, needle, 'proposal creation transaction lifecycle boundary');
}

for (const needle of [
  'Decision lifecycle is protocol state, not a browser timer.',
  'block-height deadlines',
  'upgrade records are non-activating',
]) {
  assertIncludes(proposals, needle, 'proposal queue lifecycle boundary');
}

for (const needle of [
  'Display estimate only. Backend block height is protocol truth; wall-clock time cannot advance a stage.',
  'Stages open only when backend/protocol state reaches this block height.',
]) {
  assertIncludes(timeline, needle, 'procedure timeline block-height authority copy');
}

assertIncludes(first15, 'GOVERNANCE_RENDERED_JOURNEY.md', 'first 15 minutes routes to governance journey docs');
assertIncludes(pkg, 'test:governance-rendered-journey-source', 'package script for governance rendered journey source check');

for (const unsafe of [
  'public beta ready',
  'mainnet ready',
  'public multi-validator BFT ready',
  'auto-applies software',
  'executes migrations',
  'activates economics',
]) {
  assertNotIncludes(proposals.toLowerCase(), unsafe.toLowerCase(), 'proposals overclaim guard');
  assertNotIncludes(proposal.toLowerCase(), unsafe.toLowerCase(), 'proposal overclaim guard');
  assertNotIncludes(create.toLowerCase(), unsafe.toLowerCase(), 'proposal create overclaim guard');
}

console.log('OK: governance rendered journey source checks passed');
