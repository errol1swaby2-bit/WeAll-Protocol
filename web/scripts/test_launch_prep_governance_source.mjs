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

const proposal = read('src/pages/Proposal.tsx');
const governance = read('src/lib/governance.ts');
const accountSurface = read('src/lib/accountSurface.ts');
const home = read('src/pages/Home.tsx');
const nodeDashboard = read('src/pages/NodeDashboard.tsx');
const pkg = read('package.json');

for (const needle of [
  'governanceProposalOptionsOf',
  'governanceProposalResultOf',
  'option_id',
  'selected_option_id',
  'Multi-option civic voting',
  'Votes reference canonical option IDs, not mutable labels. Abstain remains explicit.',
  'castVote(opt.option_id)',
]) {
  assertIncludes(proposal, needle, 'proposal multi-option voting surface');
}

for (const needle of [
  'option_id: string',
  'governanceProposalOptionsOf',
  'governanceProposalResultOf',
  'options.sort((a, b) => a.option_id.localeCompare(b.option_id))',
]) {
  assertIncludes(governance, needle, 'frontend governance normalizer');
}

assertIncludes(accountSurface, 'option_id', 'account vote surface preserves option_id');
assertIncludes(home, 'WeCoin and fees stay locked by default during public observer / closed-testnet review.', 'home locked economics copy');
assertIncludes(home, 'Public observer and closed-testnet flows do not activate live economics by default.', 'home economics notification copy');
assertIncludes(nodeDashboard, 'Public record-only, block-height scheduled, governance-parent bound', 'node dashboard upgrade lifecycle copy');
assertIncludes(pkg, 'test:launch-prep-governance-source', 'package script for launch-prep governance source check');

for (const unsafe of [
  'Public beta ready',
  'Mainnet ready',
  'production ready',
  'economics active by default',
]) {
  assertNotIncludes(home, unsafe, 'home overclaim guard');
  assertNotIncludes(proposal, unsafe, 'proposal overclaim guard');
}

console.log('OK: launch-prep governance frontend source checks passed');
