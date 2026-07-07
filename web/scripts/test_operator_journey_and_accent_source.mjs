import fs from 'node:fs';

function read(path) {
  return fs.readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');
}

function assertIncludes(src, needle, label) {
  if (!src.includes(needle)) {
    throw new Error(`${label}: missing ${needle}`);
  }
}

const settings = read('src/lib/settings.ts');
const css = read('src/styles.css');
const dashboard = read('src/pages/NodeDashboard.tsx');
const validatorWizard = read('src/components/ValidatorReadinessWizard.tsx');
const txPage = read('src/pages/TransactionsPage.tsx');
const txTimeline = read('src/components/TxPropagationTimeline.tsx');

for (const token of ['--accent-rgb', '--accent-2-rgb', '--accent-soft', '--accent-hover', '--accent-focus', 'setAccentVars']) {
  assertIncludes(settings, token, 'settings accent runtime variables');
}
for (const token of ['var(--accent-glow-left)', 'var(--accent-glow-right)', 'var(--accent-focus)', 'var(--accent-focus-ring)', 'rgba(var(--accent-rgb)']) {
  assertIncludes(css, token, 'css accent variable usage');
}
for (const token of ['ValidatorReadinessWizard', 'Safe switch command preview', 'Fix readiness blockers in order', 'Helper production remains']) {
  assertIncludes(dashboard + validatorWizard, token, 'validator wizard source');
}
for (const token of ['TxPropagationTimeline', 'forwarded/gossiped', 'queued/pending', 'Removed from mempool', 'peer propagation']) {
  assertIncludes(txPage + txTimeline, token, 'tx propagation timeline source');
}

console.log('OK: Batch 620 operator journey and accent source checks passed');
