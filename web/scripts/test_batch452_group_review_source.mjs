#!/usr/bin/env node
import fs from 'node:fs';

const group = fs.readFileSync(new URL('../src/pages/Group.tsx', import.meta.url), 'utf8');
const content = fs.readFileSync(new URL('../../Weall-Protocol/src/weall/api/routes_public_parts/content.py', import.meta.url), 'utf8');

function assertIncludes(haystack, needle, label) {
  if (!haystack.includes(needle)) {
    console.error(`missing ${label}: ${needle}`);
    process.exit(1);
  }
}

assertIncludes(content, 'def _dispute_vote_tally_hides_target', 'vote-tally removal helper');
assertIncludes(content, 'disputes_by_target', 'dispute target index lookup');
assertIncludes(content, 'appeal window remains open', 'appeal-window read model comment');
assertIncludes(group, 'async function reportGroupPost', 'group report action');
assertIncludes(group, 'CONTENT_FLAG', 'group report submits canonical content flag');
assertIncludes(group, 'Report group content', 'group report tx title');
assertIncludes(group, 'quickCardSplit', 'group activity split card');
assertIncludes(group, 'quickCardMain', 'group activity main button');

console.log('batch452 group review source checks passed');
