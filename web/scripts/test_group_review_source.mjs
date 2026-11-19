#!/usr/bin/env node
import fs from 'node:fs';

const group = fs.readFileSync(new URL('../src/pages/Group.tsx', import.meta.url), 'utf8');
const feed = fs.readFileSync(new URL('../src/components/FeedView.tsx', import.meta.url), 'utf8');
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
assertIncludes(group, 'scope={{ kind: "group", groupId: selected }}', 'group uses exact scoped feed');
assertIncludes(feed, 'async function doReport', 'shared group report action');
assertIncludes(feed, 'tx_type: "CONTENT_FLAG"', 'shared report submits canonical content flag');
assertIncludes(feed, 'payload: reason ? { target_id: String(targetId), reason }', 'report retains exact selected target');
assertIncludes(feed, '<MediaGallery', 'group feed renders media');
assertIncludes(feed, 'className="feedBodyText"', 'group feed renders post bodies');
assertIncludes(feed, 'Open thread', 'group feed exposes discussion navigation');

console.log('batch452 group review source checks passed');
