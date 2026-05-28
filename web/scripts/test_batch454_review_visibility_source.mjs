import fs from 'node:fs';

function assertIncludes(file, needle, message) {
  const src = fs.readFileSync(file, 'utf8');
  if (!src.includes(needle)) {
    throw new Error(`${message}\nMissing: ${needle}`);
  }
}

assertIncludes(
  'src/lib/disputeSurface.ts',
  'for (const key of ["current_vote", "viewer_vote", "vote_self"])',
  'disputeCurrentVote must prefer viewer-scoped vote records from redacted dispute detail.'
);
assertIncludes(
  '../Weall-Protocol/src/weall/api/routes_public_parts/disputes.py',
  'normalized["viewer_vote"] = viewer_vote',
  'dispute API must expose viewer-only vote state while keeping global votes redacted.'
);
assertIncludes(
  '../Weall-Protocol/src/weall/api/routes_public_parts/content.py',
  'if _dispute_vote_tally_hides_target(raw):',
  'content read model must hide upheld targets before final receipt catches up.'
);

console.log('batch454 review visibility source checks passed');
