import fs from 'node:fs';
import path from 'node:path';

const root = process.cwd();
const apiSource = fs.readFileSync(path.join(root, 'src/api/weall.ts'), 'utf8');
const groupSource = fs.readFileSync(path.join(root, 'src/pages/Group.tsx'), 'utf8');

function assertIncludes(source, needle, label) {
  if (!source.includes(needle)) {
    throw new Error(`${label}: expected source to include ${needle}`);
  }
}

assertIncludes(apiSource, 'GroupGovernanceContract', 'API exposes typed group governance contract');
assertIncludes(apiSource, '/v1/groups/${encodeURIComponent(id)}/governance-contract', 'API uses backend group governance contract route');
assertIncludes(groupSource, 'Group governance contract', 'Group page renders governance contract section');
assertIncludes(groupSource, 'Protocol governance scaled to group scope', 'Group page states group-scope governance model');
assertIncludes(groupSource, 'membership may gate posting, commenting, voting, moderation, invitation, and administration, but not reading', 'Group page states public-read/member-action boundary');
assertIncludes(groupSource, 'Frontend cache authority: never', 'Group page rejects frontend cache authority');
assertIncludes(groupSource, 'Admin shortcuts:', 'Group page makes admin shortcut status explicit');

console.log('OK: group governance frontend source contract holds');
