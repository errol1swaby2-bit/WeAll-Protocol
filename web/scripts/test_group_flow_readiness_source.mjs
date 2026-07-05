import fs from 'node:fs';
import path from 'node:path';

const root = process.cwd();
const groupsSource = fs.readFileSync(path.join(root, 'src/pages/Groups.tsx'), 'utf8');
const groupSource = fs.readFileSync(path.join(root, 'src/pages/Group.tsx'), 'utf8');
const groupCreateSource = fs.readFileSync(path.join(root, 'src/pages/GroupCreate.tsx'), 'utf8');
const packageJson = fs.readFileSync(path.join(root, 'package.json'), 'utf8');
const first15 = fs.readFileSync(path.join(root, '../Weall-Protocol/docs/testnet/FIRST_15_MINUTES.md'), 'utf8');
const doc = fs.readFileSync(path.join(root, '../Weall-Protocol/docs/testnet/GROUP_FLOW_READINESS.md'), 'utf8');

function assertIncludes(source, needle, label) {
  if (!source.includes(needle)) {
    throw new Error(`${label}: expected source to include ${needle}`);
  }
}

function assertNotIncludes(source, needle, label) {
  if (source.includes(needle)) {
    throw new Error(`${label}: source must not include ${needle}`);
  }
}

assertIncludes(packageJson, 'test:group-flow-readiness-source', 'package exposes group flow source test');

assertIncludes(groupsSource, 'The directory is a public read surface', 'Groups directory explains public read surface');
assertIncludes(groupsSource, 'Membership may gate participation inside a group, but not reading', 'Groups directory explains member-gated participation');
assertIncludes(groupsSource, 'Group admins, signers, moderators, and emissaries are public governance roles', 'Groups directory rejects owner/admin overclaim');
assertIncludes(groupsSource, 'not a private visibility gate', 'Groups empty state is honest and public-only');

assertIncludes(groupSource, 'Public group-governance records', 'Group detail renders emissary governance records section');
assertIncludes(groupSource, 'Owner appointment path: unsupported', 'Group detail rejects owner appointment path');
assertIncludes(groupSource, 'Frontend cache authority: never', 'Group detail rejects frontend authority');
assertIncludes(groupSource, 'member-gated; reading remains public', 'Group detail distinguishes participation gates from reads');
assertIncludes(groupSource, 'Track related transactions', 'Group detail links governance records to transaction status');
assertIncludes(groupSource, 'candidate(s)', 'Group detail surfaces active election candidate counts');

assertIncludes(groupCreateSource, 'public charter', 'Group create describes public charter');
assertIncludes(groupCreateSource, 'not a private room or owner-controlled enclave', 'Group create rejects private group/owner semantics');
assertIncludes(groupCreateSource, 'Track confirmation in Transactions', 'Group create links submission to tx lifecycle');
assertIncludes(groupCreateSource, 'Private group support: none', 'Group create displays public-only boundary');
assertNotIncludes(groupCreateSource, 'Group created.', 'Group create must not imply immediate finality');

assertIncludes(first15, 'Open a public group', 'FIRST_15 includes group first-run step');
assertIncludes(first15, 'Group membership may gate posting', 'FIRST_15 clarifies group participation gate');
assertIncludes(first15, 'Group flow readiness', 'FIRST_15 routes through group flow readiness');

assertIncludes(doc, 'Group admins, moderators, signers, and emissaries are not unilateral owners', 'Group readiness doc rejects unilateral ownership');
assertIncludes(doc, 'Frontend cache state never grants protocol authority', 'Group readiness doc rejects frontend authority');
assertIncludes(doc, 'private group support', 'Group readiness doc includes non-claim');

console.log('OK: group flow readiness source contract holds');
