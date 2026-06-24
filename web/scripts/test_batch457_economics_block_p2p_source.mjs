import fs from 'node:fs';
import path from 'node:path';

const root = process.cwd();
function read(rel) {
  return fs.readFileSync(path.join(root, rel), 'utf8');
}
function assertIncludes(file, needle) {
  const text = read(file);
  if (!text.includes(needle)) {
    throw new Error(`${file} missing ${needle}`);
  }
}
function assertExcludes(file, needle) {
  const text = read(file);
  if (text.includes(needle)) {
    throw new Error(`${file} must not contain ${needle}`);
  }
}

assertIncludes('src/pages/Economics.tsx', 'Economics & Treasury');
assertIncludes('src/pages/Economics.tsx', 'Genesis economics locked');
assertIncludes('src/api/weall.ts', 'economicsStatus');
assertIncludes('src/api/weall.ts', 'walletStatus');
assertIncludes('src/lib/router.ts', 'href: "/economics"');
assertIncludes('src/lib/messageCrypto.ts', 'PRIVATE_MESSAGING_UNSUPPORTED');
assertIncludes('src/pages/Messaging.tsx', 'PRIVATE_MESSAGING_UNSUPPORTED');
assertExcludes('src/pages/Messaging.tsx', 'Recipient keys are trusted on first use');
assertExcludes('src/pages/Messaging.tsx', 'The messaging key for');

console.log('batch457 economics/block/public-only checks passed');
