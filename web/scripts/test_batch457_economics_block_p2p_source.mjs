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

assertIncludes('src/pages/Economics.tsx', 'Economics & Treasury');
assertIncludes('src/pages/Economics.tsx', 'Genesis economics locked');
assertIncludes('src/api/weall.ts', 'economicsStatus');
assertIncludes('src/api/weall.ts', 'walletStatus');
assertIncludes('src/lib/router.ts', 'href: "/economics"');
assertIncludes('src/lib/messageCrypto.ts', 'messagingPeerTrustState');
assertIncludes('src/lib/messageCrypto.ts', 'trustMessagingPeerKey');
assertIncludes('src/pages/Messaging.tsx', 'Recipient keys are trusted on first use');
assertIncludes('src/pages/Messaging.tsx', 'The messaging key for');

console.log('batch457 economics/block/P2P implementation source checks passed');
