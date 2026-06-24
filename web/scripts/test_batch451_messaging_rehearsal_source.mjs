import fs from 'node:fs';

function read(path) {
  return fs.readFileSync(path, 'utf8');
}

function assertContains(path, needle) {
  const text = read(path);
  if (!text.includes(needle)) {
    throw new Error(`${path} missing expected source marker: ${needle}`);
  }
}

function assertNotContains(path, needle) {
  const text = read(path);
  if (text.includes(needle)) {
    throw new Error(`${path} must not contain private messaging marker: ${needle}`);
  }
}

assertContains('src/components/MessagingKeyBootstrapper.tsx', 'return null');
assertNotContains('src/components/MessagingKeyBootstrapper.tsx', 'ACCOUNT_SECURITY_POLICY_SET');
assertNotContains('src/App.tsx', '<MessagingKeyBootstrapper />');
assertContains('src/pages/Messaging.tsx', 'PRIVATE_MESSAGING_UNSUPPORTED');
assertNotContains('src/pages/Messaging.tsx', 'loadRecipientAccountWithMessagingKey');
assertNotContains('src/pages/Messaging.tsx', 'not visible on this node yet');
assertContains('src/components/TxQueueProvider.tsx', 'TX_RECORDED_AUTO_DISMISS_MS');
assertContains('src/components/TxQueueProvider.tsx', 'isTransientToastStatus');

console.log('batch451 public-only messaging source checks passed');
