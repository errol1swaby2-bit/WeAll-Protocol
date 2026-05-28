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

assertContains('src/components/MessagingKeyBootstrapper.tsx', 'export default function MessagingKeyBootstrapper');
assertContains('src/components/MessagingKeyBootstrapper.tsx', 'ACCOUNT_SECURITY_POLICY_SET');
assertContains('src/components/MessagingKeyBootstrapper.tsx', 'Never silently rotate');
assertContains('src/App.tsx', '<MessagingKeyBootstrapper />');
assertContains('src/pages/Messaging.tsx', 'loadRecipientAccountWithMessagingKey');
assertContains('src/pages/Messaging.tsx', 'not visible on this node yet');
assertContains('src/components/TxQueueProvider.tsx', 'TX_RECORDED_AUTO_DISMISS_MS');
assertContains('src/components/TxQueueProvider.tsx', 'isTransientToastStatus');

console.log('batch451 messaging rehearsal source checks passed');
