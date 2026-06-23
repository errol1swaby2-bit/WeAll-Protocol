import fs from 'node:fs';

function read(path) {
  return fs.readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');
}

const crypto = read('src/lib/messageCrypto.ts');
const messaging = read('src/pages/Messaging.tsx');
const backendMessaging = fs.readFileSync(new URL('../../Weall-Protocol/src/weall/runtime/apply/messaging.py', import.meta.url), 'utf8');
const identity = fs.readFileSync(new URL('../../Weall-Protocol/src/weall/runtime/apply/identity.py', import.meta.url), 'utf8');
const policy = fs.readFileSync(new URL('../../Weall-Protocol/src/weall/runtime/public_protocol_policy.py', import.meta.url), 'utf8');

for (const needle of [
  'PRIVATE_MESSAGING_UNSUPPORTED',
  'export function readMessagingEncryptionIdentity',
  'function unsupported',
]) {
  if (!crypto.includes(needle)) throw new Error(`messageCrypto public-only stub missing ${needle}`);
}

for (const needle of [
  'PRIVATE_MESSAGING_UNSUPPORTED',
  '/activity',
  'PRIVATE_MESSAGING_UNSUPPORTED',
]) {
  if (!messaging.includes(needle)) throw new Error(`Messaging compatibility page missing ${needle}`);
}

for (const needle of [
  'PRIVATE_MESSAGING_UNSUPPORTED',
  'protocol_native_direct_messages_are_unsupported',
]) {
  if (!backendMessaging.includes(needle)) throw new Error(`backend messaging hard-fail missing ${needle}`);
}

for (const needle of [
  'ENCRYPTED_PROTOCOL_PAYLOAD_UNSUPPORTED',
  'protocol_native_messaging_encryption_keys_are_unsupported',
]) {
  if (!identity.includes(needle)) throw new Error(`identity encryption-policy hard-fail missing ${needle}`);
}

for (const needle of [
  'DIRECT_MESSAGE_SEND',
  'encrypted_payload',
  'recipient_public_key',
  'GROUP_READ_VISIBILITY_MUST_BE_PUBLIC',
]) {
  if (!policy.includes(needle)) throw new Error(`public protocol policy missing ${needle}`);
}

console.log('batch450 public-only messaging compatibility source checks passed');
