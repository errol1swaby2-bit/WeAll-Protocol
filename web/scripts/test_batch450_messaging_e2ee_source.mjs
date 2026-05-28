import fs from 'node:fs';

function read(path) {
  return fs.readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');
}

const crypto = read('src/lib/messageCrypto.ts');
const messaging = read('src/pages/Messaging.tsx');
const backendMessaging = fs.readFileSync(new URL('../../Weall-Protocol/src/weall/runtime/apply/messaging.py', import.meta.url), 'utf8');
const identity = fs.readFileSync(new URL('../../Weall-Protocol/src/weall/runtime/apply/identity.py', import.meta.url), 'utf8');

const requiredCrypto = [
  'export function readMessagingEncryptionIdentity',
  'export function sameMessagingPublicJwk',
  'export function messagingEncryptionFingerprint',
  'crypto.subtle.deriveKey',
  'AES-GCM',
];
for (const needle of requiredCrypto) {
  if (!crypto.includes(needle)) throw new Error(`messageCrypto missing ${needle}`);
}

const requiredMessagingUi = [
  'messagingKeyMismatch',
  'publishedKeyMissingLocally',
  'WeAll will not silently replace',
  'messaging_encryption_previous_key_id',
  'messaging_encryption_rotation_reason',
  'Rotate messaging key',
  'older messages may not decrypt after rotation',
];
for (const needle of requiredMessagingUi) {
  if (!messaging.includes(needle)) throw new Error(`Messaging page missing ${needle}`);
}

if (!backendMessaging.includes('_enforce_envelope_matches_account_keys')) {
  throw new Error('backend messaging apply must bind DM envelopes to published account keys');
}
for (const needle of [
  'sender_messaging_encryption_key_mismatch',
  'recipient_messaging_encryption_public_key_mismatch',
  'plaintext_body_forbidden',
]) {
  if (!backendMessaging.includes(needle)) throw new Error(`backend messaging missing ${needle}`);
}

for (const needle of [
  '_apply_messaging_encryption_policy',
  'messaging_encryption_key_rotation_requires_current_previous_key',
  'messaging_encryption_key_history',
  'messaging_encryption_forward_secrecy',
  'messaging_encryption_metadata_visible',
]) {
  if (!identity.includes(needle)) throw new Error(`identity apply missing ${needle}`);
}

console.log('batch450 messaging E2EE key lifecycle source checks passed');
