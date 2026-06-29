import fs from 'node:fs';

function read(path) {
  return fs.readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');
}

function assertIncludes(src, needle, label) {
  if (!src.includes(needle)) {
    throw new Error(`${label}: missing ${needle}`);
  }
}

function assertNotIncludes(src, needle, label) {
  if (src.includes(needle)) {
    throw new Error(`${label}: unsafe source token remains: ${needle}`);
  }
}

const api = read('src/api/weall.ts');
const account = read('src/pages/Account.tsx');

for (const token of [
  'PublicProfileResponse',
  'ProfileUpdateTxRequest',
  '/v1/accounts/${encodeURIComponent(account)}/profile',
  '/v1/accounts/tx/profile-update',
  'profileUpdateTx',
]) {
  assertIncludes(api, token, 'public profile API client contract');
}

for (const token of [
  'Public civic profile',
  'Public read model',
  'Public-state boundary',
  'PROFILE_UPDATE',
  '/v1/tx/status/',
  'raw PoH evidence',
  'Submit public profile update',
  'profileDirty',
  'runProfileUpdate',
]) {
  assertIncludes(account, token, 'Account public profile UX contract');
}

for (const token of [
  'raw_video',
  'government_id',
  'session_keys',
]) {
  assertNotIncludes(account, token, 'Account page must not request private identity/account evidence fields');
}

console.log('OK: public profile frontend source contract holds');
