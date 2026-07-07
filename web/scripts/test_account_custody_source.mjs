import fs from 'node:fs';
import path from 'node:path';

const root = path.resolve(process.cwd(), '..');
const read = (p) => fs.readFileSync(path.join(root, p), 'utf8');

const login = read('web/src/pages/LoginPage.tsx');
const recovery = read('web/src/auth/recoveryFile.ts');
const session = read('web/src/auth/session.ts');
const keys = read('web/src/auth/keys.ts');

const checks = [
  [login.includes('recoveryDownloaded'), 'create flow must track recovery download/copy separately from verification'],
  [login.includes('recoveryVerified'), 'create flow must track recovery verification'],
  [login.includes('verifyRecoveryKeyFileForAccount'), 'create flow must verify saved recovery file/key against generated account key'],
  [login.includes('data-testid="verify-created-recovery-file"'), 'create flow must expose recovery-file verification input'],
  [login.includes('data-testid="verify-created-recovery-json"'), 'create flow must expose pasted recovery JSON verification input'],
  [login.includes('disabled={!recoveryVerified}'), 'continue must be disabled until recovery is verified'],
  [!login.includes('I saved my recovery key somewhere private.'), 'manual checkbox must not be sufficient for account custody'],
  [login.includes('It never replaces the verified recovery file'), 'easy sign-in must remain secondary to recovery file'],
  [recovery.includes('export function verifyRecoveryKeyFileForAccount'), 'recovery module must expose verification helper'],
  [recovery.includes('recovery_secret_key_mismatch'), 'recovery verification must check secret-key continuity'],
  [recovery.includes('recovery_public_key_mismatch'), 'recovery verification must check public-key continuity'],
  [keys.includes('sessionStorage.setItem(secretStorageKey(normalized), secretKeyB64)'), 'raw account secret should be session-scoped after creation'],
  [keys.includes('localStorage.setItem(keyStorageKey(normalized), JSON.stringify(secureMeta))'), 'localStorage should persist public key metadata only'],
  [keys.includes('hasSecret: false'), 'localStorage key metadata should mark secret absence'],
  [session.includes('missing_local_signer'), 'session health must detect missing local signer'],
];

for (const [ok, msg] of checks) {
  if (!ok) throw new Error(msg);
}

console.log('batch469 account custody source checks passed');
