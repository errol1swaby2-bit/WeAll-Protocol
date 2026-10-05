import fs from 'node:fs';
import path from 'node:path';

const root = path.resolve(process.cwd(), '..');
const session = fs.readFileSync(path.join(root, 'web/src/auth/session.ts'), 'utf8');
const actorHelpers = fs.readFileSync(path.join(root, 'web/tests/e2e/m2_actor_helpers.ts'), 'utf8');

const checks = [
  [session.includes('const SS_SESSION_BEARER = "weall_session_bearer_v1";'), 'session bearer must have an explicit session-scoped storage key'],
  [session.includes('sessionStorage.setItem(SS_SESSION_BEARER'), 'raw browser session bearer must be written only to sessionStorage'],
  [session.includes('sessionStorage.removeItem(SS_SESSION_BEARER)'), 'ending a session must clear the session-scoped bearer'],
  [!session.includes('localStorage.setItem(LS_SESSION, JSON.stringify(out))'), 'full session object containing bearer must not be persisted to localStorage'],
  [session.includes('delete persistent.sessionKey'), 'legacy or incoming persistent metadata must explicitly strip sessionKey'],
  [actorHelpers.includes('sessionStorage.getItem("weall_session_bearer_v1")'), 'browser E2E helper must verify the bearer in sessionStorage'],
  [actorHelpers.includes('expect(stored.sessionKey).toBeUndefined()'), 'browser E2E helper must assert durable session metadata contains no bearer'],
];

for (const [ok, message] of checks) {
  if (!ok) throw new Error(message);
}

console.log('A20-F002 browser bearer custody source checks passed');
