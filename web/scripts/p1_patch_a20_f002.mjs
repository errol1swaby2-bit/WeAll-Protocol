import fs from 'node:fs';
import path from 'node:path';

const root = path.resolve(process.cwd(), '..');
const sessionPath = path.join(root, 'web/src/auth/session.ts');
const actorHelperPath = path.join(root, 'web/tests/e2e/m2_actor_helpers.ts');

let session = fs.readFileSync(sessionPath, 'utf8');

const constantsNeedle = 'const LS_SESSION = "weall_session_v1";\n';
const constantsReplacement = 'const LS_SESSION = "weall_session_v1";\nconst SS_SESSION_BEARER = "weall_session_bearer_v1";\n';
if ((session.match(new RegExp(constantsNeedle.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g')) || []).length !== 1) {
  throw new Error('A20-F002 session storage constant anchor mismatch');
}
session = session.replace(constantsNeedle, constantsReplacement);

const readStart = session.indexOf('function readStoredSessionUnsafe(): Partial<SessionV1> | null {');
const readEnd = session.indexOf('\n\nfunction localSignerPresent', readStart);
if (readStart < 0 || readEnd < 0) throw new Error('A20-F002 readStoredSessionUnsafe anchors missing');
const readReplacement = `function readStoredSessionUnsafe(): Partial<SessionV1> | null {
  try {
    const raw = localStorage.getItem(LS_SESSION);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object") return null;

    const persistent = { ...(parsed as Record<string, unknown>) };
    const account = normalizeAccount(String(persistent.account || ""));
    const expiresAtMs = Number(persistent.expiresAtMs || 0);
    const legacySessionKey = String(persistent.sessionKey || "").trim();
    delete persistent.sessionKey;

    // A20-F002 migration: scrub any bearer written by older builds from
    // persistent storage immediately. Preserve it only for the current tab.
    if (legacySessionKey) {
      try {
        localStorage.setItem(LS_SESSION, JSON.stringify(persistent));
      } catch {
        // Best effort sanitization; callers still never consume the legacy key
        // directly from localStorage after this point.
      }
      try {
        sessionStorage.setItem(
          SS_SESSION_BEARER,
          JSON.stringify({ version: 1, account, expiresAtMs, sessionKey: legacySessionKey }),
        );
      } catch {
        // Fail closed below: no usable bearer is returned if tab storage fails.
      }
    }

    let sessionKey = "";
    try {
      const bearerRaw = sessionStorage.getItem(SS_SESSION_BEARER);
      const bearer = bearerRaw ? JSON.parse(bearerRaw) : null;
      if (bearer && typeof bearer === "object") {
        const bearerAccount = normalizeAccount(String(bearer.account || ""));
        const bearerExpiresAtMs = Number(bearer.expiresAtMs || 0);
        if (bearerAccount === account && bearerExpiresAtMs === expiresAtMs) {
          sessionKey = String(bearer.sessionKey || "").trim();
        }
      }
    } catch {
      sessionKey = "";
    }

    return {
      ...(persistent as Partial<SessionV1>),
      ...(sessionKey ? { sessionKey } : {}),
    };
  } catch {
    return null;
  }
}`;
session = session.slice(0, readStart) + readReplacement + session.slice(readEnd);

const getStart = session.indexOf('export function getSession(): SessionV1 | null {');
const getEnd = session.indexOf('\n\nexport function setSession', getStart);
if (getStart < 0 || getEnd < 0) throw new Error('A20-F002 getSession anchors missing');
const getReplacement = `export function getSession(): SessionV1 | null {
  const obj = readStoredSessionUnsafe();
  if (!obj || typeof obj !== "object") return null;
  if (obj.version !== 1) return null;
  const account = normalizeAccount(String(obj.account || ""));
  if (!account) return null;
  const expiresAtMs = Number(obj.expiresAtMs || 0);
  if (!Number.isFinite(expiresAtMs) || expiresAtMs <= 0) {
    endSession();
    return null;
  }
  if (Date.now() >= expiresAtMs) {
    endSession();
    return null;
  }
  const sessionKey = obj.sessionKey ? String(obj.sessionKey) : undefined;
  return { version: 1, account, expiresAtMs, sessionKey };
}`;
session = session.slice(0, getStart) + getReplacement + session.slice(getEnd);

const setStart = session.indexOf('export function setSession(s: SessionV1): void {');
const setEnd = session.indexOf('\n\nfunction readSessionAccountForCleanup', setStart);
if (setStart < 0 || setEnd < 0) throw new Error('A20-F002 setSession anchors missing');
const setReplacement = `export function setSession(s: SessionV1): void {
  const account = normalizeAccount(s.account);
  const expiresAtMs = Number(s.expiresAtMs || 0);
  if (!account) throw new Error("invalid_session_account");
  if (!Number.isFinite(expiresAtMs) || expiresAtMs <= 0) throw new Error("invalid_session_expiry");

  const persistent: SessionV1 = {
    version: 1,
    account,
    expiresAtMs,
  };
  const sessionKey = s.sessionKey ? String(s.sessionKey).trim() : "";

  if (sessionKey) {
    try {
      sessionStorage.setItem(
        SS_SESSION_BEARER,
        JSON.stringify({ version: 1, account, expiresAtMs, sessionKey }),
      );
    } catch {
      throw new Error("session_bearer_storage_failed");
    }
  } else {
    try {
      sessionStorage.removeItem(SS_SESSION_BEARER);
    } catch {
      // ignore
    }
  }

  localStorage.setItem(LS_SESSION, JSON.stringify(persistent));
}`;
session = session.slice(0, setStart) + setReplacement + session.slice(setEnd);

const endNeedle = `  try {
    localStorage.removeItem(LS_SESSION);
  } catch {
    // ignore
  }
  if (acct) {`;
const endReplacement = `  try {
    localStorage.removeItem(LS_SESSION);
  } catch {
    // ignore
  }
  try {
    sessionStorage.removeItem(SS_SESSION_BEARER);
  } catch {
    // ignore
  }
  if (acct) {`;
if (!session.includes(endNeedle)) throw new Error('A20-F002 endSession anchor missing');
session = session.replace(endNeedle, endReplacement);

fs.writeFileSync(sessionPath, session, 'utf8');

let actorHelpers = fs.readFileSync(actorHelperPath, 'utf8');
const actorNeedle = `  const stored = await page.evaluate(() => JSON.parse(localStorage.getItem("weall_session_v1") || "{}"));
  expect(stored.account).toBe(actor.account);
  expect(String(stored.sessionKey || "")).not.toBe("");`;
const actorReplacement = `  const custody = await page.evaluate(() => ({
    stored: JSON.parse(localStorage.getItem("weall_session_v1") || "{}"),
    bearer: JSON.parse(sessionStorage.getItem("weall_session_bearer_v1") || "{}"),
  }));
  const stored = custody.stored;
  expect(stored.account).toBe(actor.account);
  expect(stored.sessionKey).toBeUndefined();
  expect(custody.bearer.account).toBe(actor.account);
  expect(String(custody.bearer.sessionKey || "")).not.toBe("");`;
if (!actorHelpers.includes(actorNeedle)) throw new Error('A20-F002 actor helper anchor missing');
actorHelpers = actorHelpers.replace(actorNeedle, actorReplacement);
fs.writeFileSync(actorHelperPath, actorHelpers, 'utf8');
