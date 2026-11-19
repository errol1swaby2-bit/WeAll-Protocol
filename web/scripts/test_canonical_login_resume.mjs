import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";
import { createHash, webcrypto } from "node:crypto";
import ts from "typescript";

const journalSource = fs.readFileSync("src/auth/canonicalLoginJournal.ts", "utf8")
  .replace(/^import type .*;\n/m, "").replace(/\bexport /g, "");
const sessionSource = fs.readFileSync("src/auth/session.ts", "utf8");
const begin = sessionSource.indexOf("type DeviceLoginArgs =");
const end = sessionSource.indexOf("export async function ensureBackendSession(", begin);
assert.ok(begin >= 0 && end > begin);
const isolated = journalSource + "\n" + sessionSource.slice(begin, end).replace(/\bexport /g, "");
const code = ts.transpileModule(isolated, {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.None },
}).outputText;

const account = "@fixture";
const pubkey = "fixture-public-key";
const chainId = "weall-controlled-devnet";
const scope = { account, base: "/", pubkey };
const args = { account, base: "/", ttlSeconds: 86400 };
const keypair = { pubkeyB64: pubkey, secretKeyB64: "fixture-only" };
const deviceType = "ACCOUNT_DEVICE_REGISTER";
const issueType = "ACCOUNT_SESSION_KEY_ISSUE";

function fixture() {
  const entries = new Map();
  const storage = {
    get length() { return entries.size; },
    key: i => [...entries.keys()][i] ?? null,
    getItem: k => entries.get(k) ?? null,
    setItem: (k, v) => entries.set(k, v),
    removeItem: k => entries.delete(k),
  };
  const f = { storage, entries, writes: [], confirmed: new Set(), sync: true, authorized: false,
    direct: 0, nonce: 0, generated: 0, chainId, active: null, lostAck: false, wrongAck: false,
    confirmationGate: null, authChecks: 0, rateLimitedReads: 0, statusReads: 0, delays: [] };
  f.boot = () => {
    const context = {
      crypto: webcrypto, TextEncoder, sessionStorage: storage,
      normalizeAccount: value => String(value).toLowerCase(),
      loadKeypair: () => keypair, getApiBaseUrl: () => "",
      randomSessionKeyB64: () => "fixture-bearer-" + (++f.generated),
      randomDeviceId: () => "browser:fixture:" + f.generated,
      signDetachedB64: () => "fixture-signature", canonicalSessionLoginMessage: () => new Uint8Array(),
      config: { publicTestnet: false },
      createBrowserSession: async () => { f.direct++; throw new Error("direct_session_mutation_forbidden_in_controlled_devnet"); },
      isDirectSessionMutationForbidden: error => error.message.startsWith("direct_session_mutation_forbidden"),
      sleep: async ms => { f.delays.push(ms); },
      weall: { status: async () => {
        f.statusReads++;
        if (f.rateLimitedReads > 0) {
          f.rateLimitedReads--;
          throw Object.assign(new Error("fixture rate limit"), { status: 429 });
        }
        return { chain_id: f.chainId };
      } },
      submitSignedTxWithNonce: async a => {
        assert.equal(a.expectedChainId, f.chainId, "journal must bind the actual selected chain at signing");
        const nonce = ++f.nonce;
        const env = { chain_id: f.chainId, tx_type: a.tx_type, signer: a.account, nonce, parent: null, payload: a.payloadFactory(nonce) };
        await a.onBeforeSubmit(env);
        // Independently compute the Python-compatible canonical identity for
        // these two flat payloads, then prove tracking preceded dispatch.
        const flatten = o => Object.fromEntries(Object.entries(o).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0));
        const canonical = flatten({ chain_id: env.chain_id, tx_type: env.tx_type, signer: env.signer, nonce,
          payload: flatten(env.payload), system: false });
        const txId = "tx:" + createHash("sha256").update(JSON.stringify(canonical)).digest("hex");
        assert.ok([...entries.values()].some(v => JSON.stringify(JSON.parse(v)).includes(txId)), "exact identity persisted before dispatch");
        f.writes.push({ type: a.tx_type, txId, nonce, payload: env.payload });
        if (f.lostAck) { f.lostAck = false; throw new Error("connection lost"); }
        return { env, result: { tx_id: f.wrongAck ? "tx:" + "0".repeat(64) : txId } };
      },
      waitForConfirmedSessionTransaction: async ({ txId, timeoutMs }) => {
        assert.equal(timeoutMs, 120000);
        if (f.confirmationGate) await f.confirmationGate;
        return f.confirmed.has(txId);
      },
      waitForLocalAccountNonceAtLeast: async ({ account: signer, minNonce }) => {
        assert.equal(signer, account);
        const tracked = f.writes.find(w => w.nonce === minNonce);
        assert.ok(tracked && f.confirmed.has(tracked.txId), "only a confirmed tracked action can enter nonce reconciliation");
        return f.sync;
      },
      waitForSessionAuthState: async ({ account: signer, sessionKey, expectedAuthenticated }) => {
        f.authChecks++;
        assert.equal(signer, account);
        assert.equal(expectedAuthenticated, true);
        assert.equal(sessionKey, f.writes.find(w => w.type === issueType)?.payload.session_key);
        return f.authorized;
      },
      setSession: s => { f.active = s; },
      verifyBrowserSessionOnNode: async () => true,
    };
    return vm.runInNewContext(code + "\n({loginOnThisDevice, readCanonicalLogin, clearCanonicalLoginsForAccount})", context);
  };
  return f;
}
const pending = /Login is waiting for canonical/;

// A throttled first identity read must recover using only successful fresh
// status, not a default identity and not a duplicate direct-login probe.
const throttled = fixture();
throttled.rateLimitedReads = 2;
const throttledApi = throttled.boot();
await assert.rejects(throttledApi.loginOnThisDevice(args), pending);
assert.equal(throttled.statusReads, 3);
assert.deepEqual(throttled.delays, [500, 1000]);
assert.equal(throttled.direct, 1);
assert.deepEqual(throttled.writes.map(w => w.type), [deviceType]);

const exhausted = fixture();
exhausted.rateLimitedReads = 6;
const exhaustedApi = exhausted.boot();
await assert.rejects(exhaustedApi.loginOnThisDevice(args), /chain identity \(node rate limit\)/);
assert.equal(exhausted.statusReads, 6);
assert.deepEqual(exhausted.delays, [500, 1000, 2000, 4000, 4000]);
assert.equal(exhausted.writes.length, 0);
assert.equal(exhausted.active, null);

// The device confirmation can arrive after the first bounded wait.
const f = fixture();
let api = f.boot();
await assert.rejects(api.loginOnThisDevice(args), pending);
assert.deepEqual(f.writes.map(w => w.type), [deviceType]);
assert.equal(f.active, null);
const first = api.readCanonicalLogin(scope);
const candidate = first.sessionKey;
const device = first.deviceId;
f.confirmed.add(f.writes[0].txId);

// A confirmed device receipt alone cannot authorize chaining the session
// issuance. Hold local nonce synchronization false and retry the same attempt.
f.sync = false;
await assert.rejects(api.loginOnThisDevice(args), /ACCOUNT_DEVICE_REGISTER local account reconciliation/);
assert.deepEqual(f.writes.map(w => w.type), [deviceType]);
assert.equal(f.active, null);
assert.equal(f.authChecks, 0);
assert.equal(api.readCanonicalLogin(scope).deviceTx.txId, f.writes[0].txId);
assert.equal(api.readCanonicalLogin(scope).sessionTx, undefined);
f.sync = true;

// The issue is admitted, but not yet confirmed. Reload the same tab.
await assert.rejects(api.loginOnThisDevice(args), pending);
assert.deepEqual(f.writes.map(w => w.type), [deviceType, issueType]);
assert.equal(f.direct, 1);
assert.equal(f.active, null);
api = f.boot();
const resumed = api.readCanonicalLogin(scope);
assert.equal(resumed.sessionKey, candidate);
assert.equal(resumed.deviceId, device);
assert.equal(resumed.startedAtMs, first.startedAtMs);
f.confirmed.add(f.writes[1].txId);
f.sync = false;
await assert.rejects(api.loginOnThisDevice(args), pending);
assert.equal(f.authChecks, 0, "nonce synchronization must precede bearer authorization");
f.sync = true;
await assert.rejects(api.loginOnThisDevice(args), pending);
assert.equal(f.active, null, "a confirmed receipt is not proof of a usable bearer");
f.authorized = true;
await api.loginOnThisDevice(args);
assert.equal(f.active.sessionKey, candidate);
assert.equal(f.active.expiresAtMs, first.startedAtMs + args.ttlSeconds * 1000);
assert.equal(f.writes.length, 2);
assert.equal(f.direct, 1);
assert.equal(api.readCanonicalLogin(scope), null);

// Lost acknowledgement must not cause a duplicate semantic transaction.
const lost = fixture();
lost.lostAck = true;
let l = lost.boot();
await assert.rejects(l.loginOnThisDevice(args), pending);
assert.equal(lost.writes.length, 1);
lost.confirmed.add(lost.writes[0].txId);
l = lost.boot();
await assert.rejects(l.loginOnThisDevice(args), pending);
assert.deepEqual(lost.writes.map(w => w.type), [deviceType, issueType]);
assert.equal(lost.direct, 1);

// A changed chain or mismatched acknowledgement fails closed.
lost.chainId = "other-chain";
await assert.rejects(l.loginOnThisDevice(args), /chain_mismatch/);
assert.equal(lost.writes.length, 2);
const mismatch = fixture();
mismatch.wrongAck = true;
const m = mismatch.boot();
await assert.rejects(m.loginOnThisDevice(args), /does not match/);
await assert.rejects(m.loginOnThisDevice(args), /inconsistent acknowledgement/);
assert.equal(mismatch.writes.length, 1);
m.clearCanonicalLoginsForAccount(account);
assert.equal(mismatch.entries.size, 0, "explicit signer removal discards private pending candidates");

// Concurrent automatic/manual login callers share exactly one transaction.
const concurrent = fixture();
let release;
concurrent.confirmationGate = new Promise(resolve => { release = resolve; });
const c = concurrent.boot();
const one = c.loginOnThisDevice(args);
const two = c.loginOnThisDevice(args);
await assert.rejects(c.loginOnThisDevice({...args, account: "@other"}), /another_device_login_in_progress/);
release();
const outcomes = await Promise.allSettled([one, two]);
assert.equal(outcomes.filter(x => x.status === "rejected").length, 2);
assert.equal(concurrent.direct, 1);
assert.equal(concurrent.writes.length, 1);

// Storage failure before the signed intent is durable must prevent dispatch.
const unavailable = fixture();
unavailable.storage.setItem = () => { throw new Error("storage unavailable"); };
const u = unavailable.boot();
await assert.rejects(u.loginOnThisDevice(args), /storage unavailable/);
assert.equal(unavailable.writes.length, 0);
assert.equal(unavailable.active, null);

// Compile the real shared signing entrypoint as well as the orchestration
// above. The generic chain resolver represents a stale cache or fallback.
const signStart = sessionSource.indexOf("export async function submitSignedTxWithNonce(");
const signEnd = sessionSource.indexOf("export async function restoreAccountAndLoginOnThisDevice(", signStart);
assert.ok(signStart >= 0 && signEnd > signStart);
const signingCode = ts.transpileModule(journalSource + "\n" + sessionSource.slice(signStart, signEnd).replace("export async function", "async function"), {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.None },
}).outputText;
let selectedChain = chainId;
let cachedCalls = 0;
let dispatches = 0;
let intentCalls = 0;
let reserved = 9;
let rollbacks = 0;
let signingFails = false;
let transportFails = false;
let statusFailures = [];
let statusReads = 0;
const statusDelays = [];
const signApi = vm.runInNewContext(signingCode + "\nsubmitSignedTxWithNonce", {
  runSignerSerialized: async (_account, fn) => fn(),
  normalizeAccount: value => value,
  loadKeypair: () => keypair,
  resolveChainId: async () => { cachedCalls++; return "stale-default"; },
  sleep: async ms => { statusDelays.push(ms); },
  weall: {
    status: async base => {
      assert.equal(base, "/");
      statusReads++;
      if (statusFailures.length) {
        throw Object.assign(new Error("fixture status failure"), { status: statusFailures.shift() });
      }
      return { chain_id: selectedChain };
    },
    txSubmit: async env => {
      dispatches++;
      assert.equal(env.chain_id, chainId);
      if (transportFails) throw new Error("fixture lost acknowledgement");
      return { ok: true };
    },
  },
  claimNextNonce: async (_account, _base, journalBound) => {
    assert.equal(journalBound, true, "canonical signing must request strict nonce reservation");
    const previousReserved = reserved;
    return { account, nonce: ++reserved, previousReserved };
  },
  rollbackNonceClaim: claim => {
    if (claim && reserved === claim.nonce) {
      reserved = claim.previousReserved;
      rollbacks++;
    }
  },
  buildUnsignedEnvelope: env => env,
  signEnvelope: env => {
    if (signingFails) throw new Error("fixture signing failure");
    return env;
  },
  BROWSER_PQ_SIG_PROFILE: "pq-mldsa-v1",
});
const bound = {
  account, base: "/", tx_type: deviceType, expectedChainId: chainId,
  payloadFactory: () => ({ device_id: "fixture-device" }),
  onBeforeSubmit: env => { intentCalls++; assert.equal(env.chain_id, chainId); },
};
// Exact M4.1 failure boundary: second chain verification returns 429.
// Retry only the identity GET before allocating a nonce or signing.
statusFailures = [429, 429];
await signApi(bound);
assert.equal(statusReads, 3);
assert.deepEqual(statusDelays, [500, 1000]);
assert.equal(cachedCalls, 0);
assert.equal(dispatches, 1);
assert.equal(intentCalls, 1);
for (const invalidChain of ["", "wrong-chain"]) {
  selectedChain = invalidChain;
  await assert.rejects(signApi(bound), /pending_canonical_login_chain_mismatch/);
}
assert.equal(cachedCalls, 0);
assert.equal(dispatches, 1);
assert.equal(intentCalls, 1);

// Exhausted throttling or a different HTTP error must not consume a nonce,
// dispatch, or fall back to the generic cached chain identity.
selectedChain = chainId;
const beforeThrottle = reserved;
statusFailures = [429, 429, 429, 429, 429, 429];
await assert.rejects(signApi(bound), /chain identity \(node rate limit\)/);
assert.deepEqual(statusDelays, [500, 1000, 500, 1000, 2000, 4000, 4000]);
assert.equal(reserved, beforeThrottle);
assert.equal(dispatches, 1);
assert.equal(intentCalls, 1);
statusFailures = [403];
const beforeForbidden = statusReads;
await assert.rejects(signApi(bound), /canonical_login_prepare_failed:chain_identity/);
assert.equal(statusReads, beforeForbidden + 1);
assert.equal(reserved, beforeThrottle);
assert.equal(dispatches, 1);
assert.equal(cachedCalls, 0);

// A never-dispatched nonce must not be burned by a payload, signing, or
// intent-persistence error. An uncertain dispatch must retain its claim.
selectedChain = chainId;
const prior = reserved;
await assert.rejects(signApi({...bound, payloadFactory: () => { throw new Error("fixture payload failure"); }}), /canonical_login_prepare_failed:payload/);
assert.equal(reserved, prior);
signingFails = true;
await assert.rejects(signApi(bound), /canonical_login_prepare_failed:signature/);
assert.equal(reserved, prior);
signingFails = false;
await assert.rejects(signApi({...bound, onBeforeSubmit: () => { throw new Error("fixture intent storage failure"); }}), /canonical_login_prepare_failed:intent/);
assert.equal(reserved, prior);
assert.equal(rollbacks, 3);
assert.equal(dispatches, 1);
transportFails = true;
await assert.rejects(signApi(bound), /fixture lost acknowledgement/);
assert.equal(dispatches, 2);
assert.equal(reserved, prior + 1);
assert.equal(rollbacks, 3);
assert.equal(cachedCalls, 0);

// Exercise the actual claim helper and journal reader together. No fallback
// account read, nonce allocation or tracked intent is allowed on exhaustion.
const claimStart = sessionSource.indexOf("async function claimNextNonce(");
const claimEnd = sessionSource.indexOf("function rollbackNonceClaim(", claimStart);
assert.ok(claimStart >= 0 && claimEnd > claimStart);
const claimCode = ts.transpileModule(journalSource + "\n" + sessionSource.slice(claimStart, claimEnd), {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.None },
}).outputText;
let localReserved = 0;
let nonceReads = 0;
let nonceFailures = [429, 429];
let nonceResult = { ok: true, account, nonce_cursor: 14, next_nonce: 15 };
const nonceDelays = [];
let fallbackCalls = 0;
const strictClaim = vm.runInNewContext(claimCode + "\nclaimNextNonce", {
  normalizeAccount: value => value,
  apiGet: async (path, base) => {
    assert.equal(path, "/v1/accounts/" + encodeURIComponent(account) + "/nonce");
    assert.equal(base, "/");
    nonceReads++;
    if (nonceFailures.length) throw Object.assign(new Error("fixture nonce error"), { status: nonceFailures.shift() });
    return nonceResult;
  },
  sleep: async ms => nonceDelays.push(ms),
  getReservedNonce: () => localReserved,
  setReservedNonce: (_account, value) => { localReserved = value; },
  weall: { accountNonce: () => { fallbackCalls++; throw new Error("unsafe fallback"); }, account: () => { fallbackCalls++; throw new Error("unsafe fallback"); } },
});
const claim = await strictClaim(account, "/", true);
assert.equal(claim.nonce, 15);
assert.equal(nonceReads, 3);
assert.equal(localReserved, 15);
assert.deepEqual(nonceDelays, [500, 1000]);
nonceFailures = [429, 429, 429, 429, 429, 429];
await assert.rejects(strictClaim(account, "/", true), /nonce reservation \(node rate limit\)/);
assert.equal(localReserved, 15);
nonceFailures = [403];
await assert.rejects(strictClaim(account, "/", true), /fixture nonce error/);
assert.equal(localReserved, 15);
for (const invalid of [
  { ...nonceResult, account: "@other" }, { ...nonceResult, next_nonce: 20 },
  { ...nonceResult, ok: false }, { ...nonceResult, nonce_cursor: undefined },
]) {
  nonceResult = invalid;
  await assert.rejects(strictClaim(account, "/", true), /canonical_login_nonce_unavailable/);
  assert.equal(localReserved, 15);
}
nonceResult = { ok: true, account, nonce_cursor: 14, next_nonce: 15 };
await assert.rejects(strictClaim(account, "/", true), /local pending action/);
assert.equal(fallbackCalls, 0);

console.log("F-001 canonical login interruption, receipt/auth gates, custody and duplicate prevention passed");
