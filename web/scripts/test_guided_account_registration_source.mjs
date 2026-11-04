import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const read = (p) => fs.readFileSync(path.join(root, p), "utf8");

const login = read("src/pages/LoginPage.tsx");
const registration = read("src/pages/AccountRegistrationPage.tsx");
const protocol = read("src/lib/accountSetupRegistration.ts");
const router = read("src/lib/router.ts");
const app = read("src/App.tsx");
const prefetch = read("src/lib/routePrefetch.ts");
const e2e = read("tests/e2e/account_custody_registration_restore.spec.ts");
const keys = read("src/auth/keys.ts");
const session = read("src/auth/session.ts");
const evidence = read("src/auth/evidenceCrypto.ts");
const sessionDevices = read("src/pages/SessionDevicesPage.tsx");

function section(source, begin, end) {
  const start = source.indexOf(begin);
  const finish = source.indexOf(end, start + begin.length);
  assert.ok(start >= 0 && finish > start, "Missing source boundary: " + begin);
  return source.slice(start, finish);
}

const keyCreation = section(login, "async function handleCreateAccount(", "async function handleDownloadRecoveryKey(");
const verifiedRecovery = section(login, "function handleContinueAfterRecovery(", "function verifyCreatedRecoveryFile(");

assert.ok(!keyCreation.includes("issueSessionFromSecretKey("), "A locally created key cannot mint a login session before recovery verification");
assert.ok(keys.includes("hasStoredKeypairMetadata("), "Existing public identity metadata must be detectable after browser secret loss");
assert.ok(session.includes('if (hasStoredKeypairMetadata(acct)) throw new Error("existing_account_key_requires_recovery")'), "Missing signing seed must not trigger identity replacement");
assert.ok(keys.includes('throw new Error("existing_recovery_authority_requires_recovery")'), "Recovery authority must not silently rotate");
assert.ok(evidence.includes('throw new Error("existing_evidence_key_requires_recovery")'), "Evidence authority must not silently rotate");
assert.ok(keyCreation.includes('setMode("restore")'), "Interrupted key custody must offer recovery route");
assert.ok(session.includes('if (!sessionSynced)'), "Canonical session issuance must fail closed on observer reconciliation timeout");
assert.ok(!sessionDevices.includes('>{session?.sessionKey || "Not present"}<'), "The session utility must not display raw bearer credentials");
assert.ok(verifiedRecovery.includes('if (!recoveryVerified)'), "Recovery ceremony must fail closed");
assert.ok(verifiedRecovery.includes("issueSessionFromSecretKey("), "Recovery completion should mint the login session");
assert.ok(verifiedRecovery.includes('nav("/onboarding/register")'), "New users must register from dedicated page");
assert.ok(login.includes("ensureRecoveryAuthorityKeypair(account)"), "Recovery authority should not be silently rotated on retries");
assert.ok(login.includes("ensureEvidenceKemKeypair(account)"), "Evidence key should not be silently rotated on retries");

for (const field of [
  '"/onboarding/register"',
  "AccountRegistrationPage",
  "submitBasicAccountRegistration",
  "readRegistrationFinality",
]) {
  const source = router + app + prefetch + registration + protocol;
  assert.ok(source.includes(field), "Missing guided registration invariant: " + field);
}

assert.ok(protocol.includes('tx_type: "ACCOUNT_REGISTER"'), "Registration must use a signed canonical transaction");
assert.ok(protocol.includes("solveAccountRegistrationWork("), "Registration must meet current account registration scarcity requirements");
assert.ok(protocol.includes("ensureRecoveryAuthorityKeypair("), "Account registration must bind recovery authority");
assert.ok(protocol.includes("ensureEvidenceKemKeypair("), "Account registration must bind evidence authority");
assert.ok(protocol.includes('return "key_mismatch"'), "Registered account must be matched to the browser signer");
assert.ok(protocol.includes('result?.local_state_synced === true'), "Observer-local confirmation is not enough");
assert.ok(registration.includes("registration !== \"not_registered\""), "Unknown network state must not allow a duplicate registration");
assert.ok(registration.includes("rememberPendingTransaction("), "Pending registration should remain traceable");
assert.ok(e2e.includes('getItem("weall_session_v1")'), "Browser custody E2E must check that recovery cannot be bypassed");
assert.ok(e2e.includes('getByTestId("guided-account-registration")'), "Browser custody E2E must visit the dedicated registration flow");

console.log("F1 guided account registration source gates passed");
