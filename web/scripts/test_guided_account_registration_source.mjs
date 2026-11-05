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
const backendSessionRoute = read("../Weall-Protocol/src/weall/api/routes_public_parts/session.py");
const publicRedaction = read("../Weall-Protocol/src/weall/api/public_redaction.py");

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
assert.ok(keys.includes("export function canonicalMldsa65PublicKeyHex("), "Browser must normalize ML-DSA-65 public key bytes before comparing on-chain authorities");
assert.ok(protocol.includes("canonicalMldsa65PublicKeyHex(pubkey) !== canonicalMldsa65PublicKeyHex(keypair.pubkeyB64)"), "Registration state must compare chain hex and browser base64 by bytes");
assert.ok(e2e.includes('Buffer.from(publicKeyB64, "base64").toString("hex")'), "Real-stack test must assert the backend canonical key encoding");
assert.ok(session.includes('if (hasStoredKeypairMetadata(acct)) throw new Error("existing_account_key_requires_recovery")'), "Missing signing seed must not trigger identity replacement");
assert.ok(keys.includes('throw new Error("existing_recovery_authority_requires_recovery")'), "Recovery authority must not silently rotate");
assert.ok(evidence.includes('throw new Error("existing_evidence_key_requires_recovery")'), "Evidence authority must not silently rotate");
assert.ok(keyCreation.includes('setMode("restore")'), "Interrupted key custody must offer recovery route");
const restoredFile = section(login, "async function handleRecoveryFileSelected(", "function handlePasteRecoveryText(");
const pastedRecovery = section(login, "function handlePasteRecoveryText(", "async function handleRestoreLogin(");
const restoredLogin = section(login, "async function handleRestoreLogin(", "async function handleUseEasySignIn(");
for (const staging of [restoredFile, pastedRecovery]) {
  assert.ok(!staging.includes("saveRecoveryAuthorityKeypair("), "Import must not install recovery authority before authentication");
  assert.ok(!staging.includes("saveEvidenceKemKeypair("), "Import must not install evidence authority before authentication");
  assert.ok(staging.includes("setStagedRecoveryBundle(parsed)"), "Import must stage fully validated recovery material");
}
assert.ok(restoredLogin.includes("derivePublicKeyFromSecretKey(recoveryKeyInput.trim())"), "Restored signer must be validated before network login");
assert.ok(restoredLogin.includes("canonicalMldsa65PublicKeyHex(expectedSigner) !== canonicalMldsa65PublicKeyHex(suppliedSigner)"), "Restored signer must match canonical account identity");
assert.ok(restoredLogin.includes("restoredSessionIssued = true"), "Post-auth failures must be distinguishable");
assert.ok(restoredLogin.includes("if (restoredSessionIssued) endSession()"), "Post-auth validation failure must not retain a local login");
assert.ok(session.includes('if (!sessionSynced)'), "Canonical session issuance must fail closed on observer reconciliation timeout");
assert.ok(session.includes("async function waitForSessionAuthState("), "Canonical session authorization must be checked through the session endpoint");
assert.ok(session.includes("if (!sessionAuthorized)"), "Missing canonical key authorization must prevent active login");
assert.ok(session.includes("async function waitForConfirmedSessionTransaction("), "Session issuance must establish transaction finality independently of nonce");
assert.ok(session.includes("if (!confirmed)"), "Missing canonical receipt must block login");
assert.ok(session.includes('result?.local_state_synced === true'), "Session receipt must be synchronized with the canonical observer");
assert.ok(session.includes("expectedAuthenticated: false"), "Revocation must verify the old bearer no longer authenticates");
assert.ok(session.includes("response?.authenticated === args.expectedAuthenticated"), "Session endpoint response must explicitly match expected authentication state");
assert.ok(session.includes("submitAndVerifySessionRevocation("), "Revocation paths must use shared receipt verification");
assert.ok(session.includes("if (!authorized)"), "Replacement session keys must be canonically authorized before activation");
assert.ok(session.includes("} finally {\n    // Local logout must happen even if the network cannot confirm revocation."), "Local logout must not depend on remote revocation confirmation");
assert.ok(session.includes('apiGet("/v1/session/me"'), "Do not rely on publicly redacted account session records");
assert.ok(publicRedaction.includes('copied.pop("session_keys", None)'), "Public account views must not expose session keys");
assert.ok(backendSessionRoute.includes('@router.get("/session/me")'), "Backend must provide the dedicated session authentication contract");
assert.ok(backendSessionRoute.includes('"authenticated": bool(active and not expired)'), "Backend must explicitly authenticate active and unexpired sessions");
const canonicalCheck = restoredLogin.indexOf("canonicalMldsa65PublicKeyHex(expectedSigner) !== canonicalMldsa65PublicKeyHex(suppliedSigner)");
const recoveryAuthorityCheck = restoredLogin.indexOf("canonicalMldsa65PublicKeyHex(bundle.recoveryAuthorityPublicKeyB64) !== canonicalMldsa65PublicKeyHex(expectedRecovery)");
const loginMutation = restoredLogin.indexOf("await restoreAccountAndLoginOnThisDevice(");
assert.ok(canonicalCheck >= 0 && recoveryAuthorityCheck > canonicalCheck && loginMutation > recoveryAuthorityCheck, "All recovered authorities must be verified before network login and local mutation");
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
assert.ok(registration.includes('localStorage.setItem(pendingRegistrationKey(account), txId)'), "Nonsecret registration tracking must survive browser restarts");
assert.ok(registration.includes('persistSubmissionIntent(account, predictedTxId);'), "Registration must persist the signed canonical transaction ID before network dispatch");
assert.ok(registration.includes('localStorage.getItem(key) !== txId'), "The exact canonical transaction ID must survive a durable readback");
assert.ok(protocol.includes('onBeforeSubmit: async (signed) => {'), "Registration must derive the ID from the actually signed envelope");
assert.ok(session.includes('await args.onBeforeSubmit?.(signed);'), "Signer must await durable tracking of the signed envelope before network submission");
assert.ok(registration.includes('transactionId === "submission_unknown"'), "Unknown submission must reconcile from network state rather than submit again");
assert.ok(protocol.includes("export async function canonicalRegistrationTxId("), "Frontend must derive canonical transaction IDs before dispatch");
assert.ok(protocol.includes('if (txId !== predictedTxId)'), "Server-returned transaction IDs must be compared with locally derived identity");
assert.ok(registration.includes('setTransactionId(predictedTxId)'), "Frontend must preserve canonical transaction ID while acknowledgement is pending");
assert.ok(e2e.includes('getItem("weall_session_v1")'), "Browser custody E2E must check that recovery cannot be bypassed");
assert.ok(e2e.includes('getByTestId("guided-account-registration")'), "Browser custody E2E must visit the dedicated registration flow");

console.log("F1 guided account registration source gates passed");
