import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const read = (relative) => fs.readFileSync(path.join(root, relative), "utf8");
const keys = read("src/auth/keys.ts");
const recovery = read("src/auth/recoveryFile.ts");
const session = read("src/auth/session.ts");
const login = read("src/pages/LoginPage.tsx");
const e2e = read("tests/e2e/account_custody_registration_restore.spec.ts");
const pkg = JSON.parse(read("package.json"));
const lock = JSON.parse(read("package-lock.json"));

const failures = [];
const requireText = (source, needle, label) => {
  if (!source.includes(needle)) failures.push(`${label}: missing ${needle}`);
};
const rejectText = (source, needle, label) => {
  if (source.includes(needle)) failures.push(`${label}: forbidden ${needle}`);
};

requireText(keys, '@noble/post-quantum/ml-dsa.js', "keys");
requireText(keys, 'ml_dsa65.keygen(seed)', "keys");
requireText(keys, 'ml_dsa65.sign(msgBytes, kp.secretKey', "keys");
requireText(keys, 'ml_dsa65.verify(signature, msgBytes, publicKey', "keys");
requireText(keys, 'weall:pq-mldsa-v1:protocol-signature', "keys");
requireText(keys, 'MLDSA65_SECRET_SEED_BYTES = 32', "keys");
requireText(keys, 'MLDSA65_PUBLIC_KEY_BYTES = 1952', "keys");
requireText(keys, 'MLDSA65_SIGNATURE_BYTES = 3309', "keys");
rejectText(keys, 'browser_pq_signing_not_implemented', "keys");
rejectText(keys, 'MLDSA_BROWSER_SIGNING_AVAILABLE = false', "keys");

requireText(recovery, 'version: 2', "recovery");
requireText(recovery, 'sigProfile: "pq-mldsa-v1"', "recovery");
requireText(recovery, 'secretKeyFormat: "mldsa65-seed-b64"', "recovery");
requireText(session, 'derivePublicKeyFromSecretKey(secretKeyB64)', "session");
rejectText(session, 'secretBytes.length !== 64', "session");
requireText(login, 'data-testid="restore-recovery-file"', "login");

for (const marker of [
  'Create account key',
  'Download recovery file',
  'recovery_account_mismatch',
  'Register basic account',
  'waitForConfirmedTx',
  'signatureValid',
  'restore-recovery-file',
  'Upload your recovery file or paste your recovery key.',
  'Submit public profile update',
]) requireText(e2e, marker, "e2e");

if (pkg.dependencies?.["@noble/post-quantum"] !== "0.6.1") {
  failures.push("package.json: @noble/post-quantum must be pinned to 0.6.1");
}
const expectedLockedPackages = {
  "@noble/post-quantum": {
    version: "0.6.1",
    integrity: "sha512-+pormrDZwjRw05U8ADK4JpHejo87+gBd+muRBB/ozztH5yhDLMDF4jHQWN3NQQAsu1zBNPWTG0ZwVI0CR29H0A==",
  },
  "@noble/ciphers": {
    version: "2.2.0",
    integrity: "sha512-Z6pjIZ/8IJcCGzb2S/0Px5J81yij85xASuk1teLNeg75bfT07MV3a/O2Mtn1I2se43k3lkVEcFaR10N4cgQcZA==",
  },
  "@noble/curves": {
    version: "2.2.0",
    integrity: "sha512-T/BoHgFXirb0ENSPBquzX0rcjXeM6Lo892a2jlYJkqk83LqZx0l1Of7DzlKJ6jkpvMrkHSnAcgb5JegL8SeIkQ==",
  },
  "@noble/hashes": {
    version: "2.2.0",
    integrity: "sha512-IYqDGiTXab6FniAgnSdZwgWbomxpy9FtYvLKs7wCUs2a8RkITG+DFGO1DM9cr+E3/RgADRpFjrKVaJ1z6sjtEg==",
  },
};
for (const [name, expected] of Object.entries(expectedLockedPackages)) {
  const locked = lock.packages?.[`node_modules/${name}`];
  if (!locked) {
    failures.push(`package-lock.json: missing ${name} lock entry`);
    continue;
  }
  if (locked.version !== expected.version) {
    failures.push(`package-lock.json: ${name} must resolve to ${expected.version}`);
  }
  if (locked.integrity !== expected.integrity) {
    failures.push(`package-lock.json: ${name} integrity mismatch`);
  }
}
const pqDependencies = lock.packages?.["node_modules/@noble/post-quantum"]?.dependencies || {};
for (const dependency of ["@noble/ciphers", "@noble/curves", "@noble/hashes"]) {
  if (pqDependencies[dependency] !== "~2.2.0") {
    failures.push(`package-lock.json: @noble/post-quantum must pin ${dependency} to ~2.2.0`);
  }
}
if (pkg.scripts?.["test:account-custody-e2e"] !== "playwright test tests/e2e/account_custody_registration_restore.spec.ts") {
  failures.push("package.json: missing stateful custody E2E script");
}

if (failures.length) {
  console.error("account custody cryptographic source gate failed");
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

console.log("account custody cryptographic source gate passed");
