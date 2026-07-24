#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";

function usage() {
  console.error("usage: node scripts/generate_m2_actor_keys.mjs <devnet-keyfile.json> [browser-recovery-out.json]");
  process.exit(2);
}

const keyfile = process.argv[2];
if (!keyfile) usage();
const recoveryOut = process.argv[3] || "";
const data = JSON.parse(fs.readFileSync(keyfile, "utf8"));
const account = String(data.account || "").trim();
if (!account) throw new Error("keyfile_account_missing");

function hexToBytes(value) {
  const raw = String(value || "").trim();
  if (!raw || raw.length % 2 || !/^[0-9a-f]+$/i.test(raw)) throw new Error("invalid_hex");
  return Uint8Array.from(raw.match(/.{2}/g).map((part) => Number.parseInt(part, 16)));
}
function bytesToHex(bytes) {
  return Buffer.from(bytes).toString("hex");
}
function bytesToB64(bytes) {
  return Buffer.from(bytes).toString("base64");
}
function randomSeed() {
  return crypto.getRandomValues(new Uint8Array(32));
}

const activeSeed = hexToBytes(data.private_key_hex);
const active = ml_dsa65.keygen(activeSeed);
const expectedPubHex = bytesToHex(active.publicKey);
if (data.public_key_hex && String(data.public_key_hex).toLowerCase() !== expectedPubHex) {
  throw new Error("active_public_key_mismatch");
}
data.public_key_hex = expectedPubHex;

let recoverySeed;
if (data.recovery_private_key_hex) {
  recoverySeed = hexToBytes(data.recovery_private_key_hex);
} else {
  recoverySeed = randomSeed();
  data.recovery_private_key_hex = bytesToHex(recoverySeed);
}
const recovery = ml_dsa65.keygen(recoverySeed);
data.recovery_public_key_hex = bytesToHex(recovery.publicKey);

let kem;
if (data.evidence_kem_public_key_b64 && data.evidence_kem_secret_key_b64) {
  kem = {
    publicKey: Uint8Array.from(Buffer.from(data.evidence_kem_public_key_b64, "base64")),
    secretKey: Uint8Array.from(Buffer.from(data.evidence_kem_secret_key_b64, "base64")),
  };
} else {
  kem = ml_kem768.keygen();
  data.evidence_kem_public_key_b64 = bytesToB64(kem.publicKey);
  data.evidence_kem_secret_key_b64 = bytesToB64(kem.secretKey);
}
if (kem.publicKey.length !== 1184) throw new Error("invalid_mlkem768_public_key_length");

data.m2_independent_authorities = true;
data.updated_at_ms = Date.now();
fs.mkdirSync(path.dirname(path.resolve(keyfile)), { recursive: true });
fs.writeFileSync(keyfile, `${JSON.stringify(data, null, 2)}\n`, { mode: 0o600 });

const recoveryFile = {
  type: "weall_recovery_key",
  version: 2,
  sigProfile: "pq-mldsa-v1",
  algorithm: "ML-DSA",
  parameterSet: "ML-DSA-65",
  secretKeyFormat: "mldsa65-seed-b64",
  account,
  publicKeyB64: bytesToB64(active.publicKey),
  secretKeyB64: bytesToB64(activeSeed),
  recoveryAuthorityPublicKeyB64: bytesToB64(recovery.publicKey),
  recoveryAuthoritySecretKeyB64: bytesToB64(recoverySeed),
  evidenceKemPublicKeyB64: data.evidence_kem_public_key_b64,
  evidenceKemSecretKeyB64: data.evidence_kem_secret_key_b64,
  createdAt: new Date().toISOString(),
  warning: "Controlled M2 actor recovery material. Keep private and delete after the rehearsal.",
};
if (recoveryOut) {
  fs.mkdirSync(path.dirname(path.resolve(recoveryOut)), { recursive: true });
  fs.writeFileSync(recoveryOut, `${JSON.stringify(recoveryFile, null, 2)}\n`, { mode: 0o600 });
}
console.log(JSON.stringify({ ok: true, account, keyfile, recovery_file: recoveryOut || null }));
