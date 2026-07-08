import fs from "node:fs";

const keys = fs.readFileSync(new URL("../src/auth/keys.ts", import.meta.url), "utf8");
const session = fs.readFileSync(new URL("../src/auth/session.ts", import.meta.url), "utf8");
const login = fs.readFileSync(new URL("../src/pages/LoginPage.tsx", import.meta.url), "utf8");

function assert(cond, msg) {
  if (!cond) {
    console.error(`FAIL: ${msg}`);
    process.exit(1);
  }
}

assert(keys.includes('import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";'), "browser keys import noble ML-DSA-65");
assert(keys.includes('export const BROWSER_PQ_SIG_PROFILE = "pq-mldsa-v1"'), "browser signing profile is pq-mldsa-v1");
assert(keys.includes("ml_dsa65.keygen(seed)"), "browser key generation uses ML-DSA-65 seed keygen");
assert(keys.includes("ml_dsa65.sign(msgBytes, secretKey)"), "browser signing uses ML-DSA-65 over canonical bytes");
assert(keys.includes("ml_dsa65.verify(sig, msg, expectedPublicKey)"), "browser validation verifies ML-DSA signatures over canonical bytes");
assert(!keys.includes("MLDSA_CONTEXT"), "browser does not use primitive ML-DSA context fallback");
assert(!keys.includes(["browser", "pq", "signing", "not", "implemented"].join("_")), "browser PQ signing placeholder is removed from key module");
assert(session.includes('sig_profile: BROWSER_PQ_SIG_PROFILE'), "session login sends explicit pq signature profile");
assert(session.includes('domain_separator: "weall.session.login.v1"'), "session login canonical payload is domain separated");
assert(login.includes("ensureKeypair(account)"), "normal account creation uses browser key generation path");

console.log("OK: browser ML-DSA signing source checks passed");
