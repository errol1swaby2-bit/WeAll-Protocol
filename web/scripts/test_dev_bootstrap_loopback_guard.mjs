import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import {
  isLoopbackPeer,
  permitsLocalSecretRequest,
  protectDevBootstrapSecrets,
} from "./devBootstrapLoopbackGuard.mjs";

assert.equal(isLoopbackPeer("127.0.0.1"), true);
assert.equal(isLoopbackPeer("::1"), true);
assert.equal(isLoopbackPeer("::ffff:127.0.0.1"), true);
assert.equal(isLoopbackPeer("127.1.2.3"), true);
for (const remote of ["", "0.0.0.0", "192.168.1.20", "172.29.1.8", "8.8.8.8", "::ffff:192.168.0.2", "localhost"]) {
  assert.equal(isLoopbackPeer(remote), false, remote);
}

const valid = {
  remoteAddress: "127.0.0.1",
  host: "127.0.0.1:5173",
  origin: "http://127.0.0.1:5173",
  fetchSite: "same-origin",
};
assert.equal(permitsLocalSecretRequest(valid), true);
assert.equal(permitsLocalSecretRequest({ ...valid, origin: undefined, fetchSite: undefined }), true);
for (const altered of [
  { remoteAddress: "192.168.1.5" },
  { remoteAddress: "::ffff:192.168.1.5" },
  { host: "attacker.test:5173" },
  { host: "127.0.0.1.evil.test:5173" },
  { host: "127.0.0.1@attacker.test:5173" },
  { origin: "https://attacker.test" },
  { origin: "http://127.0.0.1:5174" },
  { fetchSite: "cross-site" },
]) {
  assert.equal(permitsLocalSecretRequest({ ...valid, ...altered }), false, JSON.stringify(altered));
}

function exercise(url, data = {}) {
  let nextCalled = false;
  const response = {
    statusCode: 200,
    headers: {},
    data: "",
    setHeader(key, val) { this.headers[key] = val; },
    end(body) { this.data = String(body || ""); },
  };
  protectDevBootstrapSecrets({
    url, socket: { remoteAddress: data.remoteAddress || "192.168.1.2" },
    headers: { host: data.host || "127.0.0.1:5173", ...(data.origin ? { origin: data.origin } : {}) },
  }, response, () => { nextCalled = true; });
  return { response, nextCalled };
}
for (const url of [
  "/v1/dev/bootstrap-secret?account=%40errol",
  "/v1/%64ev/bootstrap-secret?account=%40errol",
  "/v1/dev/demo-seed",
]) {
  const { response, nextCalled } = exercise(url);
  assert.equal(response.statusCode, 403, url);
  assert.equal(nextCalled, false, url);
  assert.match(response.data, /local_dev_bootstrap_only/);
  assert.equal(exercise(url, { remoteAddress: "127.0.0.1" }).nextCalled, true);
}
assert.equal(exercise("/v1/status").nextCalled, true);

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, "../..");
const launcher = resolve(repo, "Weall-Protocol/scripts/devnet_local_two_frontend_rehearsal.sh");
const launchText = readFileSync(launcher, "utf8");
assert.match(launchText, /FRONTEND_BIND_HOST="\$\{WEALL_LOCAL_REHEARSAL_FRONTEND_BIND_HOST:-127\.0\.0\.1\}"/);
const denied = spawnSync("bash", [launcher], {
  env: { ...process.env, WEALL_LOCAL_REHEARSAL_FRONTEND_BIND_HOST: "0.0.0.0" },
  encoding: "utf8", timeout: 15000,
});
assert.equal(denied.status, 2, denied.stderr);
assert.match(denied.stderr, /loopback-only frontend bind/);

const viteConfig = readFileSync(resolve(repo, "web/vite.config.ts"), "utf8");
assert.match(viteConfig, /server\.middlewares\.use\(protectDevBootstrapSecrets\)/);
assert.match(viteConfig, /host: "127\.0\.0\.1"/);
console.log("PASS: local-bootstrap protection denies remote and cross-origin secret requests");
