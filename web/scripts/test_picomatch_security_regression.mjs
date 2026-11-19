import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync, readdirSync, realpathSync, existsSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

// GHSA-fc5q-39xc-vjpf / CVE-2026-112366. This is an independent
// finite behavioral regression, not a replacement for npm audit or proof
// that arbitrary glob inputs are safe. Never match these inputs in the
// parent process: the vulnerable regex can block Node's event loop.
const root = fileURLToPath(new URL("../", import.meta.url));
const lock = JSON.parse(readFileSync(resolve(root, "package-lock.json"), "utf8"));
assert.ok(lock.packages && typeof lock.packages === "object", "Expected locked npm package inventory");

const installed = Object.entries(lock.packages).filter(([path, metadata]) =>
  path && (/(^|\/)node_modules\/picomatch$/.test(path) || metadata.name === "picomatch")
);
// Removal is the remedy, not a skipped test: inspect lock identities, aliases
// and the actual installed package manifests, including scoped/nested packages.
const forbidden = new Set(["picomatch", "vite", "@vitejs/plugin-react", "tinyglobby", "fdir"]);
const violations = Object.entries(lock.packages).filter(([path, metadata]) =>
  path && (forbidden.has(path.split("node_modules/").at(-1)) || forbidden.has(metadata.name) ||
    /\/(?:picomatch|vite|tinyglobby|fdir)\/-\/|\/@vitejs\/plugin-react\/-\/|\/plugin-react-/.test(metadata.resolved || ""))
);
const modules = resolve(root, "node_modules");
assert.ok(existsSync(modules), "Frozen installation required before dependency regression");
const visited = new Set();
const actual = [];
function scan(directory) {
  if (!existsSync(directory)) return;
  const real = realpathSync(directory);
  if (visited.has(real)) return;
  visited.add(real);
  for (const item of readdirSync(directory, { withFileTypes: true })) {
    if (item.name.startsWith(".")) continue;
    const path = resolve(directory, item.name);
    if (item.name.startsWith("@")) { scan(path); continue; }
    if (!existsSync(resolve(path, "package.json"))) continue;
    const metadata = JSON.parse(readFileSync(resolve(path, "package.json"), "utf8"));
    if (forbidden.has(item.name) || forbidden.has(metadata.name)) actual.push(metadata.name);
    scan(resolve(path, "node_modules"));
  }
}
scan(modules);
const esbuild = JSON.parse(readFileSync(resolve(modules, "esbuild/package.json"), "utf8"));
assert.equal(esbuild.version, lock.packages["node_modules/esbuild"].version);


const cases = [
  { label: "ordinary recursive source glob", pattern: "src/**/*.tsx", input: "src/pages/Feed.tsx", expected: true },
  { label: "ordinary extension rejection", pattern: "src/**/*.tsx", input: "src/pages/Feed.py", expected: false },
  { label: "ordinary alternation", pattern: "+(a|b)", input: "abba", expected: true },
  { label: "single-branch wildcard positive", pattern: "+(*)", input: "example", expected: true },
  { label: "single-branch suffix positive", pattern: "+(*a)", input: "ba", expected: true },
  { label: "single-branch wildcard rejection", pattern: "+(*)", input: "a".repeat(28) + "/z", expected: false },
  { label: "single-branch suffix rejection", pattern: "+(*a)", input: "a".repeat(28) + "!", expected: false },
  { label: "zero-or-more suffix rejection", pattern: "*(*a)", input: "a".repeat(28) + "!", expected: false },
];

const worker = [
  'const [entry, pattern, input, expected] = process.argv.slice(1);',
  'const picomatch = require(entry);',
  'const actual = picomatch.isMatch(input, pattern);',
  'if (actual !== (expected === "true")) {',
  '  console.error("Unexpected match result:", actual, "expected:", expected);',
  '  process.exit(1);',
  '}',
].join("\n");

let failures = 0;
for (const [path, metadata] of installed) {
  const entry = resolve(root, path);
  const actualMetadata = JSON.parse(readFileSync(resolve(entry, "package.json"), "utf8"));
  assert.equal(actualMetadata.version, metadata.version, "Installed dependency differs from lock");
  console.log(`Checking ${path}@${actualMetadata.version} (${cases.length} bounded cases)`);

  for (const { label, pattern, input, expected } of cases) {
    const result = spawnSync(process.execPath, ["-e", worker, "--", entry, pattern, input, String(expected)], {
      cwd: root,
      encoding: "utf8",
      timeout: 2000,
      killSignal: "SIGKILL",
      maxBuffer: 64 * 1024,
      windowsHide: true,
    });
    if (result.error || result.status !== 0 || result.signal) {
      failures += 1;
      console.error(`FAIL: ${label}: ${result.error?.code || result.signal || result.status}`);
      if (result.stderr) console.error(result.stderr.trim().slice(0, 1000));
    } else {
      console.log(`PASS: ${label}`);
    }
  }
}
assert.equal(failures, 0, "Picomatch behavioral regression failed; dependency remediation required");
assert.deepEqual(violations.map(([path]) => path), [], "Vulnerable dependency chain returned to locked graph");
assert.deepEqual(actual, [], "Vulnerable dependency chain present in installed graph");
console.log("PASS: Picomatch advisory dependency removed from locked and installed graphs; original behavioral vectors retained for accidental reintroduction");
