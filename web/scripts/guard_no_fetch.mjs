#!/usr/bin/env node
/* global console, process */

/**
 * Guardrail: prevent direct fetch() usage outside the approved HTTP surfaces.
 *
 * Approved surfaces:
 *   - src/api/weall.ts        (canonical API client)
 *   - src/lib/nodeSelect.ts   (node probing + seed fetch with timeouts)
 *
 * Usage:
 *   node scripts/guard_no_fetch.mjs
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SRC_DIR = path.join(ROOT, "src");

const ALLOWLIST = new Set([
  path.normalize(path.join(SRC_DIR, "api", "weall.ts")),
  path.normalize(path.join(SRC_DIR, "lib", "nodeSelect.ts")),
]);

const EXT_OK = new Set([".ts", ".tsx", ".js", ".jsx"]);

function walk(dir) {
  const out = [];
  for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, ent.name);
    if (ent.isDirectory()) {
      if (ent.name === "node_modules" || ent.name === "dist" || ent.name === "build") continue;
      out.push(...walk(p));
      continue;
    }
    if (!ent.isFile()) continue;
    const ext = path.extname(ent.name);
    if (!EXT_OK.has(ext)) continue;
    out.push(p);
  }
  return out;
}

function findFetchUsages(text) {
  const lines = text.split(/\r?\n/);
  const hits = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.includes("fetch(") || line.includes("globalThis.fetch(")) {
      hits.push({ lineNo: i + 1, line });
    }
  }
  return hits;
}

function main() {
  if (!fs.existsSync(SRC_DIR)) {
    console.error(`ERROR: src dir not found at ${SRC_DIR}`);
    process.exit(1);
  }

  const files = walk(SRC_DIR);
  const violations = [];

  for (const f of files) {
    const norm = path.normalize(f);
    const txt = fs.readFileSync(f, "utf8");
    const hits = findFetchUsages(txt);
    if (!hits.length) continue;
    if (ALLOWLIST.has(norm)) continue;

    for (const h of hits) {
      violations.push(`${path.relative(ROOT, norm)}:${h.lineNo}: ${h.line.trim()}`);
    }
  }

  if (violations.length) {
    console.error("ERROR: fetch() used outside approved surfaces.");
    console.error("Approved surfaces:");
    for (const a of Array.from(ALLOWLIST.values())) {
      console.error(`  - ${path.relative(ROOT, a)}`);
    }
    console.error("\nViolations:");
    console.error(violations.join("\n"));
    process.exit(1);
  }

  console.log("OK: fetch() usage restricted to src/api/weall.ts and src/lib/nodeSelect.ts");
}

main();
