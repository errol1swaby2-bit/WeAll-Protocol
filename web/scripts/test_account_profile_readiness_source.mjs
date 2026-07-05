import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

const webRoot = resolve(process.cwd());
const repoRoot = resolve(process.cwd(), "..");

function readWeb(rel) {
  return readFileSync(resolve(webRoot, rel), "utf8");
}

function readRepo(rel) {
  return readFileSync(resolve(repoRoot, rel), "utf8");
}

function assertIncludes(src, needle, label) {
  if (!src.includes(needle)) {
    throw new Error(`${label}: missing ${needle}`);
  }
}

function assertNotIncludes(src, needle, label) {
  if (src.includes(needle)) {
    throw new Error(`${label}: forbidden phrase ${needle}`);
  }
}

const account = readWeb("src/pages/Account.tsx");
const api = readWeb("src/api/weall.ts");
const packageJson = readWeb("package.json");
const first15 = readRepo("Weall-Protocol/docs/testnet/FIRST_15_MINUTES.md");
const readinessPath = resolve(repoRoot, "Weall-Protocol/docs/testnet/ACCOUNT_PROFILE_READINESS.md");
if (!existsSync(readinessPath)) {
  throw new Error("docs/testnet/ACCOUNT_PROFILE_READINESS.md must exist");
}
const readiness = readFileSync(readinessPath, "utf8");

for (const needle of [
  "Account/profile readiness boundary",
  "PoH/Tier status is protocol eligibility, not real-world identity certainty.",
  "Canonical account id",
  "Account public key summary",
  "Public profile source",
  "profileTruthBoundary",
  "profileReceiptStatusTemplate",
  "Protocol-state versus local draft",
  "Local form fields are not protocol state.",
  "Profile action submitted",
  "Track in Transactions",
  "PROFILE_UPDATE",
  "profileResultTxId",
  "data-testid=\"profile-tx-status-callout\"",
]) {
  assertIncludes(account, needle, "Account/profile readiness UX contract");
}

for (const needle of [
  "PublicProfileResponse",
  "receipt_paths?: Record<string, string>",
  "/v1/accounts/${encodeURIComponent(account)}/profile",
  "/v1/accounts/tx/profile-update",
]) {
  assertIncludes(api, needle, "Account/profile API client contract");
}

for (const needle of [
  "# Account and public profile readiness",
  "local form draft → PROFILE_UPDATE skeleton → local signature → /v1/tx/submit → /v1/tx/status/{tx_id} → committed public profile read model",
  "PoH/Tier status is protocol eligibility.",
  "It must not be described as legal identity proof",
  "The profile surface must not request or expose raw PoH evidence",
  "Ready for controlled internal/public-observer rehearsal candidate, with public beta readiness still blocked by explicit external evidence gates.",
]) {
  assertIncludes(readiness, needle, "Account/profile readiness doc");
}

assertIncludes(first15, "Account and public profile readiness", "First 15 minutes doc must link account/profile readiness");
assertIncludes(packageJson, "test:account-profile-readiness-source", "package script must expose account/profile readiness source check");

const checked = [account, readiness, first15].join("\n");
for (const forbidden of [
  "legal identity proof confirmed",
  "real-world identity certainty confirmed",
  "profile is confirmed after submit",
  "local browser signer grants protocol authority",
  "Public beta ready",
  "Mainnet ready",
  "public multi-validator BFT ready",
  "live economics ready",
  "automatic protocol upgrades enabled",
  "production helper execution ready",
  "legal approval granted",
]) {
  assertNotIncludes(checked, forbidden, "Account/profile surfaces must not overclaim");
}

console.log("OK: account/profile readiness source checks passed");
