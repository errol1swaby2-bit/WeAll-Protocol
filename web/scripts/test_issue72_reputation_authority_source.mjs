import fs from "node:fs";
import path from "node:path";

const root = path.resolve(import.meta.dirname, "..");
const account = fs.readFileSync(path.join(root, "src/pages/Account.tsx"), "utf8");

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

assert(
  account.includes('Canonical informational aggregate'),
  "Account Matrix must label aggregate as informational rather than operative authority",
);
assert(
  account.includes("Not a role-permission or transaction-authorization score."),
  "Aggregate score must not be represented as an operative role gate",
);
assert(
  account.includes("Canonical event score") &&
    account.includes("Legacy observation (not scored for protocol roles)"),
  "Canonical and legacy matrix indicators must be distinguishable",
);
assert(
  account.includes("Reputation dimensions, including abuse-risk indicators, are publicly inspectable."),
  "Public-only reputation UI must not claim hidden abuse-risk dimensions",
);
assert(
  !account.includes("Internal abuse-risk signals stay hidden"),
  "Retired owner-only reputation text must remain absent",
);

console.log("PASS: Matrix canonical scoring and public-only frontend source contract");
