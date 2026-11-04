import fs from "node:fs";
import path from "node:path";

const root = path.resolve(import.meta.dirname, "..");
const read = (p) => fs.readFileSync(path.join(root, p), "utf8");
const state = read("src/lib/activityReadState.ts");
const bell = read("src/components/ActivityBell.tsx");
const page = read("src/pages/Activity.tsx");
const shell = read("src/components/AppShell.tsx");

function assert(value, message) {
  if (!value) throw new Error(message);
}

assert(
  ["chain_id", "genesis_id", "encodeURIComponent(base.trim())", "encodeURIComponent(owner)"]
    .every((part) => state.includes(part)),
  "Local read-state storage must be scoped by node, chain, genesis, and account",
);
assert(
  state.includes('if (!key) return') && state.includes("window.localStorage.setItem"),
  "Missing chain identity must fail closed on local persistence",
);
assert(
  state.includes('if (item.priority === "high") return true'),
  "High-priority public safety/review notices cannot be muted from attention",
);
assert(
  bell.includes("countRecentAttention") && bell.includes("readActivityPreference"),
  "Header bell must use shared local read/attention semantics",
);
assert(
  bell.includes("response?.account_id !== account"),
  "Header bell must reject cross-account notices",
);
assert(
  bell.includes('count unavailable'),
  "Failed API response must not be represented as zero notices",
);
assert(
  page.includes('aria-label="Local notification preferences"') &&
  page.includes('type="time"') &&
  page.includes('Mute normal-priority categories'),
  "Activity page must expose local quiet hours and category mutes",
);
assert(
  !page.includes("stateSnapshot(") && !page.includes("JSON.stringify(snapshot)"),
  "Activity page may not derive recipient relevance from arbitrary state text",
);
assert(
  shell.includes("ActivityBell") && shell.includes("refreshToken={routeKey}"),
  "Header must mount the real notification component across route changes",
);

console.log("PASS: scoped notification attention, high-priority override, and UI source contract");
