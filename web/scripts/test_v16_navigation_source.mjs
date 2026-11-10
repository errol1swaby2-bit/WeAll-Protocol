import { readFileSync } from "node:fs";
import assert from "node:assert/strict";

const read = (path) => readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
const groups = read("src/pages/Group.tsx");
const tabs = read("src/lib/groupProfileTabs.ts");
const css = read("src/styles.css");
const shell = read("src/components/AppShell.tsx");
const nav = read("src/components/PrimaryNavigation.tsx");

for (const tab of ["posts", "about", "members", "governance", "emissaries"]) {
  assert.ok(tabs.includes(`id: "${tab}"`), `Missing group tab: ${tab}`);
  assert.ok(groups.includes(`activeTab === "${tab}"`), `Missing focused pane: ${tab}`);
}
assert.ok(tabs.includes('new URLSearchParams(query).get("tab")'), "Group tabs must have linkable query state");
assert.ok(groups.includes('window.addEventListener("hashchange", onHashChange)'), "Direct links and back/forward must change group tabs");
assert.ok(groups.includes("async function decideMembership"), "Existing signed membership moderation must remain");
assert.ok(groups.includes("async function reportGroupPost"), "Existing report flow must remain");
assert.ok(groups.includes("Group governance contract"), "Public group governance reads must remain");
assert.ok(groups.includes("Frontend cache authority: never"), "UI cannot grant governance authority");
assert.ok(nav.includes('aria-label="Main navigation"'), "Five-destination navigation must have landmark");
assert.ok(shell.includes("<PrimaryNavigation currentPath={route.path}"), "Shell must mount primary navigation");
assert.ok(css.includes("@media (max-width: 640px)"), "Mobile breakpoint required");
assert.ok(css.includes("safe-area-inset-bottom"), "Mobile safe-area padding required");

console.log("OK: v1.6 group tabs and stable primary navigation source contracts");
