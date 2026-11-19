import assert from "node:assert/strict";

import {
  activityReadKey,
  countRecentAttention,
  DEFAULT_ACTIVITY_PREFERENCE,
  getReadActivityIds,
  readActivityPreference,
  setReadActivityIds,
  writeActivityPreference,
} from "../src/lib/activityReadState.ts";

const entries = new Map();
const events = [];
globalThis.window = {
  localStorage: {
    getItem(key) { return entries.has(key) ? entries.get(key) : null; },
    setItem(key, value) { entries.set(key, value); },
  },
  dispatchEvent(event) { events.push(event.type); },
};

const identity = { chain_id: "chain-A", genesis_id: "genesis-A" };
const key = activityReadKey("http://localhost:8000", "@alice", identity);
assert.ok(key.includes("chain-A"));
assert.ok(key.includes("genesis-A"));
assert.notEqual(key, activityReadKey("http://localhost:8000", "@bob", identity));
assert.notEqual(key, activityReadKey("http://localhost:9000", "@alice", identity));
assert.notEqual(key, activityReadKey("http://localhost:8000", "@alice", {
  chain_id: "chain-A", genesis_id: "genesis-B",
}));
assert.equal(activityReadKey("http://localhost:8000", "@alice", { chain_id: "chain-A" }), "");

const items = [
  { id: "reply", type: "reply", priority: "normal" },
  { id: "governance", type: "governance_notice", priority: "normal" },
  { id: "review", type: "dispute_assignment", priority: "high" },
];
const base = DEFAULT_ACTIVITY_PREFERENCE;
assert.equal(countRecentAttention(items, [], base, new Date(2026, 9, 30, 10, 0)), 3);

setReadActivityIds(key, ["reply", "reply"]);
assert.deepEqual(getReadActivityIds(key), ["reply"]);
assert.deepEqual(getReadActivityIds(activityReadKey("http://localhost:8000", "@bob", identity)), []);
assert.equal(countRecentAttention(items, getReadActivityIds(key), base), 2);

const pref = {
  mutedTypes: ["governance_notice", "dispute_assignment"],
  quietHours: { enabled: true, start: "22:00", end: "08:00" },
};
writeActivityPreference(key, pref);
assert.deepEqual(readActivityPreference(key), pref);
assert.equal(countRecentAttention(items, [], pref, new Date(2026, 9, 30, 23, 0)), 1);
assert.equal(countRecentAttention(items, [], pref, new Date(2026, 9, 30, 7, 59)), 1);
assert.equal(countRecentAttention(items, [], pref, new Date(2026, 9, 30, 8, 0)), 2);
assert.equal(countRecentAttention(items, ["review"], pref, new Date(2026, 9, 30, 23, 0)), 0);

assert.ok(events.includes("weall:activity-read-changed"));
assert.equal(entries.has(":preference"), false);
assert.equal(readActivityPreference(""), base);

console.log("PASS: local read isolation, mute filtering, overnight quiet hours, high-priority override");
