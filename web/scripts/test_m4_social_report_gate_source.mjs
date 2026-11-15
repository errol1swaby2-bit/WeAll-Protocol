import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const web = (path) => readFileSync(resolve(process.cwd(), path), "utf8");
const backend = (path) => readFileSync(resolve(process.cwd(), "..", path), "utf8");
const feed = web("src/components/FeedView.tsx");
const thread = web("src/pages/Thread.tsx");
const contentPage = web("src/pages/Content.tsx");
const applier = backend("Weall-Protocol/src/weall/runtime/apply/content.py");
const admission = JSON.parse(backend("Weall-Protocol/generated/tx_index.json"));
const admissionTier = (name) => {
  const tx = (admission.tx_types || []).find((item) => item.name === name);
  assert.ok(tx, "missing canonical transaction: " + name);
  return tx.subject_gate;
};
assert.equal(admissionTier("CONTENT_POST_CREATE"), "Tier2+");
assert.equal(admissionTier("CONTENT_REACTION_SET"), "Tier2+");
assert.equal(admissionTier("CONTENT_FLAG"), "Tier1+");
assert.equal(admissionTier("CONTENT_COMMENT_CREATE"), "Tier0+"); // lobby exception

const socialReadiness = backend("Weall-Protocol/docs/testnet/PUBLIC_SOCIAL_FLOW_READINESS.md");

function section(text, start, end) {
  const a = text.indexOf(start);
  assert.ok(a >= 0, "missing start: " + start);
  const b = text.indexOf(end, a + start.length);
  assert.ok(b > a, "missing end: " + end);
  return text.slice(a, b);
}

const canonicalReport = section(applier, "def _apply_content_flag(", "def _apply_content_media_declare(");
assert.match(canonicalReport, /min_tier=1, action="content_flag"/);
const canonicalComment = section(applier, "def _apply_comment_create(", "def _apply_comment_delete(");
assert.match(canonicalComment, /min_tier=0 if public_lobby else 2,/);
assert.match(canonicalComment, /parent_post.startsWith\("public-lobby:"\)/);
const canonicalReaction = section(applier, "def _apply_reaction_set(", "def _apply_content_flag(");
assert.match(canonicalReaction, /min_tier=2, action="content_tier2_action"/);
const canonicalPost = section(applier, "def _apply_post_create(", "def _apply_post_edit(");
assert.match(canonicalPost, /min_tier=2, action="content_post_create"/);
assert.ok(socialReadiness.includes("public-readable protocol state"), "public-only social read model must remain explicit");

assert.match(feed, /const reportGateTier1 = checkGates\([\s\S]*?requireTier: 1,/);
assert.match(feed, /const gateTier2 = checkGates\([\s\S]*?requireTier: 2,/);
assert.ok(section(feed, "async function doReport(", "return (").includes("if (!reportGateTier1.ok)"));
assert.ok(feed.includes("disabled={!id || !reportGateTier1.ok || flagBusyId === id || signerBusy}"));
assert.ok(feed.includes("disabled={!id || !gateTier2.ok || likeBusyId === id || signerBusy}"));

assert.match(thread, /const reportGate = checkGates\(\{[^}]*requireTier: 1 \}\)/);
assert.match(thread, /const gate = checkGates\(\{[^}]*requireTier: 2 \}\)/);
assert.ok(section(thread, "async function flagTarget(", "return (").includes("if (!reportGate.ok)"));
assert.ok(thread.includes("disabled={!reportGate.ok || signerBusy}"));
assert.ok(thread.includes("disabled={!gate.ok || likeBusyId === postId || signerBusy}"));
assert.ok(thread.includes("disabled={!gate.ok || busy || signerBusy}"));

assert.match(contentPage, /const reportGate = checkGates\(\{[^}]*requireTier: 1 \}\)/);
assert.match(contentPage, /const gate = checkGates\(\{[^}]*requireTier: 2 \}\)/);
assert.ok(section(contentPage, "async function doReport()", "return (").includes("if (!reportGate.ok)"));
assert.ok(contentPage.includes('onClick={doReport} disabled={!reportGate.ok || txBusy}'));
assert.ok(contentPage.includes('onClick={doEdit} disabled={!gate.ok || txBusy}'));
assert.ok(contentPage.includes("reportGateOk: reportGate.ok"));

console.log("OK: M4.2 public social report Tier1 / Tier2 source and backend alignment");
