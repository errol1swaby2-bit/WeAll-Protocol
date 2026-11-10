import { readFileSync } from "node:fs";
import assert from "node:assert/strict";

const read = (path) => readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
const groups = read("src/pages/Group.tsx");
const tabs = read("src/lib/groupProfileTabs.ts");
const oversight = read("src/lib/groupOversight.ts");
const decisionScope = read("src/lib/groupDecisionScope.ts");
const createDecision = read("src/pages/ProposalCreate.tsx");
const app = read("src/App.tsx");
const css = read("src/styles.css");
const shell = read("src/components/AppShell.tsx");
const nav = read("src/components/PrimaryNavigation.tsx");
const sidebar = read("src/components/SidebarNav.tsx");
const router = read("src/lib/router.ts");
const verification = read("src/pages/AccountVerificationPage.tsx");
const verificationSections = read("src/lib/verificationSections.ts");
const account = read("src/pages/Account.tsx");
const accountTabs = read("src/lib/accountProfileTabs.ts");
const reviewer = read("src/pages/JurorDashboard.tsx");
const reviewerWorkspaces = read("src/lib/reviewerWorkspaces.ts");
const settings = read("src/pages/Settings.tsx");
const settingsSections = read("src/lib/settingsSections.ts");
const themePresets = read("src/lib/themePresets.ts");

for (const tab of ["posts", "about", "members", "decisions", "governance", "treasury", "reports", "responsibilities", "emissaries"]) {
  assert.ok(tabs.includes(`id: "${tab}"`), `Missing group tab: ${tab}`);
  assert.ok(groups.includes(`activeTab === "${tab}"`), `Missing focused pane: ${tab}`);
}
assert.ok(tabs.includes('new URLSearchParams(query).get("tab")'), "Group tabs must have linkable query state");
assert.ok(groups.includes('window.addEventListener("hashchange", onHashChange)'), "Direct links and back/forward must change group tabs");
assert.ok(groups.includes("async function decideMembership"), "Existing signed membership moderation must remain");
assert.ok(tabs.includes("groupWorkspaceTabFromHash"), "Role-specific desk must be separate from public group profile tabs");
for (const desk of ["reports", "moderation_review", "emissary_work"]) {
  assert.ok(groups.includes(`activeTab === "${desk}"`), `Group workspace missing: ${desk}`);
}
assert.ok(router.includes("emissaries\\/work"), "Emissary work must be a bounded group-local deep link");
assert.ok(router.includes("manage\\/(?:members|moderation)"), "Group moderator desks must be separately routed");
assert.ok(groups.includes('groupReportSource(item, selected, postIds)'), "Never infer group dispute scope from a route parameter");
assert.ok(groups.includes('!canModerate ?'), "Unassigned group moderation routes must not expose group-role controls");
assert.ok(groups.includes('No verdict or removal controls are available here.'), "Group reports must not confer juror verdict power");
assert.ok(oversight.includes("groupReportSource"), "Group reports must use a shared safe scope classifier");
assert.ok(oversight.includes("publicRoleAccounts"), "Canonical moderator arrays and role maps must both be handled");
const ts = await import("typescript");
const compiled = ts.transpileModule(oversight, { compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 } }).outputText;
const { groupReportSource, publicRoleAccounts } = await import(`data:text/javascript;base64,${Buffer.from(compiled).toString("base64")}`);
const compiledRouter = ts.transpileModule(router, { compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 } }).outputText;
const { matchRoute } = await import(`data:text/javascript;base64,${Buffer.from(compiledRouter).toString("base64")}`);
const compiledScope = ts.transpileModule(decisionScope, { compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 } }).outputText;
const { requireExactGroupProposalScope, verifiedGroupContract } = await import(`data:text/javascript;base64,${Buffer.from(compiledScope).toString("base64")}`);
assert.deepEqual(matchRoute("/groups/group-a/decisions/new"), { path: "/groups/:id/decisions/new", id: "group-a" });
assert.deepEqual(matchRoute("/groups/group-a/emissaries/elections"), { path: "/groups/:id", id: "group-a" });
assert.deepEqual(matchRoute("/groups/group-a/emissaries/elections/election-1"), { path: "/groups/:id", id: "group-a" });
assert.ok(app.includes('<ProposalCreate scopeGroupId={route.id} />'), "Group decision deep link must bind composer to exact canonical route ID");
assert.ok(createDecision.includes('requireExactGroupProposalScope(payload, groupContextId)'), "Group proposal payload must be validated against route group ID");
assert.ok(createDecision.includes('const currentGroup = await api.groups.governance(groupContextId, base)'), "Canonical group contract must be refreshed before signing");
assert.ok(createDecision.includes('groupContextId ? "" : actionTxType'), "Group context must not carry a stale executable action");
assert.ok(createDecision.includes('scopedGroupStatus !== "ready"'), "Group signing blocked until canonical contract is read");
assert.ok(groups.includes('activeTab === "election_detail"'), "Election detail must have an explicit read-only panel");
assert.ok(groups.includes('A candidate count cannot authorize a signed ballot'), "Missing candidate and voter roster must block ballot creation");
assert.ok(!groups.includes('tx_type: "GROUP_EMISSARY_BALLOT_CAST"'), "Do not enable blind ranked ballots");
assert.equal(verifiedGroupContract({ok:true,group_id:"g1"}, "g1"),true);
assert.equal(verifiedGroupContract({ok:true,group_id:"g2"}, "g1"),false);
assert.equal(verifiedGroupContract({ok:false,group_id:"g1"}, "g1"),false);
requireExactGroupProposalScope({ group_id: "g1", electorate_scope: "group_members" }, "g1");
for (const bad of [
 { group_id: "g2", electorate_scope: "group_members" },
 { group_id: "g1", electorate_scope: "protocol" },
 { group_id: "g1", electorate_scope: "group_members", scope_id: "g2" },
 { electorate_scope: "group_members" },
]) assert.throws(() => requireExactGroupProposalScope(bad, "g1"), /scope|group/i);
for (const route of [
  "/groups/group-a/manage/members",
  "/groups/group-a/manage/moderation",
  "/groups/group-a/emissaries/work",
  "/groups/group-a/responsibilities",
  "/groups/group-a/reports",
]) {
  assert.deepEqual(matchRoute(route), { path: "/groups/:id", id: "group-a" }, `Group task route must preserve exact group ID: ${route}`);
}
assert.deepEqual(matchRoute("/groups/group-a"), { path: "/groups/:id", id: "group-a" });

assert.deepEqual(publicRoleAccounts({ alice: { active: true }, bob: {} }), ["alice", "bob"]);
assert.deepEqual(publicRoleAccounts([" bob ", "alice", "bob"]), ["alice", "bob"]);
const ids = new Set(["post-in-group"]);
assert.equal(groupReportSource({ target_type: "content", target_id: "post-in-group" }, "g1", ids), "returned_group_post");
assert.equal(groupReportSource({ target_type: "content", target_id: "post-in-group", target_content_snapshot: { group_id: "other" } }, "g1", ids), null);
assert.equal(groupReportSource({ target_type: "content", target_id: "hidden", target_content_snapshot: { group_id: "g1" } }, "g1", ids), "canonical_target_snapshot");
assert.equal(groupReportSource({ target_type: "comment", target_id: "post-in-group" }, "g1", ids), null);
assert.equal(groupReportSource({ target_type: "poh", target_id: "post-in-group" }, "g1", ids), null);
assert.ok(tabs.includes('return "membership_review"'), "Deep-linked membership moderator desk must select the focused panel");
assert.ok(router.includes("groupRoleRoute"), "Group role paths must resolve before the catch-all group ID");
assert.ok(router.includes('manage\\/(?:members|moderation)'), "Moderator task paths must be explicitly bounded");
assert.ok(groups.includes('activeTab === "membership_review"'), "Moderator request task must have a focused workspace");
assert.ok(groups.includes('GROUP_PROFILE_TABS.filter((tab) => tab.id !== "responsibilities" || !!acct)'), "Anonymous visitors must not see role navigation");
assert.ok(groups.includes('!acct || !canSign ?') && groups.includes('!canModerate ?'), "Unassigned or signerless users must see no applicant queue or action");
assert.ok(groups.includes('Object.prototype.hasOwnProperty.call(freshRequests, member)'), "Signed membership decisions must recheck a live pending request");
assert.ok(groups.includes('freshModerators.some'), "Signed membership decisions must recheck live moderator listing");
assert.ok(groups.includes('tx_type: "GROUP_MEMBERSHIP_DECIDE"'), "Do not replace canonical signed decisions with UI-only approval");
assert.ok(groups.includes('No approval controls or pending applicant accounts are displayed.'), "No pending applicant disclosure without group moderator listing");
assert.ok(groups.includes("async function reportGroupPost"), "Existing report flow must remain");
assert.ok(groups.includes("Group governance contract"), "Public group governance reads must remain");
assert.ok(groups.includes('String(item?.group_id || item?.raw?.group_id || "").trim() === selected'), "Group decision reads must use exact canonical scope");
assert.ok(groups.includes("does not expose a verified group treasury ledger"), "No fake economic activation");
assert.ok(groups.includes("A ballot or elected emissary"), "Treasury mandate cannot be inferred from roles");
assert.ok(groups.includes("Frontend cache authority: never"), "UI cannot grant governance authority");
assert.ok(nav.includes('aria-label="Main navigation"'), "Five-destination navigation must have landmark");
assert.ok(shell.includes("<PrimaryNavigation currentPath={route.path}"), "Shell must mount primary navigation");
assert.ok(shell.includes("hidePrimary onNavigate="), "Popover should offer secondary navigation, not duplicate the five fixed destinations");
assert.ok(sidebar.includes("PRIMARY_DESTINATIONS"), "Secondary menu must filter fixed destinations");
assert.ok(groups.includes('detailDescription || "Public community profile.'), "Group identity should show the actual public group description");
assert.ok(css.includes("@media (max-width: 640px)"), "Mobile breakpoint required");
assert.ok(css.includes("safe-area-inset-bottom"), "Mobile safe-area padding required");

for (const alias of [
  'r === "/start"',
  'r === "/me"',
  'r === "/feed/new"',
  'r === "/groups/new"',
  'r === "/decisions/new"',
  'r === "/tasks"',
  'r === "/me/security/sessions"',
  'r === "/me/transactions"',
  'r === "/protocol/economics"',
  'r === "/protocol/tools"',
  'r.startsWith("/people/")',
]) {
  assert.ok(router.includes(alias), `Missing backward-compatible target alias: ${alias}`);
}
assert.ok(router.includes('r.slice("/people/".length)'), "Public-profile handle must be preserved across aliases");
for (const section of ["overview", "async", "live", "responsibilities", "history", "technical"]) {
  assert.ok(verificationSections.includes(`id: "${section}"`), `Missing verification section: ${section}`);
  assert.ok(verification.includes(`activeSection !== "${section}"`), `Verification must have focused section: ${section}`);
}
assert.ok(verification.includes('asyncRecordingState === "recording" && requested !== "async"'), "Switching sections must not hide an active camera recording");
assert.ok(verification.includes("Recording fresh verification video") || verification.includes("Record fresh verification video"), "Camera capture action must survive layout refactor");
assert.ok(verification.includes("Assigned reviewers may view this evidence"), "Evidence consent must remain visible");
assert.ok(verification.includes("submitAsyncEvidence()"), "Signed async submission must remain");
assert.ok(verification.includes("submitLiveRequest()"), "Signed live request must remain");
assert.ok(router.includes('r === "/verification/async"'), "Dedicated verification entry alias required");
assert.ok(css.includes(".verificationSection[hidden]"), "Inactive verification panels must actually hide");
for (const tab of ["posts", "overview", "reputation", "eligibility", "responsibilities", "node"]) {
  assert.ok(accountTabs.includes(`id: "${tab}"`), `Missing account tab: ${tab}`);
  assert.ok(account.includes(`activeProfileTab !== "${tab}"`), `Account UI missing focused pane: ${tab}`);
}
assert.ok(accountTabs.includes("!tab.ownerOnly || isOwner"), "Public visitors cannot open owner-only panels");
assert.ok(accountTabs.includes('id: "appearance"'), "Public profile edit needs owner-only tab");
assert.ok(account.includes('activeProfileTab !== "appearance"'), "Public profile edits need a focused panel");
assert.ok(account.includes('open={profileDirty || activeProfileTab === "appearance"}'), "Public profile editor must open when its section is selected");
assert.ok(router.includes('r === "/me/profile-appearance"'), "Owner appearance deep-link missing");
assert.ok(account.includes('banner_cid: bannerChanged ? bannerDraftCid : undefined'), "Only new banner CIDs can be submitted in signed PROFILE_UPDATE");
assert.ok(account.includes('bannerRemovalUnsupported'), "Public banner removal must fail closed when protocol schema rejects empty values");
assert.ok(account.includes('publicProfile.banner_media'), "Other accounts need canonical public banner reference");
assert.ok(account.includes('Hide decorative background'), "Viewers need a decorative suppression control");
assert.ok(account.includes('!bannerDraftValid'), "Invalid banner CIDs must not be signed");
assert.ok(css.includes(".publicProfileBanner img"), "Public banner image must be bounded");
assert.ok(account.includes("ACCOUNT_PROFILE_TABS.filter((entry) => isSelf || !entry.ownerOnly)"), "Visitor nav must exclude owner-only tabs");
assert.ok(account.includes('title="Public posts"'), "Public post feed must remain");
assert.ok(account.includes("async function") || account.includes("function runOperatorTx"), "Existing signed operator actions must remain");
assert.ok(css.includes(".accountProfilePane[hidden]"), "Inactive public profile sections must hide");
for (const section of ["overview", "content_review", "dispute_review", "poh_async_review", "poh_live_review", "reported"]) {
  assert.ok(reviewerWorkspaces.includes(`id: "${section}"`), `Missing reviewer workspace: ${section}`);
  assert.ok(reviewer.includes(`workspace === "${section}"`), `Reviewer page missing focused section: ${section}`);
}
for (const path of ["/tasks/content", "/tasks/disputes", "/tasks/poh-async", "/tasks/poh-live"]) {
  assert.ok(router.includes(`r === "${path}"`), `Missing reviewer path: ${path}`);
  assert.ok(reviewerWorkspaces.includes(`href: "${path}"`), `Reviewer nav must use its named route: ${path}`);
}
assert.ok(reviewer.includes('aria-label="Reviewer workspaces"'), "Reviewer workspace navigation needs named landmark");
assert.ok(reviewer.includes('title="Assigned content reviews"'), "Content context is still separate from dispute actions");
assert.ok(reviewer.includes('title="Assigned dispute work"'), "Dispute jury has its own focused view");
assert.ok(reviewer.includes('title="Reports you submitted"'), "Reporter tracking is separated from jury service");
assert.ok(reviewer.includes('reviewerLaneStatus("dispute_review").label'), "Dispute decisions must display canonical lane opt-in posture");
assert.ok(reviewer.includes('item?.ciphertext_cid || item?.encrypted_blob_cid'), "Protected identity evidence remains excluded from ordinary media gallery");
assert.ok(reviewer.includes('encryptedEvidence.length && reviewerEvidenceUnlocked'), "Protected evidence remains gated by accepted assignment");
assert.ok(reviewer.includes('async function') && reviewer.includes('submitSkeletonTx'), "Existing signed review path must remain");
assert.ok(css.includes(".reviewerWorkspaceTab:focus-visible"), "Reviewer workspace tabs must support visible keyboard focus");
for (const name of ["overview", "connection", "themes", "layout", "accessibility", "advanced"]) {
  assert.ok(settingsSections.includes(`id: "${name}"`), `Missing settings section: ${name}`);
}
for (const url of ["/settings/connection", "/settings/themes", "/settings/layout", "/settings/accessibility", "/settings/advanced"]) {
  assert.ok(router.includes(`r === "${url}"`), `Missing settings route alias: ${url}`);
}
assert.ok(settings.includes('aria-label="Theme presets"'), "Theme gallery needs an accessible name");
assert.ok(settings.includes('aria-pressed={selected}'), "Selected appearance preset must be distinguishable");
assert.ok(settings.includes('saveSettings(next)'), "Theme changes remain browser-local settings");
assert.ok(themePresets.includes('THEME_PRESETS'), "Safe, built-in theme palettes required");
assert.ok(!themePresets.includes('url('), "Preset theme file must not fetch background images");
assert.ok(!settings.includes('FileReader'), "No private wallpapers in v1.6");
assert.ok(css.includes(".settingsSectionTab:focus-visible"), "Keyboard focus required on settings category navigation");
console.log("OK: v1.6 grouped reviewers, focused settings, browser-local theme presets and route aliases");
