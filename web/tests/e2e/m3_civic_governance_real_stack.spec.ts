import fs from "node:fs";
import path from "node:path";

import { expect, test, type APIRequestContext, type Browser, type BrowserContext } from "@playwright/test";

type PublicActor = {
  role: string;
  account: string;
  recovery_file?: string;
  storage_state: string;
};

type M3Journey = {
  post_id: string;
  group_id: string;
  dispute_id: string;
  proposal_id: string;
  expected_dispute_stage?: string;
  expected_dispute_outcome?: string;
  expected_proposal_stage?: string;
  minimum_final_ballots?: number;
};

type M3ActorManifest = {
  schema_version: number;
  backend_base_url: string;
  actors: PublicActor[];
  journey: M3Journey;
};

const REQUIRED_SINGLETON_ROLES = ["author_proposer", "member_reporter_voter"] as const;
const FRONTEND_BASE_URL = process.env.PLAYWRIGHT_BASE_URL ?? "http://127.0.0.1:5173";

function absoluteExistingFile(value: string, label: string): string {
  const absolute = path.resolve(String(value || ""));
  expect(fs.existsSync(absolute), `${label} does not exist: ${absolute}`).toBe(true);
  return absolute;
}

function loadActorManifest(): M3ActorManifest {
  const manifestPath = String(process.env.WEALL_M3_ACTOR_MANIFEST || "").trim();
  expect(
    manifestPath,
    "M3 actor manifest is required. The closure journey must use independent real actor custody states.",
  ).not.toBe("");

  const absolute = absoluteExistingFile(manifestPath, "M3 actor manifest");
  const manifest = JSON.parse(fs.readFileSync(absolute, "utf8")) as M3ActorManifest;
  expect(manifest.schema_version).toBe(2);
  expect(String(manifest.backend_base_url || "")).toMatch(/^http:\/\/127\.0\.0\.1:\d+$/);

  const actors = manifest.actors || [];
  const roles = new Set(actors.map((actor) => String(actor.role || "")));
  for (const role of REQUIRED_SINGLETON_ROLES) {
    expect(roles.has(role), `M3 actor role is missing: ${role}`).toBe(true);
  }
  const reviewers = actors.filter((actor) => String(actor.role || "").startsWith("reviewer"));
  expect(
    reviewers.length,
    "A low-severity original panel and a fresh disjoint appeal panel require at least fourteen independent reviewers.",
  ).toBeGreaterThanOrEqual(14);

  const accounts = actors.map((actor) => String(actor.account || "").trim());
  expect(accounts.every(Boolean), "Every M3 actor needs a public account identifier.").toBe(true);
  expect(new Set(accounts).size, "M3 actors must use independent account identities.").toBe(accounts.length);
  for (const actor of actors) {
    absoluteExistingFile(actor.storage_state, `storage state for ${actor.role}`);
  }

  const journey = manifest.journey || ({} as M3Journey);
  for (const [field, value] of Object.entries({
    post_id: journey.post_id,
    group_id: journey.group_id,
    dispute_id: journey.dispute_id,
    proposal_id: journey.proposal_id,
  })) {
    expect(String(value || "").trim(), `journey.${field} is required`).not.toBe("");
  }
  return manifest;
}

async function getJson(request: APIRequestContext, base: string, route: string): Promise<any> {
  const response = await request.get(`${base}${route}`, { timeout: 15_000 });
  expect(response.ok(), `${route} returned HTTP ${response.status()}: ${await response.text()}`).toBeTruthy();
  return response.json();
}

function actorFor(manifest: M3ActorManifest, role: string): PublicActor {
  const actor = manifest.actors.find((item) => item.role === role);
  expect(actor, `actor role missing: ${role}`).toBeTruthy();
  return actor!;
}

async function openActorContext(browser: Browser, actor: PublicActor): Promise<BrowserContext> {
  return browser.newContext({
    baseURL: FRONTEND_BASE_URL,
    storageState: absoluteExistingFile(actor.storage_state, `storage state for ${actor.role}`),
  });
}

async function assertActorSession(context: BrowserContext, actor: PublicActor, route: string): Promise<void> {
  const page = await context.newPage();
  try {
    await page.goto(route);
    await expect(page.locator("body")).toBeVisible();
    const account = await page.evaluate(() => {
      const raw = localStorage.getItem("weall_session_v1");
      if (!raw) return "";
      try {
        const parsed = JSON.parse(raw) as Record<string, unknown>;
        return String(parsed.account || parsed.account_id || parsed.handle || "");
      } catch {
        return "";
      }
    });
    expect(account, `${actor.role} storage state must identify its independent account`).toBe(actor.account);
  } finally {
    await page.close();
  }
}

function findMember(items: any[], account: string): boolean {
  return items.some((item) => {
    if (typeof item === "string") return item === account;
    if (!item || typeof item !== "object") return false;
    return String(item.account || item.account_id || item.member || item.id || "") === account;
  });
}

test.describe.configure({ mode: "serial" });

test("M3 independent actors complete the signed civic and governance journey", async ({ browser, request }) => {
  test.setTimeout(180_000);
  const manifest = loadActorManifest();
  const backend = manifest.backend_base_url.replace(/\/$/, "");
  const journey = manifest.journey;
  const author = actorFor(manifest, "author_proposer");
  const member = actorFor(manifest, "member_reporter_voter");
  const reviewers = manifest.actors.filter((actor) => actor.role.startsWith("reviewer"));

  await getJson(request, backend, "/v1/status");

  await test.step("signed public content", async () => {
    const authorContext = await openActorContext(browser, author);
    try {
      await assertActorSession(authorContext, author, "/#/feed");
    } finally {
      await authorContext.close();
    }
    const content = await getJson(request, backend, `/v1/content/${encodeURIComponent(journey.post_id)}`);
    const record = content.content || content.post || content.item || content;
    expect(String(record.post_id || record.id || "")).toBe(journey.post_id);
    expect(String(record.author || record.created_by || "")).toBe(author.account);
    expect(record.deleted).not.toBe(true);
  });

  await test.step("canonical group membership", async () => {
    const memberContext = await openActorContext(browser, member);
    try {
      await assertActorSession(memberContext, member, "/#/groups");
    } finally {
      await memberContext.close();
    }
    const group = await getJson(request, backend, `/v1/groups/${encodeURIComponent(journey.group_id)}`);
    expect(String(group.group?.id || group.group?.group_id || "")).toBe(journey.group_id);
    const members = await getJson(request, backend, `/v1/groups/${encodeURIComponent(journey.group_id)}/members?limit=500`);
    expect(findMember(members.members || members.items || [], member.account)).toBe(true);
  });

  await test.step("public report and independent review", async () => {
    for (const reviewer of reviewers.slice(0, 7)) {
      const context = await openActorContext(browser, reviewer);
      try {
        await assertActorSession(context, reviewer, "/#/reviews");
      } finally {
        await context.close();
      }
    }
    const body = await getJson(request, backend, `/v1/disputes/${encodeURIComponent(journey.dispute_id)}`);
    const dispute = body.dispute || body;
    expect(String(dispute.id || dispute.dispute_id || "")).toBe(journey.dispute_id);
    expect(String(dispute.target_id || "")).toBe(journey.post_id);
    expect(String(dispute.panel_commitment || "")).not.toBe("");
    expect(Number(dispute.panel_required_size || 0)).toBe(7);
    expect(Number(dispute.substitute_required_count || 0)).toBe(2);
    expect(dispute.public_ballot_disclosure).toBe("aggregate_only");
  });

  await test.step("appeal and final receipt", async () => {
    const body = await getJson(request, backend, `/v1/disputes/${encodeURIComponent(journey.dispute_id)}`);
    const dispute = body.dispute || body;
    expect(String(dispute.appeal_panel_commitment || "")).not.toBe("");
    expect(String(dispute.appeal_panel_commitment || "")).not.toBe(String(dispute.panel_commitment || ""));
    expect(Number(dispute.counts_total?.appeals || dispute.appeal_count || 0)).toBeGreaterThanOrEqual(1);
    if (journey.expected_dispute_stage) {
      expect(String(dispute.stage || "")).toBe(journey.expected_dispute_stage);
    }
    if (journey.expected_dispute_outcome) {
      expect(String(dispute.resolution?.outcome || dispute.outcome || "")).toBe(journey.expected_dispute_outcome);
    }
  });

  await test.step("versioned electorate round", async () => {
    const body = await getJson(request, backend, `/v1/gov/proposals/${encodeURIComponent(journey.proposal_id)}`);
    const proposal = body.proposal || body;
    expect(Number(proposal.electorate_round || 0)).toBeGreaterThanOrEqual(1);
    expect(String(proposal.electorate_commitment || "")).not.toBe("");
    expect(Number(proposal.eligible_voter_count || 0)).toBeGreaterThan(0);
    expect(Number(proposal.required_votes || 0)).toBeGreaterThan(0);
    expect(proposal.ballot_finality_policy).toBe("first_admitted_final_ballot");
    expect(proposal.public_ballot_disclosure).toBe("aggregate_only");
  });

  await test.step("first admitted final ballot", async () => {
    const votes = await getJson(request, backend, `/v1/gov/proposals/${encodeURIComponent(journey.proposal_id)}/votes`);
    expect(votes.identity_choice_maps_exposed).toBe(false);
    expect(votes.votes_redacted).toBe(true);
    expect(votes).not.toHaveProperty("votes");
    expect(Number(votes.counts_total?.votes || 0)).toBeGreaterThanOrEqual(journey.minimum_final_ballots || 1);
  });

  await test.step("block-height tally and finalization", async () => {
    const body = await getJson(request, backend, `/v1/gov/proposals/${encodeURIComponent(journey.proposal_id)}`);
    const proposal = body.proposal || body;
    expect(Number(proposal.created_at_height || 0)).toBeGreaterThanOrEqual(0);
    expect(Number(proposal.tallied_at_height || proposal.finalized_at_height || 0)).toBeGreaterThan(0);
    if (journey.expected_proposal_stage) {
      expect(String(proposal.stage || "")).toBe(journey.expected_proposal_stage);
    } else {
      expect(["tallied", "executed", "finalized"]).toContain(String(proposal.stage || ""));
    }
  });
});
