import { expect, test, type Page } from "@playwright/test";

const revisionProposal = {
  proposal_id: "proposal:discussion:alpha",
  creator: "@alice",
  title: "Shared water-use rules",
  body: "Discuss the wording before we make a final decision.",
  stage: "revision",
  created_at_height: 10,
  updated_at_height: 18,
  revision_opened_at_height: 12,
  current_procedure_height: 18,
  rules: { revision_period_blocks: 12 },
  current_version: 2,
  frozen_version: 0,
  comments: [
    { comment_id: "comment:1", by: "@bob", body: "Can we include smaller neighborhoods?", height: 14 },
    { comment_id: "comment:2", by: "@alice", body: "Yes; I will revise section two.", height: 18 },
  ],
  versions: [
    { version: 1, title: "Shared water-use rules", body: "Initial text", created_at_height: 10, revision_reason: "initial proposal" },
    { version: 2, title: "Shared water-use rules", body: "Revised text", created_at_height: 18, revision_reason: "after public input" },
  ],
  actions: [],
  poll_votes: {},
  votes: {},
  poll_counts: { yes: 0, no: 0, abstain: 0 },
  counts: { yes: 0, no: 0, abstain: 0 },
};

const votingProposal = {
  ...revisionProposal,
  proposal_id: "proposal:discussion:beta",
  title: "Public garden locations",
  stage: "voting",
  updated_at_height: 16,
  comments: [{ comment_id: "comment:3", by: "@carol", body: "Please preserve public access.", height: 16 }],
};

const finalProposal = {
  ...revisionProposal,
  proposal_id: "proposal:discussion:final",
  title: "Already finalized",
  stage: "finalized",
};

async function mockGovernance(page: Page): Promise<void> {
  const proposals = [revisionProposal, votingProposal, finalProposal];

  await page.route(/\/v1\/gov\/proposals(?:\?.*)?$/, async (route) => {
    await route.fulfill({
      json: {
        ok: true,
        items: proposals,
        summary: { total: 3, active: 2, by_stage: { revision: 1, voting: 1, finalized: 1 } },
      },
    });
  });

  await page.route(/\/v1\/gov\/proposals\/[^/?]+\/votes(?:\?.*)?$/, async (route) => {
    await route.fulfill({
      json: {
        ok: true,
        proposal_id: revisionProposal.proposal_id,
        stage: "revision",
        poll_counts: { yes: 0, no: 0, abstain: 0 },
        counts: { yes: 0, no: 0, abstain: 0 },
        identity_choice_maps_exposed: false,
        poll_votes_redacted: true,
        votes_redacted: true,
      },
    });
  });

  await page.route(/\/v1\/gov\/proposals\/[^/?]+(?:\?.*)?$/, async (route) => {
    const id = decodeURIComponent(route.request().url().split("/").pop() || "");
    const proposal = proposals.find((item) => item.proposal_id === id);
    await route.fulfill(proposal
      ? { json: { ok: true, proposal } }
      : { status: 404, json: { ok: false, detail: "proposal_not_found" } });
  });
}

test("active deliberation previews lead to the authoritative discussion and revisions", async ({ page }) => {
  await mockGovernance(page);
  await page.goto("/#/decisions");

  const activity = page.getByRole("region", { name: "Active proposal deliberations" });
  await expect(activity).toContainText("Shared water-use rules");
  await expect(activity).toContainText("Can we include smaller neighborhoods?");
  await expect(activity).toContainText("Yes; I will revise section two.");
  await expect(activity).toContainText("Public garden locations");
  await expect(activity).toContainText("Deliberation closed");
  await expect(activity).not.toContainText("Already finalized");

  await activity.getByRole("button", { name: "Join deliberation" }).click();
  await expect(page).toHaveURL(/#\/decisions\/proposal%3Adiscussion%3Aalpha/);
  await expect(page.getByRole("heading", { name: "Comments and revisions" })).toBeVisible();
  await expect(page.getByText("Can we include smaller neighborhoods?")).toBeVisible();
  await expect(page.getByText("Yes; I will revise section two.")).toBeVisible();
  await expect(page.getByText("Version 2")).toBeVisible();
  await expect(page.getByText("after public input")).toBeVisible();
  await expect(page.getByText("Version history", { exact: true }).first()).toBeVisible();
});

test("voting-stage proposals retain readable history but close commenting", async ({ page }) => {
  await mockGovernance(page);
  await page.goto("/#/decisions");
  const activity = page.getByRole("region", { name: "Active proposal deliberations" });
  await activity.getByRole("button", { name: "Review discussion and vote" }).click();

  await expect(page.getByText("Please preserve public access.")).toBeVisible();
  await expect(page.getByText("Comments closed", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Submit comment" })).toBeDisabled();
});


test("anonymous accounts cannot open the protected proposal composer", async ({ page }) => {
  await page.goto("/#/decisions/create");
  await expect(page.getByLabel("Starting status")).toHaveCount(0);
  await expect(page.getByText("Create a community decision")).toHaveCount(0);
});

test("guided composer source defaults to a deliberative draft and distinguishes outcomes", async () => {
  // Authenticated rendered creation still requires a real signed session.
  const { readFileSync } = await import("node:fs");
  const source = readFileSync(new URL("../../src/pages/ProposalCreate.tsx", import.meta.url), "utf8");
  expect(source).toContain('const [startStage, setStartStage] = useState("draft");');
  expect(source).toContain("Recorded community decision: a vote can record collective support");
  expect(source).toContain("Executable governance request");
  expect(source).toContain("Stages advance only when the backend");
});

test("a record-only finalized proposal does not pretend to execute protocol actions", async ({ page }) => {
  await mockGovernance(page);
  await page.goto("/#/decisions/" + encodeURIComponent(finalProposal.proposal_id));
  await expect(page.getByText(/Record-only decision: voting may record collective support/)).toBeVisible();
  await expect(page.getByText(/No authoritative final tally published yet/)).toBeVisible();
});

test("preliminary majority is not mislabeled as an approved governance outcome", async ({ page }) => {
  const poll = { ...revisionProposal, proposal_id: "proposal:poll:test", stage: "poll",
    poll_counts: { yes: 8, no: 1, abstain: 0 } };
  await page.route(/\/v1\/gov\/proposals(?:\?.*)?$/, async (route) => {
    await route.fulfill({ json: { ok: true, items: [poll], summary: { total: 1, active: 1, by_stage: { poll: 1 } } } });
  });
  await page.goto("/#/decisions");
  await expect(page.getByText("Consultation or voting in progress")).toBeVisible();
  await expect(page.getByText("Approved", { exact: true })).toHaveCount(0);
});
