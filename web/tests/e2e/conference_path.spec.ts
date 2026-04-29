import { expect, test } from "@playwright/test";

type DevBootstrapManifest = {
  account?: string;
  seededGroup?: { group_id?: string };
  seededProposal?: { proposal_id?: string };
  seededDispute?: { dispute_id?: string };
};

async function readManifest(page: import("@playwright/test").Page): Promise<Required<Pick<DevBootstrapManifest, "account" | "seededGroup" | "seededProposal" | "seededDispute">>> {
  const manifest = await page.evaluate(async () => {
    const res = await fetch("/dev-bootstrap.json", { cache: "no-store" });
    if (!res.ok) {
      throw new Error(`manifest fetch failed with status ${res.status}`);
    }
    return (await res.json()) as DevBootstrapManifest;
  });

  const account = String(manifest?.account || "").trim();
  const groupId = String(manifest?.seededGroup?.group_id || "").trim();
  const proposalId = String(manifest?.seededProposal?.proposal_id || "").trim();
  const disputeId = String(manifest?.seededDispute?.dispute_id || "").trim();

  expect(account, "seeded account must exist in dev-bootstrap manifest").not.toBe("");
  expect(groupId, "seeded group id must exist in dev-bootstrap manifest").not.toBe("");
  expect(proposalId, "seeded proposal id must exist in dev-bootstrap manifest").not.toBe("");
  expect(disputeId, "seeded dispute id must exist in dev-bootstrap manifest").not.toBe("");

  return {
    account,
    seededGroup: { group_id: groupId },
    seededProposal: { proposal_id: proposalId },
    seededDispute: { dispute_id: disputeId },
  };
}

test("seeded conference path is visible from login through groups disputes and governance", async ({ page }) => {
  await page.goto("/#/login");

  const manifest = await readManifest(page);
  const groupId = String(manifest.seededGroup.group_id || "");
  const proposalId = String(manifest.seededProposal.proposal_id || "");
  const disputeId = String(manifest.seededDispute.dispute_id || "");

  await expect(page.getByTestId("dev-bootstrap-summary")).toBeVisible();
  await expect(page.getByTestId("dev-bootstrap-account")).toContainText(manifest.account);
  await expect(page.getByTestId("dev-bootstrap-seeded-group")).toContainText(groupId);
  await expect(page.getByTestId("dev-bootstrap-seeded-proposal")).toContainText(proposalId);
  await expect(page.getByTestId("dev-bootstrap-seeded-dispute")).toContainText(disputeId);
  await expect(page.getByTestId("dev-bootstrap-fallback")).toBeVisible();
  await expect(page.getByTestId("dev-bootstrap-reset")).toBeVisible();
  await expect(page.getByTestId("dev-bootstrap-quick-links")).toBeVisible();
  await expect(page.getByTestId("dev-bootstrap-open-group")).toBeVisible();
  await expect(page.getByTestId("dev-bootstrap-open-disputes")).toBeVisible();
  await expect(page.getByTestId("dev-bootstrap-open-proposal")).toBeVisible();

  await page.getByTestId("load-demo-tester-session").first().click();
  await page.waitForURL(/#\/home$/);

  await page.goto(`/#/groups/${encodeURIComponent(groupId)}`);
  await expect(page.getByRole("heading", { name: /groups/i })).toBeVisible();
  await expect(page.getByText(groupId, { exact: false }).first()).toBeVisible();

  await page.goto("/#/disputes");
  await expect(page.getByRole("heading", { name: /disputes/i })).toBeVisible();
  await expect(page.getByRole("button", { name: new RegExp(disputeId.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")) })).toBeVisible();
  await page.getByRole("button", { name: new RegExp(disputeId.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")) }).click();
  await expect(page.getByText(disputeId, { exact: false }).first()).toBeVisible();

  await page.goto(`/#/proposal/${encodeURIComponent(proposalId)}`);
  await expect(page.getByText("Proposal id")).toBeVisible();
  await expect(page.getByText(proposalId, { exact: false }).first()).toBeVisible();
});
