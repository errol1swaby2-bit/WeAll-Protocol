import fs from "node:fs";
import path from "node:path";

import { expect, test } from "@playwright/test";

type PublicActor = {
  role: string;
  account: string;
  recovery_file?: string;
  storage_state?: string;
};

type M3ActorManifest = {
  schema_version: number;
  backend_base_url: string;
  actors: PublicActor[];
};

const REQUIRED_ROLES = [
  "author_proposer",
  "member_reporter_voter",
  "reviewer_1",
  "reviewer_2",
  "reviewer_3",
] as const;

function loadActorManifest(): M3ActorManifest {
  const manifestPath = String(process.env.WEALL_M3_ACTOR_MANIFEST || "").trim();
  expect(
    manifestPath,
    "M3 actor manifest is required. The closure journey must not use a demo tester session.",
  ).not.toBe("");

  const absolute = path.resolve(manifestPath);
  expect(fs.existsSync(absolute), `M3 actor manifest does not exist: ${absolute}`).toBe(true);

  const manifest = JSON.parse(fs.readFileSync(absolute, "utf8")) as M3ActorManifest;
  expect(manifest.schema_version).toBe(1);
  expect(String(manifest.backend_base_url || "")).toMatch(/^http:\/\/127\.0\.0\.1:\d+$/);

  const roles = new Set((manifest.actors || []).map((actor) => String(actor.role || "")));
  for (const role of REQUIRED_ROLES) {
    expect(roles.has(role), `M3 actor role is missing: ${role}`).toBe(true);
  }

  const accounts = (manifest.actors || []).map((actor) => String(actor.account || "").trim());
  expect(accounts.every(Boolean), "Every M3 actor needs a public account identifier.").toBe(true);
  expect(new Set(accounts).size, "M3 actors must use independent account identities.").toBe(accounts.length);

  return manifest;
}

test.describe.configure({ mode: "serial" });

test("M3 independent actors complete the signed civic and governance journey", async () => {
  const manifest = loadActorManifest();
  expect(manifest.actors.length).toBeGreaterThanOrEqual(REQUIRED_ROLES.length);

  await test.step("signed public content", async () => {
    // Target: browser-held ML-DSA custody signs CONTENT_POST_CREATE through /v1/tx/submit,
    // transaction finality reconciles, and an unauthenticated public read sees the post.
  });

  await test.step("canonical group membership", async () => {
    // Target: create a public charter, obtain /v1/groups/join skeleton,
    // sign GROUP_MEMBERSHIP_REQUEST, reconcile committed membership,
    // prove member-gated write and nonmember public read.
  });

  await test.step("public report and independent review", async () => {
    // Target: signed report references committed content; three conflict-free opted-in
    // reviewers independently accept, attend, and submit one canonical review ballot.
  });

  await test.step("appeal and final receipt", async () => {
    // Target: eligible affected actor files an appeal; required fresh reviewers act;
    // final outcome and append-only correction receipt reconcile in public read models.
  });

  await test.step("frozen electorate", async () => {
    // Target: proposal records scope, snapshot height, eligible-set commitment,
    // fixed denominator, and equal human vote weight. Validator status grants no vote.
  });

  await test.step("first admitted final ballot", async () => {
    // Target: one eligible ballot succeeds; duplicate, replacement, revoke,
    // validator-only, and otherwise ineligible attempts fail deterministically.
  });

  await test.step("block-height tally and finalization", async () => {
    // Target: scheduler-controlled close, aggregate tally, and no-action civic
    // finalization receipts reconcile without browser-time authority.
  });

  throw new Error(
    "M3_CLOSURE_NOT_IMPLEMENTED: wire the signed real-stack actor journey before changing this test to green.",
  );
});
