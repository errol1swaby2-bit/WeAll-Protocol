import fs from "node:fs";
import path from "node:path";

import { expect, test, type APIRequestContext, type Browser, type BrowserContext, type Page } from "@playwright/test";

type PublicActor = {
  role: string;
  account: string;
  storage_state: string;
  signer_state: string;
};

type PrivateSignerState = {
  schema_version: 1;
  account: string;
  secretKeyB64: string;
};

type M3Action = {
  label: string;
  role: string;
  account: string;
  tx_type: string;
  tx_id: string;
  subject_id: string;
  status: "confirmed";
  evidence_kind?: string;
};

type M3NegativeAttempt = {
  label: string;
  role: string;
  account: string;
  tx_type: string;
  payload: Record<string, unknown>;
  subject_id: string;
  precondition_tx_id?: string;
  expected_error_code: string;
};

type M3TransactionTranscript = {
  schema_version: number;
  implementation_freeze_commit: string;
  chain_id: string;
  actions: M3Action[];
  negative_attempts: M3NegativeAttempt[];
};

type M3Journey = {
  post_id: string;
  group_id: string;
  group_post_id: string;
  dispute_id: string;
  proposal_id: string;
  negative_post_id: string;
  negative_group_id: string;
  negative_dispute_id: string;
  negative_proposal_id: string;
  transaction_transcript: string;
  expected_dispute_stage?: string;
  expected_dispute_outcome?: string;
  expected_proposal_stage?: string;
  minimum_final_ballots?: number;
};

type M3ActorManifest = {
  schema_version: number;
  implementation_freeze_commit: string;
  backend_base_url: string;
  frontend_base_url?: string;
  actors: PublicActor[];
  journey: M3Journey;
};

const REQUIRED_SINGLETON_ROLES = ["author_proposer", "member_reporter_voter", "nonmember_ineligible"] as const;
const FRONTEND_BASE_URL = process.env.PLAYWRIGHT_BASE_URL ?? "http://127.0.0.1:5173";
const TERMINAL_SUCCESS = new Set(["confirmed", "committed", "finalized"]);
const EMBEDDED_ATTENDANCE_EVIDENCE_KIND = "acceptance_embedded_attendance";

const ATTENDANCE_ACCEPTANCE_LABEL = new Map<string, string>([
  ["original_panel_attendance", "original_panel_acceptance"],
  ["appeal_panel_attendance", "appeal_panel_acceptance"],
]);

function isEmbeddedAttendancePair(first: M3Action, second: M3Action): boolean {
  const firstAcceptanceLabel = ATTENDANCE_ACCEPTANCE_LABEL.get(first.label);
  const secondAcceptanceLabel = ATTENDANCE_ACCEPTANCE_LABEL.get(second.label);

  let attendance: M3Action;
  let acceptance: M3Action;

  if (firstAcceptanceLabel === second.label) {
    attendance = first;
    acceptance = second;
  } else if (secondAcceptanceLabel === first.label) {
    attendance = second;
    acceptance = first;
  } else {
    return false;
  }

  return (
    attendance.evidence_kind === EMBEDDED_ATTENDANCE_EVIDENCE_KIND
    && attendance.tx_type === "DISPUTE_JUROR_ACCEPT"
    && acceptance.tx_type === "DISPUTE_JUROR_ACCEPT"
    && attendance.tx_id === acceptance.tx_id
    && attendance.role === acceptance.role
    && attendance.account === acceptance.account
    && attendance.subject_id === acceptance.subject_id
    && attendance.status === "confirmed"
    && acceptance.status === "confirmed"
  );
}

function absoluteExistingFile(value: string, label: string): string {
  const absolute = path.resolve(String(value || ""));
  expect(fs.existsSync(absolute), `${label} does not exist: ${absolute}`).toBe(true);
  expect(fs.lstatSync(absolute).isSymbolicLink(), `${label} must not be a symlink: ${absolute}`).toBe(false);
  return absolute;
}

function loadActorManifest(): { manifest: M3ActorManifest; transcript: M3TransactionTranscript } {
  const manifestPath = String(process.env.WEALL_M3_ACTOR_MANIFEST || "").trim();
  expect(
    manifestPath,
    "M3 actor manifest is required. Closure must use independent custody states and a signed transaction transcript.",
  ).not.toBe("");

  const absolute = absoluteExistingFile(manifestPath, "M3 actor manifest");
  const manifest = JSON.parse(fs.readFileSync(absolute, "utf8")) as M3ActorManifest;
  expect(manifest.schema_version).toBe(3);
  expect(manifest.implementation_freeze_commit).toBe(String(process.env.M3_IMPLEMENTATION_FREEZE_COMMIT || ""));
  expect(JSON.stringify(manifest)).not.toContain("recovery_file");
  expect(JSON.stringify(manifest)).not.toContain("private_key");
  expect(String(manifest.backend_base_url || "")).toMatch(/^http:\/\/127\.0\.0\.1:\d+$/);

  const actors = manifest.actors || [];
  const roles = new Set(actors.map((actor) => String(actor.role || "")));
  for (const role of REQUIRED_SINGLETON_ROLES) {
    expect(roles.has(role), `M3 actor role is missing: ${role}`).toBe(true);
  }
  const originalReviewers = actors.filter((actor) => String(actor.role || "").startsWith("reviewer_original_"));
  const appealReviewers = actors.filter((actor) => String(actor.role || "").startsWith("reviewer_appeal_"));
  expect(originalReviewers.length, "Original panel pool requires seven jurors plus two substitutes.").toBeGreaterThanOrEqual(9);
  expect(appealReviewers.length, "Fresh appeal panel pool requires seven jurors plus two substitutes.").toBeGreaterThanOrEqual(9);

  const accounts = actors.map((actor) => String(actor.account || "").trim());
  expect(accounts.every(Boolean), "Every M3 actor needs a public account identifier.").toBe(true);
  expect(new Set(accounts).size, "M3 actors must use independent account identities.").toBe(accounts.length);
  for (const actor of actors) {
    absoluteExistingFile(actor.storage_state, `storage state for ${actor.role}`);
    absoluteExistingFile(actor.signer_state, `private signer state for ${actor.role}`);
  }

  const journey = manifest.journey || ({} as M3Journey);
  for (const [field, value] of Object.entries({
    post_id: journey.post_id,
    group_id: journey.group_id,
    group_post_id: journey.group_post_id,
    dispute_id: journey.dispute_id,
    proposal_id: journey.proposal_id,
    negative_post_id: journey.negative_post_id,
    negative_group_id: journey.negative_group_id,
    negative_dispute_id: journey.negative_dispute_id,
    negative_proposal_id: journey.negative_proposal_id,
  })) {
    expect(String(value || "").trim(), `journey.${field} is required`).not.toBe("");
  }
  const transcriptPath = absoluteExistingFile(journey.transaction_transcript, "M3 transaction transcript");
  const transcript = JSON.parse(fs.readFileSync(transcriptPath, "utf8")) as M3TransactionTranscript;
  expect(transcript.schema_version).toBe(1);
  expect(transcript.implementation_freeze_commit).toBe(manifest.implementation_freeze_commit);
  expect(String(transcript.chain_id || "")).not.toBe("");
  expect(transcript.actions.length).toBeGreaterThan(0);
  expect(transcript.negative_attempts.length).toBeGreaterThan(0);
  return { manifest, transcript };
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

function loadPrivateSignerState(actor: PublicActor): PrivateSignerState {
  const signerPath = absoluteExistingFile(actor.signer_state, `private signer state for ${actor.role}`);
  const value = JSON.parse(fs.readFileSync(signerPath, "utf8")) as PrivateSignerState;
  expect(value.schema_version, `${actor.role} signer state schema mismatch`).toBe(1);
  expect(value.account, `${actor.role} signer state account mismatch`).toBe(actor.account);
  expect(String(value.secretKeyB64 || "").trim(), `${actor.role} signer seed is missing`).not.toBe("");
  return value;
}

async function openActorContext(browser: Browser, actor: PublicActor): Promise<BrowserContext> {
  const signer = loadPrivateSignerState(actor);
  const context = await browser.newContext({
    baseURL: FRONTEND_BASE_URL,
    storageState: absoluteExistingFile(actor.storage_state, `storage state for ${actor.role}`),
  });
  await context.addInitScript(({ account, secretKeyB64 }) => {
    sessionStorage.setItem(`weall_secret::${account}`, secretKeyB64);
  }, { account: actor.account, secretKeyB64: signer.secretKeyB64 });
  return context;
}

async function assertActorSession(context: BrowserContext, actor: PublicActor, route: string): Promise<Page> {
  const page = await context.newPage();
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
  return page;
}

function findMember(items: any[], account: string): boolean {
  return items.some((item) => {
    if (typeof item === "string") return item === account;
    if (!item || typeof item !== "object") return false;
    return String(item.account || item.account_id || item.member || item.id || "") === account;
  });
}

function errorCodeFrom(value: any): string {
  const candidates = [
    value?.code,
    value?.payload?.error?.code,
    value?.payload?.code,
    value?.payload?.error?.details?.reason,
    value?.payload?.error?.details?.code,
    value?.body?.error?.code,
    value?.body?.code,
    value?.body?.error?.details?.reason,
    value?.body?.error?.details?.code,
  ];
  return String(candidates.find((item) => String(item || "").trim()) || "").trim();
}

async function submitExpectedFailure(
  page: Page,
  backend: string,
  attempt: M3NegativeAttempt,
): Promise<{ ok: boolean; code: string; message: string }> {
  return page.evaluate(async ({ backendValue, attemptValue }) => {
    const sessionModule = await import("/src/auth/session.ts");
    try {
      await sessionModule.submitSignedTx({
        account: attemptValue.account,
        tx_type: attemptValue.tx_type,
        payload: attemptValue.payload,
        base: backendValue,
        headers: sessionModule.getAuthHeaders(attemptValue.account),
      });
      return { ok: true, code: "", message: "unexpected_success" };
    } catch (error: any) {
      const candidates = [
        error?.code,
        error?.payload?.error?.code,
        error?.payload?.code,
        error?.payload?.error?.details?.reason,
        error?.payload?.error?.details?.code,
        error?.body?.error?.code,
        error?.body?.code,
        error?.body?.error?.details?.reason,
        error?.body?.error?.details?.code,
      ];
      const code = String(candidates.find((item) => String(item || "").trim()) || "").trim();
      return { ok: false, code, message: String(error?.message || error) };
    }
  }, { backendValue: backend, attemptValue: attempt });
}

test.describe.configure({ mode: "serial" });

test("M3 independent actors complete the signed civic and governance journey", async ({ browser, request }) => {
  test.setTimeout(600_000);
  const { manifest, transcript } = loadActorManifest();
  const backend = manifest.backend_base_url.replace(/\/$/, "");
  const journey = manifest.journey;
  const author = actorFor(manifest, "author_proposer");
  const member = actorFor(manifest, "member_reporter_voter");
  const reviewers = manifest.actors.filter((actor) => actor.role.startsWith("reviewer"));

  await getJson(request, backend, "/v1/status");
  const ballotProfileResponse = await getJson(request, backend, "/v1/gov/ballot-profile");
  expect(ballotProfileResponse.ballot_profile).toEqual({
    profile_id: "controlled-testnet-aggregate-v1",
    active: true,
    strict: true,
    mode: "controlled-testnet",
    reason: "active_controlled_testnet_profile",
  });

  await test.step("signed transaction transcript is canonical", async () => {
    const seen = new Map<string, M3Action[]>();

    for (const action of transcript.actions) {
      const priorRecords = seen.get(action.tx_id) ?? [];

      if (priorRecords.length > 0) {
        expect(
          priorRecords.length,
          `transaction id appears more than twice: ${action.tx_id}`,
        ).toBe(1);

        expect(
          isEmbeddedAttendancePair(priorRecords[0], action),
          `duplicate transaction id is not a canonical acceptance/attendance pair: ${action.tx_id}`,
        ).toBe(true);
      }

      priorRecords.push(action);
      seen.set(action.tx_id, priorRecords);

      const status = await getJson(
        request,
        backend,
        `/v1/tx/status/${encodeURIComponent(action.tx_id)}`,
      );

      expect(
        TERMINAL_SUCCESS.has(
          String(status.status || status.phase || "").toLowerCase(),
        ),
        JSON.stringify(status),
      ).toBe(true);

      expect(String(status.tx_type || "")).toBe(action.tx_type);
      expect(String(status.signer || "")).toBe(action.account);
      expect(String(action.subject_id || "").trim()).not.toBe("");
      expect(action.status).toBe("confirmed");
    }
  });

  await test.step("signed public content", async () => {
    const authorContext = await openActorContext(browser, author);
    try {
      const page = await assertActorSession(authorContext, author, "/#/feed");
      await page.close();
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
      const page = await assertActorSession(memberContext, member, "/#/groups");
      await page.close();
    } finally {
      await memberContext.close();
    }
    const group = await getJson(request, backend, `/v1/groups/${encodeURIComponent(journey.group_id)}`);
    expect(String(group.group?.id || group.group?.group_id || "")).toBe(journey.group_id);
    const members = await getJson(request, backend, `/v1/groups/${encodeURIComponent(journey.group_id)}/members?limit=500`);
    expect(findMember(members.members || members.items || [], member.account)).toBe(true);
    const groupPost = await getJson(request, backend, `/v1/content/${encodeURIComponent(journey.group_post_id)}`);
    const record = groupPost.content || groupPost.post || groupPost.item || groupPost;
    expect(String(record.author || record.created_by || "")).toBe(member.account);
  });

  await test.step("public report and independent review", async () => {
    for (const reviewer of reviewers.slice(0, 7)) {
      const context = await openActorContext(browser, reviewer);
      try {
        const page = await assertActorSession(context, reviewer, "/#/reviews");
        await page.close();
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

  await test.step("negative fixture subjects remain active", async () => {
    const negativeGroup = await getJson(request, backend, `/v1/groups/${encodeURIComponent(journey.negative_group_id)}`);
    expect(String(negativeGroup.group?.id || negativeGroup.group?.group_id || "")).toBe(journey.negative_group_id);

    const negativeDisputeBody = await getJson(request, backend, `/v1/disputes/${encodeURIComponent(journey.negative_dispute_id)}`);
    const negativeDispute = negativeDisputeBody.dispute || negativeDisputeBody;
    expect(["juror_review", "review", "voting"]).toContain(String(negativeDispute.stage || "").toLowerCase());
    expect(String(negativeDispute.target_id || "")).toBe(journey.negative_post_id);
    expect(String(negativeDispute.target_owner || negativeDispute.target_author || "")).toBe(author.account);
    const selected = new Set(
      [
        ...(negativeDispute.assigned_jurors || []),
        ...(negativeDispute.panel || []),
        ...(negativeDispute.substitutes || []),
      ].map((value: unknown) => String(value || "")),
    );
    const nonselectedAttempt = transcript.negative_attempts.find((attempt) => attempt.label === "nonselected_reviewer_vote_rejected");
    expect(nonselectedAttempt).toBeTruthy();
    expect(selected.has(String(nonselectedAttempt?.account || "")), "nonselected reviewer fixture is actually selected").toBe(false);

    const negativeProposalBody = await getJson(request, backend, `/v1/gov/proposals/${encodeURIComponent(journey.negative_proposal_id)}`);
    const negativeProposal = negativeProposalBody.proposal || negativeProposalBody;
    expect(["voting", "vote"]).toContain(String(negativeProposal.stage || "").toLowerCase());
  });

  await test.step("negative signed attempts fail closed", async () => {
    const actionById = new Map(transcript.actions.map((action) => [action.tx_id, action]));
    for (const attempt of transcript.negative_attempts) {
      const actor = actorFor(manifest, attempt.role);
      expect(actor.account).toBe(attempt.account);
      expect(String(attempt.subject_id || "").trim()).not.toBe("");
      if (attempt.precondition_tx_id) {
        const prior = actionById.get(attempt.precondition_tx_id);
        expect(prior, `${attempt.label} precondition transaction is absent`).toBeTruthy();
        expect(prior?.account).toBe(attempt.account);
        expect(prior?.subject_id).toBe(attempt.subject_id);
        const priorStatus = await getJson(request, backend, `/v1/tx/status/${encodeURIComponent(attempt.precondition_tx_id)}`);
        expect(TERMINAL_SUCCESS.has(String(priorStatus.status || priorStatus.phase || "").toLowerCase())).toBe(true);
      }
      const context = await openActorContext(browser, actor);
      try {
        const page = await assertActorSession(context, actor, "/#/transactions");
        const result = await submitExpectedFailure(page, backend, attempt);
        expect(result.ok, `${attempt.label} unexpectedly succeeded`).toBe(false);
        const combined = `${result.code} ${result.message}`;
        expect(combined, `${attempt.label} did not expose expected failure: ${JSON.stringify(result)}`).toContain(attempt.expected_error_code);
        expect(errorCodeFrom(result) || result.code || result.message).not.toBe("");
        await page.close();
      } finally {
        await context.close();
      }
    }
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
