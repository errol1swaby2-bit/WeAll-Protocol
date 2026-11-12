# PR #88 — Dispute material-conflict gate v2 activation and historical replay RFC

**Status:** PROPOSED / NOT AUTHORIZED. Owner: accountable constitutional and protocol reviewers (not a bot). Applies only to candidate strict civic-governance chains after an explicitly approved activation mechanism. This RFC is not a transaction, constitution, amendment, production node instruction or release approval.

## 1. Baseline established by executable evidence

- The current strict dispute panel selector excludes the full set returned by `_dispute_conflict_account_ids` when assembling a panel; the historical non-strict selector is intentionally narrower.
- A controlled chain can validly assign a juror, then accept a signed `GROUP_MODERATORS_SET` placing the juror into a material group-officer conflict. The historical default v1 path still permits signed `DISPUTE_JUROR_ACCEPT` and `DISPUTE_VOTE_SUBMIT` (the confirmed source-path gap).
- The candidate v2 guard checks the current material conflict set before explicit assignment/accept/vote. Although a direct call to `DISPUTE_JUROR_ATTENDANCE` can change assigned to accepted, its **canonical contract is SYSTEM-only, receipt-only, block-context, parented by `DISPUTE_JUROR_ACCEPT`**. Public ingress rejects a reviewer-signed attendance submission (`system_tx_forbidden:system_flag_required`). No legitimate independent queue-origin attendance bypass is proven; do not change the accepted receipt handler without that evidence.
- The v2 opt-in is **currently dormant**: `params.dispute_material_conflict_gate_version` defaults to v1 and the live governance parameter policy does not whitelist changing it. A synthetic test-genesis with v2 is **not** an activation or migration.
- Strict governance currently blocks `CONSTITUTION_UPGRADE_DECLARE` and `CONSTITUTION_UPGRADE_ACTIVATE` with `constitutional_amendment_process_not_enabled`, because the constitutional amendment approval, challenge and rights-floor process has not been fully specified. Neither a routine `GOV_RULES_SET` nor an ad hoc local configuration may bypass that lock.

## 2. Proposed immutable activation record (not implemented)

Any future authorized mechanism must commit and publicly verify all of the following as **consensus state**, not local environment variables:

1. Exact protocol/constitution diff and semantic failure-contract digest, including `juror_conflict_material`, `unsupported_dispute_material_conflict_gate_version`, and implicit attendance acceptance.
2. Explicit activation **block height H**, chain ID, preactivation state root, software artifact hashes, review/witness commitments, and the required constitutional decision/appeal/challenge expiry receipts.
3. A canonical, authenticated, governance-approved activation transaction type and deterministic execution order; there is **no such approved mechanism in PR #88**. Do not repurpose the genesis bootstrap or synthetic test fixture for an existing chain.
4. A deterministic post-block parameter transition at H that is represented in the block state root. Block N less than H must always use v1; block N at or above H uses v2, with the decision independent of a follower's wall-clock time, local tip, code version, or runtime environment.
5. An explicit fail-closed unsupported-version handling contract, including the policy for older binaries, unknown values, and returning validators. Never silently interpret v2 as v1 after activation.

No `param_policy.ALLOWED` entry, activation height, fallback-to-v1 path, automatic upgrade executor or new governance capability is created by this RFC.

## 3. Historical and cross-version invariants required before any activation

- **Prefix replay:** for every pre-H block, a fresh executor from the historical genesis reproduces exactly the previously accepted transaction receipts, deterministic state roots and evidence proofs, even if later software supports v2.
- **Upgrade block:** the exact approved activation transaction appears at H; all validators derive the same state transition and reject a block that applies v2 early or v1 late.
- **Returning follower:** an offline node replays old blocks under v1, observes the approved activation event, and thereafter applies v2. A follower may not merely seed v2 in its old genesis; this changes the genesis state root and must be rejected.
- **No replay edit:** signed historical juror accept/vote receipts do not change retroactively; a post-H conflicted action rejects with a canonical failed receipt that consumes the nonce under the existing failure contract.
- **No invisible fallback:** if an incoming block, manifest, state version, semantic digest, or canonical tx schema conflicts with the approved schedule, the node refuses to finalize/sync that block. The behavior of a pre-H/old-binary follower requires an explicit compatibility test.
- **Validator migration:** upgrade ordering, deterministic quorums, validator restart and replay convergence must be independently verified before H. A same-machine pair of SQLite executors is not a production validator quorum or public-network finality.

## 4. Liveness and procedural fairness (unresolved)

The conservative rejection of a newly conflicted assigned juror should not quietly convert the strict constitutional 7/15/25 panel requirements into smaller panels or punish jurors for conflicts imposed after assignment.

Required decisions and tests:

- Deterministically invalidate/recuse a newly conflicted juror and preserve the originally committed panel and substitute selection proof.
- Substitute selection, reserve exhaustion, deadline recalculation, quorum calculations, and a new panel-round commitment must be specified and replayed identically on all nodes. Do not silently promote a substitute through a local scheduler.
- Decide whether an affected juror may safely **decline or withdraw** with a conflict-specific no-penalty receipt, instead of accruing a timeout or late-withdraw reputation penalty for becoming ineligible.
- Distinguish a conflict pre-existing at panel selection, a conflict introduced after selection but before acceptance, and a conflict introduced after acceptance but before a ballot. Pre-H historical ballots remain immutable.
- Confirm that an unconflicted juror can still sign `DISPUTE_JUROR_ACCEPT` and `DISPUTE_VOTE_SUBMIT` under v2 and that attendance evidence generated by acceptance, the counted ballot and reputation accounting survive restart/replay. `DISPUTE_JUROR_ATTENDANCE` is not a user-origin transaction.
- Cases with too few independent jurors must remain unassigned, paused or otherwise deterministically fail closed—never auto-approve an adverse sanction.
- Independent PoH, control of reviewer selection, public ballot confidentiality, appeals and real-world juror independence are separate prerequisites. A signed synthetic replay cannot substitute for them.

### Read-only replacement candidate preview (proposal, not executable recovery)

The new `src/weall/runtime/dispute_panel_recovery_preview.py` is an isolated
read-only diagnostic, not imported into the production scheduler, executor or
transaction router. It reports the committed original panel, substitute order,
pinned voting requirement, material conflicts, inactive reviewer lanes, and
candidate pairings **without modifying state**.

The existing production scheduler `repair_unassigned_dispute_panels` skips any
dispute with a nonempty `assigned_jurors` list. The separately used
`_dispute_eligible_juror_ids` may project fewer eligible jurors and recompute
a smaller voting quorum from the filtered set. **The signed controlled-chain
regression reproduced this as actual consensus-state drift:** starting from a
strict seven-person panel whose `required_votes` was **5**, a later signed
group-moderator conflict excluded one assigned reviewer; after an
unconflicted juror cast a successful signed vote, the persisted
`eligible_validator_count` became **6** and `required_votes` became **4**,
while `assigned_jurors` still contained **7**. The new preview rejects that
state with `blocked_original_vote_threshold_drift`, rather than treating
four votes as adequate for the originally committed seven-person panel.
This is proof of a consensus-reachable **quorum shrink**, not proof that
the complete dispute finalized under that reduced threshold. The preview therefore does not
run either mutating routine or treat a newly smaller eligible set as permission
to finalize an undersized constitutional panel.

The preview fails closed rather than proposing executable appointments if the
original snapshot or reserve size is incomplete, a quorum was already
reduced, too many assigned jurors are ineligible for the original reserves,
or any ballot was already recorded. It preserves committed reserve **order**
instead of sorting it anew or silently redrawing a panel. Even when candidate
substitutions are available, the result is
`candidate_requires_constitutional_review` and explicitly records the reserve
replenishment deficit. No automatic appointment, reassigning submitted votes,
new quorum, penalty waiver, replay repair, or activation is authorized.
All preview output is advisory; an original commitment's cryptographic
provenance still needs independent verification.

A reviewer-facing evidence set checks one, two and three conflicts, reserve
ineligibility, corrupted/aliased snapshots, existing votes/nullifiers, missing
commitments, old/unsupported policy versions, and nonmutation/repeatability.
The signed controlled-development-chain reproduction additionally inspects
the preview against its legitimately created post-assignment group conflict,
before and after an unconflicted juror casts a ballot. This is not evidence
of a constitutional substitute-selection procedure.

### Dormant v2 fixed-panel threshold and resolution hold (implemented candidate)

The branch now includes an **explicit strict-v2-only** initial-review helper:
`_strict_v2_initial_panel_votes` pins `required_votes` to at least the
original 7/15/25-member panel threshold, rather than recomputing it from
a smaller current eligible subset. In constitutional-clock severe
sanctions it also retains the 20-vote floor. When no chain-state v2 gate
is selected, historical v1 computations remain unchanged; appeal
panels retain their separately defined semantics.

A second guard, `_strict_v2_initial_panel_complete`, checks that the
currently eligible juror set still matches the original complete,
nonduplicated, nonconflicted, active reviewer panel before
`_maybe_schedule_dispute_auto_resolution` can queue a result. A
post-assignment conflict therefore **does not** give six remaining
reviewers permission to decide a seven-person case even if five valid
ballots arrive. This guard is a *safety hold*, not verification of
independent humanity or constitutional panel-commitment provenance.

A signed controlled-development-chain test commits a complete strict
seven-member panel, adds a later signed moderator conflict, then
commits **five signed unconflicted votes**. The new v2 candidate
preserves `required_votes=5` with `eligible_validator_count=6`,
stores the ballots, does not automatically resolve the incomplete
panel, and replays on a separate SQLite executor with matching block
and state roots. [Exact-source test workflow #43314857271](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/43314857271)
passed 31/31 cases including default-v1 and severe threshold
checks. This does **not** establish a safe path to finalization: no
substitute reassignment, counted-vote transfer, penalty-free recusal,
appeal settlement, or approved on-chain activation was added.

The [live B5xx regeneration #43314846789](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/43314846789)
executed and live-verified all three underlying proof harnesses and
pushed only generated JSON evidence in
[`5df06bfc`](https://github.com/errol1swaby2-bit/WeAll-Protocol/commit/5df06bfc37709a7b4172032303b6707ca3cc33ac).
No accepted v2 semantic-review digest or production release lock changed.

### Conflict-triggered reputation fairness: source characterization, not a waiver

The read-only `preview_dispute_panel_recovery` now includes
`currently_impacted_juror_reputation_risks`. For each currently conflicted
or inactive assigned reviewer it reports the persisted juror status, whether
a ballot has already been recorded (without disclosing the ballot choice),
block-height deadlines, potential late-withdraw/timeout penalty values,
and exposure to the existing missed-vote final-accountability rule.
It never writes penalties or a new recusal, verifies when a conflict arose,
or claims an existing penalty has already occurred. Missing or non-integer
chain height is **unknown**, not an expired deadline. Ambiguous juror-record
aliases are reported as unverified.

The existing direct appliers do **not** exempt a currently conflicted juror
from late-withdraw or timeout penalties. A synthetic accepted reviewer
whose safe-withdraw and vote deadlines had passed was still assigned
`DISPUTE_JUROR_WITHDREW_LATE` (**−500 milli-units**) by the withdrawal
applier and `DISPUTE_JUROR_TIMED_OUT` (**−1,500 milli-units**) by the
SYSTEM-only timeout applier. A separate direct call to final-accountability
suspended a conflicted assigned nonvoter with reason
`assigned_dispute_vote_missed`. These observations use *separate synthetic
fixture states*, with the reputation-event writer replaced for the
withdrawal/timeout characterization. They **do not** establish a valid
signed SYSTEM-queue producer, a finalized containing block, an authenticated
material-conflict introduction height, or a constitutionally legitimate
final receipt. The existing status skip paths for withdrawn, declined,
timed-out and voted jurors were also characterized.

The [focused exact-head fairness/replay workflow](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/43322442666)
passed **48/48** tests with Ruff clean. The new tests include cases on
both sides of the safe-withdraw/vote deadline, existing ballots,
nonmutation of the read-only preview and alias ambiguity; they retain
the earlier signed v1/v2 dispute regression and controlled replay.

**Approval needed before any change:** define what constitutes a
cryptographically or consensus-authenticated *post-assignment* conflict,
whether a juror has an affirmative obligation to report it, which
deadline pauses are constitutional, who may trigger a recusal and under
what vote/appeal process, how accumulated votes and reputation events
are preserved without retroactive editing, and whether a no-penalty
withdrawal is available to protect against conflicts imposed by other
actors. A locally inferred conflict or arbitrary payload reason must
never be sufficient to suppress a penalty or appoint a substitute.
The default v1 paths, non-whitelisted v2 parameter, and constitutional
amendment lock remain intact.

## 5. Staged review gates

| Stage | Required evidence | Current disposition |
|---|---|---|
| A. Source defect characterization | Signed v1 group-officer conflict, successful legacy accept/vote and identical restart/replay roots | Confirmed in controlled dev |
| B. Candidate v2 denial | Signed conflicted accept/vote failure; signed user attendance rejected at ingress; no partial dispute mutation; reviewer-lane and alias cases | Tests under PR #88; not authorization |
| C. Positive v2 liveness | Signed unconflicted acceptance/vote and independent replay | Test under PR #88; not full panel finality |
| D. Cross-profile safety | Different genesis-root rejection; old v1 prefix replay | Test under PR #88, activation-at-H still absent |
| E. Automatic recusal and substitutes | Deterministic conflict recusal, panel repair, deadlines and no unjust penalty | Not implemented |
| F. Constitutional amendment procedure | Fully specified protected-rights/amendment process, independent review, challenge window, unamendable-floor guard | **Blocked**; current strict constitutional upgrade actions fail closed |
| G. Canonical activation | Approved, signed on-chain height-H transition with old-binary and returning-node compatibility | **Not implemented** |
| H. Release evidence | Authenticated BFT, clean full backend/reviewer/P1 gates, constitutional/semantic signoff, fresh source-bound proofs | **NO-GO**; existing V2 semantic-review backlog remains |

## 6. Non-authorizations and stop conditions

This document does not authorize: updating any accepted `specs/v2/source/semantic_reviews.json` digest; merging PR #88; switching the production genesis to v2; inserting v2 into an existing ledger's live state; bypassing consensus checks or replay hashes; granting constitutional amendment power through a generic governance action; or enabling production validators, economic features, public testnet or mainnet.

If source changes make B528/B534/B567 source-bound V1.5 proofs stale, regenerate them only with their actual test harnesses and `--verify-live`, change only validated proof artifacts with an unchanged-head lease, and preserve release locks. A stale artifact is a CI failure, not a reason to skip the gate.

**Decision needed:** accountable reviewers must determine the constitutional authority and procedural fairness of this change before any version-2 activation design can move beyond its test-only state.
