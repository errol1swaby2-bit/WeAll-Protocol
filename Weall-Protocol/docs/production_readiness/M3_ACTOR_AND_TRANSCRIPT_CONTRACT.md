# M3 actor and signed-transaction evidence contract

The M3 real-stack gate consumes a **schema-v3 actor manifest** and a **schema-v1 signed transaction transcript**. These files are runtime inputs. They may reference private local browser storage-state files, but private custody files are never copied into `artifacts/m3-closure`.

## Actor manifest

The manifest must contain:

- the exact full implementation-freeze commit;
- loopback backend and frontend URLs;
- unique actors with `role`, public `account`, and local `storage_state` and private `signer_state` paths;
- `author_proposer`, `member_reporter_voter`, and `nonmember_ineligible` roles;
- at least nine roles prefixed `reviewer_original_` for the seven-person original panel plus two substitutes;
- at least nine disjoint roles prefixed `reviewer_appeal_` for the seven-person fresh appeal panel plus two substitutes;
- the primary post, group, group-post, dispute, and proposal identifiers;
- separate active negative-fixture group, dispute, and proposal identifiers;
- the signed transaction transcript path.

Recovery files, private keys, secret keys, mnemonics, browser state contents, cookies, and session material are forbidden in the manifest itself.

Before the signed journey, the author, member, and all 18 reviewers must reach Tier 2 through normal controlled-devnet Tier-1 and Tier-2 transactions; the outsider remains Tier 0. Open PoH bootstrap is not part of the M3 closure path. Each reviewer must explicitly opt into both `content_review` and `dispute_review`. The first lane supplies content-report panel candidates, while the second authorizes dispute acceptance, attendance, and ballots.

Build the manifest from a local actor list:

```bash
python scripts/build_m3_actor_manifest.py \
  --implementation-freeze "$M3_IMPLEMENTATION_FREEZE_COMMIT" \
  --backend-base-url http://127.0.0.1:18401 \
  --frontend-base-url http://127.0.0.1:5173 \
  --actors-file /secure/runtime/m3-actors.json \
  --transaction-transcript /secure/runtime/m3-transaction-transcript.json \
  --post-id post:m3:001 \
  --group-id group:m3:001 \
  --group-post-id post:m3:group:001 \
  --dispute-id dispute:m3:001 \
  --proposal-id proposal:m3:001 \
  --negative-post-id post:m3:negative \
  --negative-group-id group:m3:negative \
  --negative-dispute-id dispute:m3:negative \
  --negative-proposal-id proposal:m3:negative \
  --out /secure/runtime/M3_ACTOR_MANIFEST.json
```

## Signed transaction transcript

Every positive action must identify:

- `label`;
- `role` and public `account`;
- canonical `tx_type`;
- canonical `tx_id` (or a deterministic inline-transition evidence id where explicitly allowed);
- canonical `subject_id`;
- `status: "confirmed"`.

The evidence contract binds every label to an allowed transaction type and actor role. For ordinary actions the Playwright gate independently fetches `/v1/tx/status/{tx_id}` and verifies terminal status, canonical signer, and transaction type.

`DISPUTE_RESOLVE` is intentionally different: the runtime applies it inline in the threshold-reaching `DISPUTE_VOTE_SUBMIT`; no standalone `DISPUTE_RESOLVE` transaction is admitted or indexed for that transition. The `dispute_resolution` transcript row must therefore use `evidence_kind: "inline_system_transition"`, include the confirmed `trigger_tx_id` for the threshold-reaching original-panel ballot, and set `tx_id` to `inline:<trigger_tx_id>:DISPUTE_RESOLVE`. Validation proves the trigger is a confirmed ballot for the same dispute, and the real-stack gate proves the canonical dispute state contains the resulting resolution. A fabricated standalone `DISPUTE_RESOLVE` tx id is invalid evidence.

Required positive labels cover:

- public post, group, membership, and group-post creation;
- report, seven original-panel acceptances, attendances, ballots, and resolution;
- appeal, seven fresh appeal-panel acceptances, attendances, ballots, and final receipt;
- proposal creation, comment, at least two eligible ballots, close, tally, and finalization.

System-produced transitions use `role: "system_scheduler"` and `account: "SYSTEM"`. Human action records must bind exactly to an actor role/account pair from the manifest.

## Negative fixtures and attempts

Negative attempts are executed live by independent browser contexts after the gate confirms that:

- the negative group exists and the group-write actor is a Tier-2 reviewer who is not a member;
- the negative dispute remains in an active review stage and the chosen nonselected reviewer is actually outside its assigned panel/substitute set;
- a distinct negative appeal dispute is resolved but remains in `appeal_window`, with the author as affected target owner;
- the negative proposal remains in an active voting stage.

Each negative attempt must include `label`, `role`, `account`, `tx_type`, `payload`, `subject_id`, exact `expected_error_code`, exact `expected_error_reason`, and `expected_rejection_layer` (`admission` or `apply`). Duplicate, replacement, and revoke attempts that prove prior-ballot immutability also require `precondition_tx_id`, which must reference a confirmed prior ballot by the same actor against the same active subject.

Admission-layer negatives must fail before `/v1/tx/submit` admits the envelope. Apply-layer negatives must be admitted as signed canonical transactions, included in a persisted block, and then surface through `/v1/tx/status/{tx_id}` as `status: rejected`, `apply_ok: false`, with the exact deterministic receipt `code` and `reason`. HTTP acceptance into mempool is not semantic success.

The fixed negative contract proves:

- a Tier-2 nonmember cannot write to a group without group authority;
- nonselected and conflicted dispute voting fail at the public `Juror` admission gate;
- a Tier-0 governance voter fails at the public `Tier2+` admission gate;
- governance duplicate, replacement, and revoke attempts are block-backed apply rejections;
- dispute duplicate and replacement ballots are block-backed apply rejections, while the nonexistent revoke tx type is rejected as noncanonical at admission;
- a nonowner appeal against a distinct dispute in `appeal_window` is rejected by the target-owner authority check.

The transcript is public evidence and must contain no private keys, recovery material, session tokens, cookies, authorization headers, or browser storage-state contents.

## Private signer-state companion

Playwright storage-state files preserve cookies and local storage, but browser account signing seeds are intentionally held in session storage. Each private actor record therefore includes a `signer_state` path outside the repository. The file schema is `{"schema_version": 1, "account": "@...", "secretKeyB64": "..."}`. The real-stack runner injects that seed into session storage before opening a page. Signer-state files are never copied into `artifacts/m3-closure/` or the public actor manifest.
