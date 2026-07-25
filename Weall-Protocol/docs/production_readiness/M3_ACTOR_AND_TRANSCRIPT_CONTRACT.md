# M3 actor and signed-transaction evidence contract

The M3 real-stack gate consumes a **schema-v3 actor manifest** and a **schema-v1 signed transaction transcript**. These files are runtime inputs. They may reference private local browser storage-state files, but private custody files are never copied into `artifacts/m3-closure`.

## Actor manifest

The manifest must contain:

- the exact full implementation-freeze commit;
- loopback backend and frontend URLs;
- unique actors with `role`, public `account`, and local `storage_state` paths;
- `author_proposer`, `member_reporter_voter`, and `nonmember_ineligible` roles;
- at least nine roles prefixed `reviewer_original_` for the seven-person original panel plus two substitutes;
- at least nine disjoint roles prefixed `reviewer_appeal_` for the seven-person fresh appeal panel plus two substitutes;
- the primary post, group, group-post, dispute, and proposal identifiers;
- separate active negative-fixture group, dispute, and proposal identifiers;
- the signed transaction transcript path.

Recovery files, private keys, secret keys, mnemonics, browser state contents, cookies, and session material are forbidden in the manifest itself.

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
- unique `tx_id`;
- canonical `subject_id`;
- `status: "confirmed"`.

The evidence contract binds every label to an allowed transaction type and actor role. The Playwright gate independently fetches every `/v1/tx/status/{tx_id}` record and verifies its terminal status, canonical signer, and transaction type.

Required positive labels cover:

- public post, group, membership, and group-post creation;
- report, seven original-panel acceptances, attendances, ballots, and resolution;
- appeal, seven fresh appeal-panel acceptances, attendances, ballots, and final receipt;
- proposal creation, comment, at least two eligible ballots, close, tally, and finalization.

System-produced transitions use `role: "system_scheduler"` and `account: "SYSTEM"`. Human action records must bind exactly to an actor role/account pair from the manifest.

## Negative fixtures and attempts

Negative attempts are executed live by independent browser contexts after the gate confirms that:

- the negative group exists;
- the negative dispute remains in an active review stage and targets the conflicted actor;
- the negative proposal remains in an active voting stage.

Each negative attempt must include `label`, `role`, `account`, `tx_type`, `payload`, `subject_id`, and the exact `expected_error_code`. Duplicate, replacement, and revoke attempts also require `precondition_tx_id`, which must reference a confirmed prior ballot by the same actor against the same active subject.

The fixed negative contract proves:

- nonmember group writing is rejected;
- nonselected and conflicted dispute voting are rejected;
- ineligible governance voting is rejected;
- governance duplicate, replacement, and revoke attempts are rejected;
- dispute duplicate, replacement, and nonexistent revoke attempts are rejected.

The transcript is public evidence and must contain no private keys, recovery material, session tokens, cookies, authorization headers, or browser storage-state contents.
