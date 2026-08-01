# Phase 1 — Canonical Group Membership Execution Trace

Truth boundary: real files and functions in the supplied source snapshot. No Git identity is available.

## A. Group creation

1. `GroupCreatePayload` in `Weall-Protocol/src/weall/runtime/tx_schema.py` accepts `group_id`, `charter`, public participation permissions, and public read visibility. It has no membership-policy field.
2. `GROUP_CREATE` in `generated/tx_index.json` is a user-origin mempool transaction gated by `Tier2+`.
3. `admit_tx()` in `src/weall/runtime/tx_admission.py` validates the modeled payload, signature policy, nonce, reputation/flags, and the `Tier2+` gate.
4. `domain_apply.apply_tx()` performs atomic execution; `domain_dispatch.apply_tx()` enforces canon and routes the transaction to `apply_groups()`.
5. `_apply_group_create()` in `src/weall/runtime/apply/groups.py` creates the canonical record in `roles.groups_by_id` and mirrors that same object at top-level `groups_by_id`.
6. The creator becomes a signer and member, but the canonical top-level `moderators` list is initialized as empty.
7. Result: the creator can satisfy `GroupSigner`, but cannot satisfy `GroupModerator` without a later moderator-setting path.

## B. Membership request

1. `/v1/groups/join` returns a `GROUP_MEMBERSHIP_REQUEST` skeleton.
2. The route emits optional text under payload key `message`.
3. `GroupMembershipRequestPayload` permits optional key `note` and forbids extra keys.
4. Therefore a request with text is rejected at canonical schema admission with `invalid_payload/schema_validation_failed`.
5. A request without text passes the schema and the `Tier1+` canonical gate.
6. `_apply_group_membership_request()` forces public read metadata, checks existing membership, then directly inserts the requester into `members` with `joined_via=request_auto_accept`.
7. Any same-account entry in `membership_requests` is removed.
8. Result: no pending request survives for a later decision transaction.

## C. Membership decision

1. `GROUP_MEMBERSHIP_DECIDE` is a user-origin mempool transaction gated by `GroupModerator`.
2. `_gate_ok()` calls `eval_gate()`; `GroupModerator` dispatches to `_is_group_moderator()`.
3. `_is_group_moderator()` requires an available Tier-2 account and an active record in the canonical group `moderators` authority location.
4. A newly created group has `moderators=[]`; the creator therefore fails canonical admission.
5. Even if a moderator were separately installed, `_apply_group_membership_decide()` does not require a pending request. It can add any target account on an `accept` decision and returns success when rejecting a nonexistent request.
6. Result: the current apply function is not a faithful “decision on a prior request” contract.

## D. Group leave API mismatch

1. `/v1/groups/leave` describes itself as self-removal and emits `GROUP_MEMBERSHIP_REMOVE` signed by the leaving account.
2. Canon gates `GROUP_MEMBERSHIP_REMOVE` with `GroupModerator`.
3. An ordinary member therefore cannot submit the route-generated skeleton successfully.
4. This is a separate API/canon mismatch. It is outside the minimum M3 formal journey but must be resolved before operator/public UX closure.

## E. Formal M3 consequence

The evidence contract distinguishes `membership_request` as `GROUP_MEMBERSHIP_REQUEST` and `membership_accept` as `GROUP_MEMBERSHIP_DECIDE`. The runtime converts the request into immediate membership and initializes no moderator able to submit the decision. The required signed journey is impossible through the canonical path.
