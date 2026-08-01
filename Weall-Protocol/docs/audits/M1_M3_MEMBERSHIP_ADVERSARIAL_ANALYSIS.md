# Phases 2–5 — Membership Invariants, Adversarial Analysis, Divergence, and Exploit Chains

## Derived invariants

1. Public read visibility is independent of membership participation rights.
2. Canonical group authority is read from `roles.groups_by_id`; API mirrors must reference the same object rather than a divergent copy.
3. `GROUP_MEMBERSHIP_DECIDE` may be admitted only for an active Tier-2 group moderator.
4. In an approval workflow, a decision must consume exactly one existing pending request.
5. A request must not both create membership and remain evidence of an independent pending action.
6. Repeating a request must be deterministic and must not create multiple pending records.
7. Acceptance and rejection must produce distinct deterministic outcomes.
8. A newly created approval-required group must have at least one canonical authority capable of deciding its first request.
9. Legacy groups without an explicit membership policy need one deterministic compatibility interpretation.
10. API skeleton payload keys must exactly match the strict transaction schema.

## Adversarial findings

### A. Unrequested membership grant

**Precondition:** an attacker controls or compromises any account in the group moderator list.

**Chain:**
1. Submit `GROUP_MEMBERSHIP_DECIDE` with `decision=accept` for an account that never requested membership.
2. Canonical `GroupModerator` admission succeeds.
3. `_apply_group_membership_decide()` constructs an empty request map when none exists.
4. It inserts the target account into `members` without checking request existence.
5. It returns an apparently valid decision receipt.

**Impact:** the transaction name and evidence semantics claim a decision, but no application existed. This breaks traceability and can create unauthorized participation eligibility.

### B. Evidence aliasing failure

**Chain:**
1. Member submits `GROUP_MEMBERSHIP_REQUEST`.
2. Apply immediately adds the member.
3. Formal evidence later expects a separately signed acceptance.
4. The creator cannot admit the acceptance because the creator is not a canonical moderator.
5. Any attempt to treat the request as both request and acceptance violates the evidence contract.

**Impact:** M3 closure cannot be authentic; a tool may be tempted to relabel one transaction as two actions.

### C. API skeleton denial

**Chain:**
1. User enters a join message.
2. API emits `message` in the skeleton.
3. Client signs the exact skeleton.
4. Strict schema permits only `note`.
5. Admission rejects the signed transaction.

**Impact:** a legitimate UI path fails only when optional text is used, creating a hard-to-diagnose operator/user defect.

### D. Self-leave denial

**Chain:**
1. Ordinary member calls `/v1/groups/leave`.
2. API emits a self-signed `GROUP_MEMBERSHIP_REMOVE`.
3. Canon requires `GroupModerator`.
4. Admission rejects the member.

**Impact:** the API promises a capability that canonical policy denies.

## Divergence analysis

The confirmed membership defects are deterministic semantic contradictions rather than node-to-node nondeterminism: conforming nodes will all auto-accept and all deny the creator’s moderator-gated decision. The greater divergence risk is policy bifurcation between canonical `runtime/gate_expr.py` and the apparently legacy `ledger/gate_resolver.py`. If a future path reintroduces the legacy resolver, two execution/admission surfaces could interpret authority differently. The current audit has not proven that legacy module reachable in production, so this remains a risk rather than a confirmed exploit.

## Required correction properties

- `membership_mode` must normalize to exactly `open` or `approval_required`.
- Missing legacy mode must deterministically mean `open`.
- New groups must persist the normalized mode in canonical group state and public metadata.
- The creator must be installed in the canonical top-level moderator list.
- Open mode may auto-accept but must identify that result explicitly.
- Approval-required mode must store a pending request and leave membership unchanged.
- A decision must reject when no matching pending request exists.
- Acceptance must consume the request and create membership; rejection must consume the request without membership.
- Route text must use schema key `note`.
- Tests must cover schema, admission, apply, state, duplicate request, nonexistent decision, nonmoderator decision, acceptance, rejection, and replay.
