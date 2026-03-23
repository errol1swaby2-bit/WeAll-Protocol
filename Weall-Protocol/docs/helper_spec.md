# WeAll Helper Production Safety Spec v1 (Executable)

Reference:
- Authoritative protocol spec (HotStuff) must remain canonical consensus
- Helpers operate strictly as deterministic execution accelerators

## Core Rule
Serial execution result == Helper execution result (ALWAYS)

## Deterministic Planner
Inputs:
- ordered tx list
- validator set (normalized)
- block context (height, parent, epoch)

Output:
- lane mapping
- helper assignment

## Receipt Schema
Fields:
- chain_id
- epoch
- validator_set_hash
- parent_block_id
- height
- lane_id
- ordered_tx_ids
- input_state_hash
- output_state_hash
- helper_signature

## Merge Rule
- Canonical lane order
- No cross-lane mutation conflicts
- Deterministic application only

## Fallback Rule
If helper missing:
- proposer executes lane locally

## Invariants
1. Deterministic assignment
2. Deterministic laneing
3. Canonical ordering
4. Verifiable receipts
5. Deterministic merge
6. Crash equivalence
7. Byzantine rejection
8. Serial equivalence
