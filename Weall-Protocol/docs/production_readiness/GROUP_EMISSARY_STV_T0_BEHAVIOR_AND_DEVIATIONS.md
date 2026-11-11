# T0 — Current group-emissary STV golden vectors and nonstandard transfer finding

**Status:** OBSERVED CURRENT BEHAVIOR ONLY · NOT A NORMATIVE STV CERTIFICATION · NO PROTOCOL CHANGE  
**Source audited:** `src/weall/runtime/apply/groups.py` (`_stv_winners` and `_apply_group_emissary_election_finalize`) at commit `f98fd31e15eb55ef98d282f17e7b028c49dd6058`.  
**Fixture:** `specs/research/group_emissary_stv_t0_vectors_v0_1.json`  
**Independent behavioral model:** `scripts/validate_group_emissary_stv_t0.py`  
**Cross-check tests:** `tests/test_group_emissary_stv_t0_vectors.py`

## Purpose

Freeze the **existing** election selection behavior as hard-coded outcomes and event traces, without changing consensus code. The reference uses one unit per active preference and no production `Fraction`, pile structures or runtime tally imports. These checks protect current historical replay compatibility; they do **not** endorse the algorithm or prove that it satisfies ordinary STV.

## High-priority discrepancy: quota weight is not retained

The current helper describes itself as “Deterministic STV (Droop quota) with Fraction weights.” It determines a Droop-style quota and splits elected candidates' piles into retained and surplus weights. **But it then removes the elected candidate from the active set and reassigns both the retained and surplus parcels to their next eligible preference**. Since their fractional weights sum to the previous weight and share the same preference list, this is mathematically equivalent to transferring **100%** of that ballot's active weight after election rather than retaining the quota.

**Golden example:** 2 seats, 4 candidates, 7 ballots: A→C four times, B twice, D→B once. Quota is 3. Current behavior elects **A then C**, because all four A voters flow to C. Under conventional surplus-only transfer, only one of A's four votes of surplus flows to C; when D is eliminated, B would reach quota and win the second seat. The current result is therefore not safely described as ordinary Droop-quota STV.

This may alter elected emissaries and, via `_apply_group_emissary_election_finalize`, the group signer and treasury signer thresholds. Treat this as a **high-priority governance-integrity finding requiring separate protocol resolution and historical replay analysis**. Do **not** silently fix it within this golden-vector increment.

## Other current behavior characterized

- When two candidates meet quota with the same weight, lexicographically smaller IDs elect first.
- When two candidates have the same lowest weight, lexicographically smaller IDs eliminate first.
- Invalid/duplicate candidate preferences are filtered, empty ballots are ignored for quota, and exhausted partial rankings cease to contribute.
- A helper call with `seats <= 0` returns no winners; valid election creation must require at least five emissary seats.
- When candidate count equals remaining seats, the helper fills the remaining slate alphabetically, regardless of first-choice count.
- With one participating voter and six candidates for five seats, a slate of five can still be seated. This is current behavior, **not proof of electorate legitimacy or quorum sufficiency**.
- With **zero valid ballots**, the raw STV helper would still fill the slate, but the **canonical finalizer explicitly returns `no_decision`** and must not alter group or treasury authority. The integration tests bind this distinction.
- The strict profile's aggregated apply-state is not a secret ballot: canonical signed envelopes still identify the signer alongside plaintext choices. T0 uses synthetic ranking fixtures and confers no new privacy claim.

## Evidence gates and limits

The fixture stores hard-coded winners, quota and deterministic event traces for nine cases. The independent no-Fraction behavioral reference and production helper must both match each vector. Candidate/voter insertion order reversal must not alter results. Three five-seat fixtures also exercise actual current finalization, including signer/treasury authority effects and the no-decision non-mutation boundary.

These tests are source/fixture evidence. They do not establish signed two-node consensus finality, full chain replay across versions, cryptographic tally soundness, a normative STV correction, a quantum-resistant ballot system, or constitutional approval.

**Next isolated work:** open a distinct protocol-compatibility/design decision for the retained-quota defect, specify intended STV variant, review impact on existing historical blocks and election finality, devise a versioned activation/migration rule if a change is authorized, and demonstrate its invariants before any new emissary election uses the corrected algorithm.

**No new ballot transaction, no secret-ballot activation, no new treasury authority, no runtime code change. PR #88 and PR #81 remain DRAFT / NO-GO.**
