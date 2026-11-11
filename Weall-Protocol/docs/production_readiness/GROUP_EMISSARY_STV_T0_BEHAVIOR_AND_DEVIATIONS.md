# T0 — Intended WeAll sequential preference redistribution: behavioral golden vectors

**Status:** INTENDED WEALL RULE VERIFIED AGAINST CURRENT CODE · NOT CONVENTIONAL QUOTA-RETAINING STV · NO PROTOCOL CHANGE  
**Source audited:** `src/weall/runtime/apply/groups.py` (`_stv_winners` and `_apply_group_emissary_election_finalize`), anchored to prior source commit `f98fd31e15eb55ef98d282f17e7b028c49dd6058`.  
**Golden vectors:** `specs/research/group_emissary_stv_t0_vectors_v0_1.json`  
**Independent reference model:** `scripts/validate_group_emissary_stv_t0.py`  
**Focused tests:** `tests/test_group_emissary_stv_t0_vectors.py`

## Explicit design-intent clarification (2026-11-10)

The WeAll protocol architect clarified the intended election rule:

> Once the first slot makes its choice, the votes are redistributed to the voters' preferred second candidate.

**Interpretation encoded in the tests:** when a candidate is selected to occupy a seat, every ballot currently assigned to that candidate remains at full weight and is reassigned to its highest-ranked *still-eligible* candidate. The same process repeats for each successive seat. If a voter's second choice is already elected or eliminated, the tally uses that voter's next eligible ranked choice. If no preference remains, that ballot is exhausted. Candidates not yet selected or eliminated retain their votes.

This is an **intentional full-weight, sequential ranked-preference redistribution mechanism**. It is not conventional surplus-only STV, even though the existing helper docstring names a Droop quota and calls itself “STV.” The earlier audit incorrectly labeled the full-weight transfer a **defect**. That classification is **withdrawn**. The current code and the stated intention agree on the central transfer behavior.

The helper currently splits winning piles into retained and surplus fractions but then reassigns both to the remaining active candidates, preserving full vote weight. This is an implementation equivalence, not evidence of an unintended tally error.

## Confirmed examples

### Two seats, seven voters

Four ballots: A → C. Two ballots: B. One ballot: D → B.

- A wins the first seat with four first choices; all four A ballots move to C.
- C receives four votes and wins the second seat.
- **WeAll expected result: A, C.** A conventional surplus-retaining STV calculation might produce A, B, but **that is not WeAll's specified rule** and should not be substituted.

### Five seats, six voters

All six voters rank A → B → C → D → E → F.

The full six votes move in order to the next eligible preferred candidate after every selection. The five selected emissaries, in order, are **A, B, C, D, E**, with a tally of six at each seat selection. The new golden vector and canonical finalization integration test cover this sequence.

## Additional existing invariants

- Lexicographically sorted candidate IDs break equal leading-tally elections and equal-low-tally eliminations.
- Duplicate/unknown ranked choices are filtered; partial ballots can exhaust.
- The election-creation/finalization contract requires at least **five seats**, while raw helper tests may exercise smaller or zero-seat edge cases.
- When remaining candidate count equals the number of unfilled seats, remaining candidates are seated alphabetically. This is an explicit existing edge behavior to review against the intended governance contract, not a claim of voter turnout.
- With one ballot and six nominees for five seats, the current code seats five emissaries. **No minimum-turnout or quorum rule is established by this test.** Those legitimacy rules are a separate governance question.
- With zero valid ballots, canonical finalization returns **no_decision** and leaves group and treasury authorization unchanged. Do not infer finalization behavior solely from the helper's raw zero-ballot result.
- Current signed ballot envelopes still expose signer and plaintext ranking. Sequential redistribution does not establish a secret ballot.

## Replay, change control and limits

Golden fixtures and the independent reference model verify the design's current transfer semantics against the production helper without altering production consensus. Two paths are kept separate:

1. **Existing rule preservation:** no migration or retained-quota correction is warranted by the transfer behavior alone. Preserve historical replay.
2. **Possible future rule changes:** changes to tie handling, empty/partial ranking behavior, default seat filling, turnout/quorum requirements, election eligibility or cryptographic ballot transport would require a separate constitutional decision, versioned activation and replay analysis.

The independent reference is behavioral, not an independent proof of every consensus-state path, constitutional approval, production ledger history, multi-node finality or cryptographic privacy. The public election UI remains read-only; no ballot-submission authority is enabled.

**PR #88 and stacked PR #81 remain DRAFT / NO-GO.** No runtime tally rule, treasury signer authority or production voting path was changed in this clarification.
