# Milestone 3 implementation freeze and evidence-only closure

Milestone 3 is closed only by a clean implementation-freeze commit followed by a separately validated evidence-only direct child. Passing unit tests, source checks, or a seeded page-navigation demo is not sufficient.

## 1. Blocking implementation conditions

Before creating the freeze, all M3 traceability rows must be `closed` or `evidence_required`. The closure runner must reject any remaining:

- `open_protocol_gap`;
- `planned_failing_test`;
- unresolved M-050 ballot-contract divergence;
- unresolved M-051 electorate-snapshot divergence;
- validator-as-political-elector behavior;
- vote replacement or revocation after first admission;
- browser skip/fixme or demo-seed dependency;
- direct runtime-applier substitution for signed API submission;
- browser-timer stage or finalization authority;
- missing transaction/read-model reconciliation.

The bounded M3 proof may use a no-action civic proposal. It must not imply executable upgrade, constitutional, treasury, economic, validator, or node-operation authority.

## 2. Implementation-freeze commit

The freeze contains all source, generated canon, tests, runbooks, traceability files, actor-manifest tooling, closure runners, and evidence tooling.

Record it only from a clean tree:

```bash
export M3_IMPLEMENTATION_FREEZE_COMMIT="$(git rev-parse HEAD)"
```

The freeze must descend from the audited M1/M2-closed base and must not contain `artifacts/m3-closure/**`.

## 3. Mandatory closure suite

The canonical runner will be:

```bash
M3_IMPLEMENTATION_FREEZE_COMMIT="$M3_IMPLEMENTATION_FREEZE_COMMIT"   bash scripts/run_m3_complete_closure.sh
```

It must run, capture, and verify at least:

1. requirement traceability;
2. generated canon freshness and clean-checkout reproduction;
3. complete backend tests;
4. frontend typecheck, production build, contracts, and public-only safety;
5. non-skippable independent-browser M3 journey;
6. signed group create, canonical membership request, member write, and nonmember public read;
7. signed report, independent reviewer acceptance/attendance/votes, outcome, appeal, and final receipt;
8. scope-correct frozen governance electorate;
9. eligible ballot acceptance plus ineligible, duplicate, replacement, and revoke rejection;
10. block-height close, tally, and finalization receipts;
11. privacy/secret scan proving protected identity and key material are absent;
12. restart/replay equality;
13. two-node state-root and receipt equality;
14. observer catch-up without authority;
15. artifact sanitization and evidence-manifest generation.

No mandatory browser or network gate may report skipped, expected failure, or synthetic fallback.

## 4. Evidence manifest

The future schema-v2 M3 manifest must bind:

- implementation-freeze commit and tree hash;
- exact command ledger and success markers;
- every evidence file path, byte size, and SHA-256;
- actor public identities and role labels without private keys or recovery material;
- content, group, dispute, appeal, electorate, ballot, tally, and finalization identifiers;
- receipt/transcript hashes;
- restart/replay, two-node, and observer final-state summaries;
- the M3 truth boundary and explicit exclusions.

The builder must reject symlinks, out-of-tree paths, missing evidence families, private-key/recovery markers, skipped journeys, demo actors, direct-applier proof, and an evidence tree inherited from the freeze.

## 5. Evidence-only direct child

The evidence commit may contain only:

```text
artifacts/m3-closure/**
```

The checker must verify the staged Git blobs before commit and the committed tree afterward. It must prove:

- direct-parent relationship to the recorded freeze;
- complete manifest/path-set equality;
- hashes, sizes, counts, command markers, receipts, and state summaries;
- no source, configuration, test, specification, generated-canon, or documentation changes;
- no private material;
- no missing or inherited evidence file.

## 6. Merge preservation

Use a merge commit, not squash or rebase. The merge tree must be byte-for-byte equal to the evidence-only child and both closure commits must remain ancestors of `main`.

## 7. Closure claim

After all gates pass, the allowed claim is:

> R-M3 closes the controlled-testnet, multi-actor, signed content, public-group, dispute/review/appeal, and no-action civic-governance proposal-to-finalization flows at the implementation freeze recorded in the current M3 evidence manifest.

This does not claim public beta, Mainnet, production constitutional governance, executable governance actions, emergency governance, public validator/BFT readiness, live economics, complete global anti-collusion protection, independent external review, or completion of R-M1.
