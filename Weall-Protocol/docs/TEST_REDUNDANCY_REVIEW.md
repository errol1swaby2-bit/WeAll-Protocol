# Test Redundancy Review

This pass did not delete or merge tests. The repository baseline was treated as safety-clean, and batch-numbered filenames were considered a presentation problem rather than proof of redundant coverage.

| File A | File B | Overlap | Unique assertions | Decision | Reason |
|---|---|---|---|---|---|
| Not applicable in this patch | Not applicable in this patch | No mechanically proven exact duplicate was removed | Not applicable | keep all | The audit found many similar historical/progression names, but no candidate was deleted because the required mechanical and semantic redundancy proof was not established in this pass. |

## Deletion standard retained

A future deletion or merge must prove the same invariant, equivalent fixture setup, same code path, same or weaker assertion strength, no unique environment posture or regression value, targeted pass after removal, and no remaining docs/scripts/generated references.

## Fixture deduplication review

No fixture was deduplicated in the function-level cleanup patch. Similar setup helpers remain intentionally duplicated where they protect different runtime postures, temporary directory layouts, process boundaries, genesis/testnet profiles, frontend source scans, or release-export contexts. The audit did not find a fixture pair that satisfied the same setup class, same code path, and same assertion-strength requirements without weakening failure diagnostics.

Decision: **defer fixture deduplication** until a focused patch can prove equivalence and run the affected domain tests.
