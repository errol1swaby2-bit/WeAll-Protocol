# PR77 nested dictionary proxy JSON hashing investigation

**Classification: open consensus-sensitive parity concern; no semantic fix or approval.**

The bounded rollback `JournaledDict` inherits `dict` but stores canonical
entries in `_target`, while built-in dictionary storage is empty. Python's
native `json.dumps` can encode the empty inherited dictionary rather than
iterating the delegated entries. Both the entire proxy and nested proxies
inside otherwise ordinary dictionaries can produce unintended hash inputs.

The new adversarial regression `tests/test_pr77_nested_proxy_json_hash.py`
compares the four existing canonical JSON hash helpers in the Content,
Dispute, Governance and Groups apply modules against detached, raw JSON
inputs. A separate fixture invokes the Dispute module's legacy
deattributed-resolution-recording helper with nested state-derived input.

These are marked `xfail(strict=True, raises=AssertionError)` **only while
the incompatibility exists**. An unexpected fix changes these to XPASS and
breaks CI until the reviewer explicitly removes the stale expected-failure
markers. A green workflow with XFAIL is **not** a consensus or release PASS.

`materialize_journaled` already provides the correct raw JSON snapshot.
Moving source-bound helpers onto it may alter computed consensus hashes for
previously committed blocks. Therefore this diagnostic must **not** be used
to justify a blind change, manifest regeneration, role/V2 attestation
refresh, or network activation. First identify actual production reachability,
capture pinned pre-fix commitments and validate old-version replay, then
decide on protocol-safe versioning or an explicitly authorized migration.

The 236-current-vector executor parity suite remains valuable but lacks
adversarial deep JSON proxy coverage. Historical ledger and independent
two-node proof remain blocked.

## Corrective implementation results (2026-11-01)

The four canonical JSON hash functions now call
`materialize_journaled(value)` before passing data to Python's JSON encoder.
The earlier strict XFAIL tests were converted to ordinary equality tests,
and the dedicated CI at
https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/41364359110
passed **6 tests** with no XFAILs. This fixes the reported nested-proxy
hash differences for those current-version fixtures. Previous XFAIL results
above remain part of the audit trail for the pre-fix implementation.

Do not infer compatibility with finalized pre-fix blocks or independent V2
semantic approval from this result. These tests check deterministic parity
under the present code and synthetic inputs only. PR #77 remains Draft and
historical replay review remains NO-GO.
