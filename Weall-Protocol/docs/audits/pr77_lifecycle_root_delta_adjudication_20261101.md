# PR77 — lifecycle source-bound adjudication (review still required)

**Status: NO-GO for semantic attestation refresh, historical replay closure and merge.**

The diagnostic compares the tracked 236-row V1.5 lifecycle manifest with a
fresh in-memory candidate. It reports exact JSON-pointer differences,
current-fixture state transition paths and the results of independent deepcopy
versus bounded-journal execution for every changed transaction.

Run at the pinned draft revision from `Weall-Protocol/`:

```bash
ruff check scripts/pr77_lifecycle_drift_audit.py tests/test_pr77_lifecycle_drift_audit.py
ruff format --check scripts/pr77_lifecycle_drift_audit.py tests/test_pr77_lifecycle_drift_audit.py
python -m pytest -q tests/test_pr77_lifecycle_drift_audit.py
python scripts/pr77_lifecycle_drift_audit.py \
  --report pr77_lifecycle_drift_report.json \
  --candidate pr77_lifecycle_candidate.json
```

The final command **must fail while unreviewed drift exists**. Both outputs are
created outside tracked `generated/`; no lifecycle approval, source state,
old chain, V2 digest, or committed expectation is modified.

The four known changed transactions are `ROLE_JUROR_ACTIVATE`,
`ROLE_JUROR_REINSTATE`, `ROLE_JUROR_SUSPEND`, and
`ROLE_NODE_OPERATOR_SUSPEND`. Tests reject any extra changed row,
unanticipated non-row drift, or mismatch between current execution engines.

The listed current-fixture state paths are **not** old-versus-new historical
state differences. A prior state root is a cryptographic commitment, not a
reversible encoding of the old state. An oracle match under today's code does
not establish pre-fix historical compatibility. Closing the underlying
consensus risk still requires authenticated old blocks, pinned original
software and policies, per-height receipt/state-root comparison and a
separate external two-node replay, followed by authorized semantic review.

No merge, attestation refresh, public validator launch, or production enablement.

## Authorized source-bound manifest refresh — 2026-11-01

The draft's current fixture generator was re-run after the journal identity
and nested JSON hash corrections. The guarded workflow confirmed **248
passing current-version tests**, changed exactly the four known role rows,
and rejected any extra transaction or top-level semantic drift. The
source-derived manifest-only refresh commit is `78c64132788891d957e5185fb163d44872587818`.
No other tracked file changed in that commit.

The previous four-row comparison remains available in the workflow evidence
and earlier revisions. From the refreshed baseline, the diagnostic test
requires **zero** candidate-versus-committed differences. This does not
establish historical chain replay, pre-fix migration compatibility, V2
semantic-review authorization, or permission to merge/launch.
