# PR77 — DISPUTE_OPEN V2 semantic attribution investigation (no review accepted)

All three red PR77 CI workflows currently fail at the same V2 semantic-review
digest: `DISPUTE_OPEN`. Backend CI also attempts to upload a P0 assurance
artifact after the compilation step has failed.

**Verified source comparison:** `def dispute_open` and `def apply_dispute`
in `src/weall/runtime/apply/dispute.py` are textually identical between
`main` and PR77 at `3de576f5ce0bb1efd628a8f2086300a3867be07d`.

**Root-cause candidate:** `tx_appliers.json` bound `DISPUTE_OPEN` to the
generic `apply_dispute` dispatcher, while all sibling dispute transactions
had direct bindings to their actual handlers. The V2 static analyzer only
prefers `apply_*`/`_apply_*` callees during dispatch branch extraction and
otherwise transitively visits up to 24 local functions, potentially
attributing unrelated severe-sanction and appeal code changes to
`DISPUTE_OPEN`. This patch fixes the *source registry* to bind directly to
`dispute_open` and adds a static analyzer regression test.

**No review digest was altered.** The V2 compiler must still report stale
accepted material until the new, narrowly scoped contract fields are
inspected against the previous generated contract and explicitly accepted by
the authorized reviewer. The diagnostic workflow reports all stale review
types and exact field differences without changing review or derivative
files. Another failure may be revealed after DISPUTE_OPEN acceptance.

The correction to the V2 source registry is analytical only. It does not
change runtime transaction dispatch, constitutional authority, activated
protocol behavior or ACCOUNT_BAN fail-closed gates. PR77 remains Draft.
