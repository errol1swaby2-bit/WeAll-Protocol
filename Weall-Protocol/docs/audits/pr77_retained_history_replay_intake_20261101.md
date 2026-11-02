# PR77 retained-history replay intake — NOT COMPLETE

Status: **BLOCKED until authentic retained chain data is supplied.** This is an
offline review tool, not an assertion that historical or two-node consensus
equivalence has been established. No production database is opened by CI.

Source requirements:
- Supply a **quiesced, independently preserved OFFLINE copy** of a node SQLite
  ledger. Never pass the live DB or a symlink to it.
- Require a trustworthy source-chain identity, captured source SHA-256, and
  pinned checkout SHA and tx-index SHA-256. Preserve provenance externally.
- The input must contain the native SQLite `blocks` and `ledger_state`
  tables, with all blocks from height 1 through the retained tip.
- No SQLite WAL/SHM sidecars. If an active node uses WAL, create a proper
  SQLite backup after quiescence; do not simply discard WAL files.

On the exact PR77 checkout, from `Weall-Protocol/` with locked dependencies
installed, create a **new empty scratch directory** (not a symlink) and run:

```bash
python scripts/pr77_retained_history_replay.py \
  --offline-source-db /path/to/verified-offline-copy.sqlite \
  --source-sha256 '<externally-captured-source-sha256>' \
  --chain-id '<historical-chain-id>' \
  --scratch-dir /path/to/new-empty-scratch-dir \
  --tx-index generated/tx_index.json \
  --tx-index-sha256 '<pinned-index-sha256>' \
  --expected-commit '<full-checkout-sha>' \
  --report /path/to/replay-report.json
```

The tool opens the source with SQLite `mode=ro&immutable=1`, validates the
archive and rejects gaps, missing commitments, branch/index mismatches and
different chain identity. It creates a **new** scratch executor and compares
every re-applied block/header commitment and calculated state root to the
retained committed block, failing at the first mismatch. On success, it emits
a per-height transcript of block ID, block hash, state root and receipts root
for comparison with separately pinned historical/external runs. The scratch
directory must be empty, and the optional report must be a new file, never
the source SQLite ledger or pinned transaction index. Canonical state
and receipt roots are validated within the block `header`, not as
nonexistent top-level block fields.

A PASS means only single-revision replay against the supplied stored
commitments succeeded. The report deliberately sets the fields for historical
provenance, old-version compatibility, and independent two-node convergence
to false. Record old-executor replay separately on pinned historical software,
compare receipts and state-root timelines and investigate any first divergent
height. Validate independent two-node catch-up afterwards. Do not update V2
semantic review attestations or treat this tool as merge authorization.

The repository tracks no suitable old SQLite ledger in its tracked-file
inventory. The dedicated CI workflow tests offline-intake guards and a short, **synthetic** three-block replay through the actual executor. It is **not** historical replay evidence.

## Separate single-runner two-node rehearsal (not historical proof)

The `.github/workflows/pr77-local-two-node-restart-catchup.yml` workflow
runs the existing `scripts/devnet_restart_catchup_live.sh` on an ephemeral
GitHub Actions runner. It boots two **local** controlled-devnet processes
with separate databases, exercises signed transactions and verified state
sync, restarts each process from persisted state, and checks state-root parity
after each restart. It uploads comparison/sync logs only, not the node
databases or generated operator key files.

A green run demonstrates the single-runner devnet path, **not** historical
compatibility, machine independence, a third-party attestation, decentralized
validator consensus or public testnet readiness. It cannot close either the
retained-history archive prerequisite or external two-machine review gate.


## Pinned-main-to-review synthetic cross-revision replay — positive bounded evidence (2026-11-01)

**PASS, but STILL NOT HISTORICAL-LEDGER REPLAY.** New read-only CI
`.github/workflows/pr77-cross-revision-synthetic-replay.yml` checks out
two independently pinned code revisions into separate directories and Python
environments:

- Base: `main` commit `2f35cfb5823cc083a3cb833798cf60a1b1895377`.
- Candidate: PR77 commit `f7aa3460f17a056a09a08188005449695ff73898`
  for the first verified run.
- Both use Python 3.12 and their respective hashed dev dependency locks.
- GitHub verifies checkout HEAD identities, distinct revisions, identical
  tracked synthetic fixture generator and transaction index.
- The base produces and stores a **three-block synthetic testnet ledger**
  with six signed `ACCOUNT_REGISTER` submissions, replayed by a second base
  executor. The retained base SQLite DB is hashed and treated as offline
  source input to the PR77 historical-intake verifier.
- The PR77 verifier replays **the base-produced stored blocks** in a fresh
  scratch executor. It independently checks the hash-bound source and TX
  index, each block's commitment, each per-height state root and final state
  root. The workflow also compares the three produced block IDs and hashes to
  the base manifest and asserts the final state root matches exactly.
- No databases, operator keys or key files are uploaded to Actions
  artifacts; only a synthetic-source JSON manifest and a replay result JSON.

[Successful run 41377240939](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/41377240939)
includes the [non-secret dual-report artifact](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/41377240939/artifacts/13112121006).
Both selected code revisions successfully executed on the separate Python
environments and passed the three-height checks. The generated report
preserves `historical_provenance_verified=false`,
`old_version_compatibility_proven=false` and
`independent_two_node_consensus_proven=false`; the workflow adds only
`synthetic_cross_revision_replay_proven=true`.

This evidence narrows uncertainty about *ordinary signed account
registration block compatibility* between the pinned main revision and the
review branch. It does not exercise severe dispute votes, the initial
20/25-juror outcome, fresh appeal assignment, ACCOUNT_BAN receipt
authorization, reviewer-lane opt-out admission, or explicit v2 reputation
role-gate activation. It cannot show that an **independently captured,
historically retained** old ledger will replay, and does not certify any
public or two-machine consensus workflow.

The missing authentic old-chain database remains the **hard gate**. Do not
rename this result as a historical replay, update any V2 digest, or merge
from a green synthetic compatibility check.


## Controlled two-node rehearsal on review head — passed (2026-11-01)

The existing `pr77-local-two-node-restart-catchup.yml` workflow
was updated to trigger on changes to the executor, block builder,
block replay, system queue, roles, reputation, and dispute runtime
modules, in addition to changes to the rehearsal scripts. This is
a **test scheduling correction**, not a consensus rule change.

[Run 41377414524](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/41377414524)
**PASS** at commit `9bd8ac7a71af95f2c1b1c1cdcece71e42cc875c7`.
The CI ran two controlled-devnet processes with independent local
SQLite stores on the **same ephemeral runner**, performed the
signed-transaction cross-node convergence probe, synchronized node 2
from node 1, and compared canonical roots.

- Both nodes reached parity after initial convergence.
- Following persisted-state restart of **node 2**, catch-up reached
  parity on **attempt 1**.
- Following persisted-state restart of **node 1**, catch-up again
  reached parity on **attempt 1**.
- The workflow uploaded non-secret comparison, sync and convergence
  logs but not node databases or operator keys.

This independent process-state observation complements but does not
merge with the pinned-main synthetic three-height replay result.
The exercise does **not** represent two separate machines or operators,
remote open-network BFT, production-identity/PoH enrollment, severe
juror/appeal finality, BFT adversarial partition convergence, or
retained historical state-root compatibility. Public-genesis
rehearsal and V2 semantics are still blocked; preserve PR77 Draft
NO-GO and do not refresh stale review digests.


## Legacy role cross-revision outcome probe — six metadata differences (2026-11-01)

The first `pinned-main → PR77` synthetic replay workflow was extended to
run an **identical 126-case legacy role/reviewer transaction matrix** inside
each pinned revision's separately installed environment. The single source
script, `scripts/pr77_legacy_role_parity_probe.py`, verifies that its
`weall.runtime.apply.roles` import actually comes from the requested
checkout. The matrix includes 9 TX types, two parameter states (missing
`reputation_role_gate_version` and explicit integer v1), and seven
synthetic conditions (normal, banned, locked, Tier1, manually revoked, low
scalar reputation, absent account). Both sides invoke the actual
`run_with_bounded_rollback` role dispatcher and capture exact result
metadata or exception code/reason/details, plus input and output consensus
state roots. Rejected transactions must roll back their state.

**Finding: exact outcome parity FAILS in six of 126 synthetic cases**;
the other 120 match. All six have the same input state root, output state
root, admission-independent status and all other metadata. The **sole
difference** is the `deduped` value:

| Transaction | State | Pinned main | PR77 |
| --- | --- | --- | --- |
| `ROLE_JUROR_ACTIVATE` | Already active; missing version and explicit v1 | `false` | `true` |
| `ROLE_JUROR_REINSTATE` | Already active; missing version and explicit v1 | `false` | `true` |
| `ROLE_NODE_OPERATOR_ACTIVATE` | Already active; missing version and explicit v1 | `false` | `true` |

**Zero state-root differences** were observed across all 126.
The known source-level mechanism is the `JournaledList` proxy in
`bounded_rollback.py`. Pinned main inherits C-level list membership from
the empty underlying proxy list; PR77 now overrides `__contains__` to
query the actually persisted target list. This fixes the proxy's observable
semantics and the previously proven discrepancy against deepcopy, but also
changes returned `deduped` metadata when a role is already active.

**Consensus receipt-root scope:** Both current block construction
(`block_builder.py`) and follower replay (`block_replay.py`) produce
successful canonical receipts from `tx_id`, `tx_type`, `signer`,
`nonce` and `ok`; they do **not** serialize the role applier's
`deduped` field into the success receipt. Therefore these six
`deduped` differences alone do **not** change the current canonical
receipt root or state root. This observation does not establish that all
possible metadata consumers, earlier historical receipt schemas, or
other list operations are equivalent. A real retained old ledger and
source-specific replay remain required.

[Discovery run 41378027258](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/41378027258)
first stopped at the already-active juror difference. The expanded
diagnostic [run 41378163352](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/41378163352)
printed the **six complete mismatches** and preserved old/current case
summaries and machine-readable variance in a non-secret Actions artifact.
The cross-revision *block replay* step independently passed in these
workflows; the overall job is red **specifically because exact applier
metadata parity was required**. Do not relabel the job as a replay failure
or silently forgive the differences. Whether to add a reviewed
versioned compatibility policy for auxiliary metadata needs a
distinct, explicit decision; no runtime or semantic digest change was
authorized by this probe.

This is a synthetic applier matrix: no signed historical role blocks,
historical external node ledger, historical activate/opt-out roots,
cryptographic SYSTEM queue origin, or independent BFT replay is established.
PR77 stays Draft/unmerged and public-testnet NO-GO.


The historical base and current review candidate also have **identical
tracked Git blob IDs** for both canonical commit/replay implementations:
`block_builder.py` =
`65081c2da6cb56c4c699454f0faf12f68d9a9381`, and
`block_replay.py` =
`57f35d90d8dafb64ff6e698b7cc09ab519882991`.
This pins the above success-receipt shape to *both code revisions*, not
just to the new candidate. It does not establish the behavior of
untracked historical software or data.


## Strict receipt-boundary classification of the six legacy dedupe deltas

**Result: PASS in scoped synthetic cross-revision execution; not semantic
approval or authentic historical replay.** The prior full-applier-output
comparison identified six old `deduped=false` vs new `deduped=true`
outcomes (three already-active role operations under missing and explicit
v1 gate versions), even though 126/126 pre/post state roots matched.

A new strict classifier
`scripts/pr77_legacy_role_parity_adjudication.py` compares both
126-case transcripts. It requires all cases to remain correctly ordered,
identically initialized, with identical outcome status, error/rejection
information, input and post-execution state roots, and canonical
receipt-shaped objects hashed by the actual `compute_receipts_root`.
It permits **only six exact** differences in the *auxiliary* `deduped`
metadata for already-active `ROLE_JUROR_ACTIVATE`,
`ROLE_JUROR_REINSTATE`, and `ROLE_NODE_OPERATOR_ACTIVATE` in the
two legacy policy-version configurations. Any extra, missing, reversed
or modified difference fails. Twelve adversarial unit tests test the
unclassified-change and state/receipt fail-closed behavior.

The workflow verifies byte-identical pinned-main/PR77 sources for
`block_builder.py` and `block_replay.py` before the comparison.
Both implementations construct successful receipts without the
`deduped` metadata. In the parity matrix, each receipt is
**reconstructed with a synthetic test-only transaction ID**; it is
not an admitted, signed, committed historical role transaction.
Therefore matching synthetic receipt roots support the limited
conclusion that the six metadata-only deltas cannot affect **that
canonical success-receipt shape**, not that an authentic historical
role/dispute ledger has replayed.

[Run 41379560860](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/41379560860)
**PASS** at commit `fdb05165842dd8826b6cff392f0abe055ec1aa81`:
pinned-main three-block signed synthetic-chain replay passed;
strict Ruff checks and format passed; **12 adversarial tests passed**;
and the two 126-case transcripts had identical synthetic receipt roots
and state roots, with exactly six documented auxiliary metadata differences.
[Non-secret artifact 13112289802](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/41379560860/artifacts/13112289802)
contains both transcripts, the scoped adjudication result and synthetic
replay summary, not database/key material.

The strict **consensus-boundary diagnostic** can now pass without
pretending full applier metadata parity or allowing new differences.
The machine-readable results explicitly retain:
`strict_full_applier_metadata_parity=false`,
`authentic_retained_history_proven=false`,
`v2_semantic_review_approved=false`, and `release_ready=false`.
No consensus rule, existing V2 semantic-review acceptance digest,
or historical block was changed. All 15 V2 reviews remain outstanding;
real old-chain role/dispute/severe-case history, per-height committed
receipt/state-root checks, independent nodes and an authenticated
severe-sanction producer remain release blockers.


## Replay-bound signed-opening observation (2026-11-02; review only)

Optional offline-only arguments `--opening-tx-id tx:<64-lowercase-hex>`
and `--opening-case-id <canonical-dispute-id>` must be provided **together**.
The replay tool then locates the one opening transaction by the retained
block's canonical header transaction IDs, captures the replay-executor
**predecessor state** immediately before applying the containing block, and
verifies that the predecessor root equals the previously replayed block's
committed state root. Height-one openings fail closed: there is no replayed
predecessor; a separately authenticated genesis anchor is still needed.

After ordinary full block replay, the tool requires the stored and re-executed
block to agree, checks the post-state root against the committed header and
source snapshot, loads the actual case from the replayed post-state, and runs
the existing genuine-ML-DSA signed-opening/source-commitment reviewer.
Any missing case, claimed ID not found, duplicate ID, root mismatch, invalid
signature, or inconsistent case/receipt source causes the optional witness
request to **fail**. The successful report contains only the opening ID,
case ID, height, block ID/hash, predecessor and post-state roots, and boolean
observations. It does **not** export account keys, evidence contents,
signatures, unredacted dispute state, or the original database.

The opt-in witness is a stricter *single-revision replay-relative* link; it
is **not** an external chain provenance certificate. The source SQLite copy,
its initial/retained genesis lineage and BFT finalization must still be
authenticated independently. The witness always returns
`constitutional_authorization=NOT_ESTABLISHED`,
`may_classify_canonical_case=false`, and
`may_enqueue_account_ban=false`. The existing replay report retains
`historical_provenance_verified=false`,
`old_version_compatibility_proven=false`, and
`independent_two_node_consensus_proven=false`.

**Test coverage:** the new optional path has fail-closed regression cases for
malformed or incomplete identifiers before any source read and an actual
synthetic three-block executor replay proving that an absent opening ID cannot
produce a witness. No authentic historical DISPUTE_OPEN ledger was available,
so the positive runtime integration of this optional path remains **unproven**
and must be tested with a preserved genuine opening once available.


## Positive *synthetic* committed-opening replay (2026-11-02; not historical proof)

The preflight workflow now invokes
`tests/test_pr77_signed_opening_synthetic_replay.py`, which configures an
**explicit, deterministic test-only genesis bootstrap** for `@alice` on a
controlled-devnet chain. The bootstrap profile is part of the initialized
state; it is not inserted into the ledger after the first block. The test
submits and commits a genuinely signed `@bob` account registration at
height 1, then submits and commits a genuinely signed `@alice`
`DISPUTE_OPEN` at height 2 using the real mempool, producer and domain
applier. The opening explicitly supplies `dispute_id`, as required by
the *admission schema*, while the applier also supports an autogenerated ID
on its lower-level domain path. This difference is tracked as an
admission/applier divergence; it must not be mistaken for proof of
end-to-end acceptance of omitted IDs. Its account target and public
reason are normalized from the signature-covered payload.

The original SQLite is then opened read-only by the existing
`replay_offline_source`, and a fresh scratch executor reconstructs
the recorded chain from the same deterministic genesis. The opt-in
witness checks the previous block's state root, replays the disputed
block, loads the canonical case **from the replayed post-state**, and
verifies its original signed opening with ML-DSA, complete block
commitments and the recorded success receipt. Wrong-case substitution
must fail closed. Neither the fixture's genesis private key nor the
source SQLite is uploaded to CI artifacts.

The review-only verifier now recognizes both actual chain-bound
signature policy representations (`require_signatures=true` and
`block_tx_signature_policy=required`) and separately handles the
canonical chain-only signature domain with **no network_id** in either
transaction or state. A single-sided claimed network is still rejected.
Missing top-level `block_hash` is accepted **only** when the
existing complete-block validator recomputes and checks the hash
from the committed header. Actual signature verification is always
performed and cannot be bypassed by testnet policy switches.

A passing test proves only **single-revision, locally generated
synthetic signed-opening replay compatibility**. It is not a retained
external historical ledger, independently finalized BFT/QC ancestry,
cross-version compatibility, authentic PoH uniqueness evidence or a
constitutionally authorized S4 opening or penalty. The witness and
overall replay report remain fail-closed on every authority field.


### Admission-schema observation

The initial positive synthetic preflight failed **safely before block production**
because `tx_schema.DisputeOpenPayload` requires the `dispute_id` field.
`apply.dispute._mk_id` can generate an ID when that field is omitted if
invoked directly; this is a lower-level compatibility behavior, not valid
canonical external transaction ingress. The repaired positive fixture supplies
an explicit signed `dispute_id`. Independent semantic-review approval of the
DISPUTE_OPEN schema remains pending; this change **does not** loosen the
admission gate or change consensus.


### Reviewer key-layout correction — 2026-11-02

A positive synthetic replay exposed a mismatch in the *reviewer*, not
in consensus signature admission. The initial helper used
`weall.crypto.sig.verify_tx_sig_against_any_key`, whose separate
`extract_active_account_pubkeys` only supports account key **lists**.
Canonical genesis bootstrap writes active keys into `keys.by_id` (a mapping).
The actual runtime's `weall.runtime.sigverify._extract_active_keys`
supports both formats. The reviewer now uses that existing active-key
extraction, but verifies the exact ML-DSA signature through
`canonical_tx_message` and `verify_signature_for_profile` directly.
It deliberately avoids runtime `verify_tx_signature`'s
`WEALL_UNSAFE_DEV` fallback and never substitutes a caller-authored
`verified=true` flag. It continues to require signed transaction chain
identity, matching predecessor signer keys, and complete block commitments.
This is read-only review tooling; consensus verification is unchanged.
