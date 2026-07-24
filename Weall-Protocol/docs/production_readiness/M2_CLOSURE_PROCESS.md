# Milestone 2 implementation freeze and evidence-only closure

Milestone 2 is closed only by a two-commit sequence: a clean implementation-freeze commit followed by a separately validated evidence-only commit. Passing source tests alone is necessary but not sufficient.

## 1. Implementation-freeze commit

The freeze commit contains all source, generated canon artifacts, tests, runbooks, and closure scripts. Its working tree must be clean and all local deterministic checks must pass.

Record it:

```bash
export M2_IMPLEMENTATION_FREEZE_COMMIT="$(git rev-parse HEAD)"
```

The public-testnet seed registry must be rotated through the legitimate operator signing ceremony before the closure runner can pass. Test keys, controlled-devnet keys, and bypasses are not valid substitutes.

## 2. Run the closure suite

```bash
bash scripts/run_m2_complete_closure.sh
```

The runner refuses skipped mandatory browser journeys, stale chain artifacts, an unsigned public-testnet registry, state-root mismatch, failed observer catch-up, or missing requirement traceability. Restart/replay, two-node equality, and observer catch-up gates write canonical `final-state.json` summaries in their evidence directories.

## 3. Build the evidence manifest

```bash
python3 scripts/build_m2_evidence_manifest.py \
  --artifact-root artifacts/m2-closure \
  --freeze-commit "$M2_IMPLEMENTATION_FREEZE_COMMIT"
```

Schema version 2 records and binds:

- the implementation-freeze commit and tree hash;
- the exact closure command ledger and success markers;
- every committed evidence file's path, byte size, and SHA-256 digest;
- restart/replay, two-node, and observer final state roots;
- transcript hashes;
- the controlled-testnet truth boundary.

The builder rejects missing evidence families, symlinks, paths outside the repository, and likely private-key material.

## 4. Evidence-only commit

Stage only:

- `artifacts/m2-closure/**`;
- the generated closure evidence manifest;
- no source, configuration, test, or specification files.

Validate the staged shape and contents:

```bash
M2_IMPLEMENTATION_FREEZE_COMMIT="$M2_IMPLEMENTATION_FREEZE_COMMIT" \
  bash scripts/check_m2_evidence_only_commit.sh --cached
```

The checker independently reads the staged Git blobs and verifies:

- exact agreement between the manifest file list and the staged evidence paths;
- hashes, sizes, artifact count, and required evidence families;
- the command ledger and required success markers;
- final-state summaries and transcript hashes;
- absence of private-key markers;
- the freeze commit, tree hash, and evidence-only parent relationship.

After committing the evidence, rerun without `--cached` against the resulting commit:

```bash
M2_IMPLEMENTATION_FREEZE_COMMIT="$M2_IMPLEMENTATION_FREEZE_COMMIT" \
  bash scripts/check_m2_evidence_only_commit.sh
```

## 5. Closure claim

Milestone 2 may be marked closed only after:

1. the operator-authorized public-testnet seed-registry rotation passes;
2. the implementation-freeze commit exists;
3. every mandatory closure gate passes from that freeze;
4. the schema-v2 evidence manifest validates;
5. the evidence-only commit exists and passes the independent checker.

This closes the Milestone 2 account-custody, recovery, async/live PoH, and outside-tester onboarding scope. It does not claim public beta, public validator admission, public multi-validator BFT, live economics, or Mainnet readiness.
