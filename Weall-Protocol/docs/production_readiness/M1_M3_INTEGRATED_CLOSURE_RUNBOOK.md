# M1-M3 current-head integrated closure runbook

This process rolls the historical Spec-M1, M2, and R-M3 closures forward to one
new implementation freeze. It does not widen their authorization boundary.

## 1. Apply and validate the implementation patch set

Start from a clean branch descending from the intended GitHub `main` commit.
Install the exact Python and frontend dependencies, then run:

```bash
PYTHONPATH=Weall-Protocol/src \
  python Weall-Protocol/scripts/check_consensus_profile_manifest.py

PYTHONPATH=Weall-Protocol/src \
  python -m pytest -q \
    Weall-Protocol/tests/test_consensus_signature_policy_pinning.py \
    Weall-Protocol/tests/test_consensus_profile_manifest.py \
    Weall-Protocol/tests/test_protocol_blocker_safety.py

bash scripts/run_m1_m3_adversarial_matrix.sh
```

## 2. Reproducible environment

Build the closure image from the repository root:

```bash
docker build \
  --file docker/Dockerfile.m1-m3-closure \
  --tag weall-m1-m3-closure:2026-07-30 .
```

The exact Python lockfiles, npm lockfile, Playwright base image, consensus-profile
manifest, source commit, source tree, and installed package inventory are bound
into the cumulative evidence.

## 3. Restore and verify historical evidence

```bash
bash scripts/restore_m2_m3_evidence_from_git.sh --verify-only
```

Use the command without `--verify-only` only when a complete local copy of the
historical evidence trees is needed. The integrated closure itself generates
fresh evidence at the new freeze.

## 4. Fast iterative closure pass

```bash
export M1_M3_IMPLEMENTATION_FREEZE_COMMIT="$(git rev-parse HEAD)"
bash scripts/run_m1_m3_cumulative_closure.sh --source-only
```

Delete `artifacts/m1-m3-integrated` after an iterative pass before modifying or
committing implementation code.

## 5. Record the implementation freeze

After every source, generated-canon, test, configuration, documentation, and
closure-tooling change is committed and the tree is clean:

```bash
export M1_M3_IMPLEMENTATION_FREEZE_COMMIT="$(git rev-parse HEAD)"
git status --short
test -z "$(git status --porcelain --untracked-files=all)"
```

The freeze must not contain `artifacts/m1-m3-integrated/**`.

## 6. Prepare the new M3 actor contract

The private M3 actor manifest and signed transaction transcript must be rebuilt
for the new freeze. Private signer and browser storage state remain outside the
repository. Follow `M3_FINAL_CLOSURE_RUNBOOK_WSL.md`, then export:

```bash
export WEALL_M3_ACTOR_MANIFEST="$HOME/.local/share/weall/m1-m3-${M1_M3_IMPLEMENTATION_FREEZE_COMMIT:0:12}/M3_ACTOR_MANIFEST.json"
```

## 7. Run the full cumulative closure

The runner executes source/build/adversarial gates and then runs complete M2 and
M3 closures in separate detached worktrees at the exact same freeze:

```bash
M1_M3_IMPLEMENTATION_FREEZE_COMMIT="$M1_M3_IMPLEMENTATION_FREEZE_COMMIT" \
WEALL_M3_ACTOR_MANIFEST="$WEALL_M3_ACTOR_MANIFEST" \
  bash scripts/run_m1_m3_cumulative_closure.sh --full
```

## 8. Create the evidence-only direct child

```bash
git add -f artifacts/m1-m3-integrated
M1_M3_IMPLEMENTATION_FREEZE_COMMIT="$M1_M3_IMPLEMENTATION_FREEZE_COMMIT" \
  bash scripts/check_m1_m3_evidence_only_commit.sh --cached

git commit -m "evidence(m1-m3): close current-head integrated readiness"
export M1_M3_EVIDENCE_COMMIT="$(git rev-parse HEAD)"

M1_M3_IMPLEMENTATION_FREEZE_COMMIT="$M1_M3_IMPLEMENTATION_FREEZE_COMMIT" \
  bash scripts/check_m1_m3_evidence_only_commit.sh
```

No source, configuration, test, generated-canon, specification, or documentation
change is permitted in this child.

## 9. Merge preservation

Merge the release branch with a merge commit. Do not squash or rebase. Verify
that both the freeze and evidence commits remain ancestors and that the merge
introduces no tree change beyond the evidence child.

```bash
git merge --no-ff release/m1-m3-current-head-closure
git merge-base --is-ancestor "$M1_M3_IMPLEMENTATION_FREEZE_COMMIT" HEAD
git merge-base --is-ancestor "$M1_M3_EVIDENCE_COMMIT" HEAD
test "$(git rev-parse HEAD^{tree})" = "$(git rev-parse "$M1_M3_EVIDENCE_COMMIT^{tree}")"
```

## 10. Signed detached release archive

```bash
export WEALL_RELEASE_GPG_KEY="YOUR_GPG_KEY_FINGERPRINT"
M1_M3_IMPLEMENTATION_FREEZE_COMMIT="$M1_M3_IMPLEMENTATION_FREEZE_COMMIT" \
M1_M3_EVIDENCE_COMMIT="$M1_M3_EVIDENCE_COMMIT" \
WEALL_RELEASE_GPG_KEY="$WEALL_RELEASE_GPG_KEY" \
  bash scripts/build_signed_m1_m3_release.sh
```

The archive, provenance record, and checksum ledger receive separate detached
ASCII-armored signatures. An unsigned rehearsal is supported only through the
explicit `--unsigned-rehearsal` flag and is not a release artifact.
