# M1–M3 Closure Operator Runbook

## Prerequisites

A full Git clone with history; clean dedicated branch/worktree; Python and Node versions required by lockfiles; locked dependencies including ML-DSA-capable `cryptography`; no running process using the intended replacement live directory; private actor/custody material outside Git; and enough disk space for isolated worktrees, logs, state copies, and evidence.

## Read-only audit

```bash
bash scripts/audit_m1_m3.sh --check-only --json-out "$HOME/.local/share/weall/m1-m3-audit.json"
```

## Source tests

```bash
bash scripts/test_m1_m3_source.sh --json-out "$HOME/.local/share/weall/m1-m3-source.json" --require-ruff
```

## Upgrade tests

```bash
bash scripts/test_upgrade_safety.sh --json-out "$HOME/.local/share/weall/m1-m3-upgrade.json"
```

## Freeze creation

Run the complete backend/frontend/clean-checkout gates, review every generated change, commit source, then record:

```bash
IMPLEMENTATION_COMMIT="$(git rev-parse HEAD)"
IMPLEMENTATION_TREE="$(git rev-parse 'HEAD^{tree}')"
printf 'implementation_commit=%s\nimplementation_tree=%s\n' "$IMPLEMENTATION_COMMIT" "$IMPLEMENTATION_TREE"
```

Do not create evidence until HEAD equals this clean implementation commit.

## Formal journey preflight

```bash
bash scripts/run_m3_formal_journey.sh \
  --implementation-freeze "$IMPLEMENTATION_COMMIT" \
  --actor-manifest "$HOME/.local/share/weall/m3-private/actor-manifest.json" \
  --check-only
```

## Evidence generation

```bash
bash scripts/build_m1_m3_evidence.sh \
  --implementation-freeze "$IMPLEMENTATION_COMMIT" \
  --actor-manifest "$HOME/.local/share/weall/m3-private/actor-manifest.json"
```

The actor manifest must use fresh keys/accounts and point to fresh live endpoints. Never copy prior M3 evidence into the replacement directory.

## Evidence-only commit

Review and stage only approved evidence paths. Run cached validators before committing. The commit must be the direct child of the implementation freeze and contain no source changes or private custody material. Then run committed validation:

```bash
bash scripts/check_m1_m3_closure.sh \
  --formal \
  --implementation-freeze "$IMPLEMENTATION_COMMIT" \
  --evidence-commit HEAD
```

## Golden path

```bash
bash scripts/close_m1_m3.sh \
  --implementation-freeze "$IMPLEMENTATION_COMMIT" \
  --actor-manifest "$HOME/.local/share/weall/m3-private/actor-manifest.json" \
  --check-only

bash scripts/close_m1_m3.sh \
  --implementation-freeze "$IMPLEMENTATION_COMMIT" \
  --actor-manifest "$HOME/.local/share/weall/m3-private/actor-manifest.json"
```

The orchestrator never commits automatically. Human review remains mandatory.

## Troubleshooting

- `source_export`: operate from the real Git checkout; no formal workaround is valid.
- `tree dirty`: preserve a binary patch outside the repository, then restore a clean worktree.
- `semantic review mismatch`: inspect old/new authoritative material and update only explicitly reviewed entries.
- `missing ML-DSA`: install the exact locked dependency set in an isolated environment.
- `wrong freeze`: do not relabel evidence; recreate it at the intended freeze.
- `actor manifest invalid`: regenerate private actors; do not edit public evidence to match.
- `live directory busy`: stop the owning process before archiving or replacing it.
- `migration failure`: retain the original database and logs; never continue from a partial output.

## Cleanup

Temporary worktrees and processes are removed by traps. Live databases, historical freezes, actor custody, and evidence archives are never deleted by generic cleanup. Verify repository status and run the privacy scanner before staging.
