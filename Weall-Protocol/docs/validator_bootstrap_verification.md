# Validator Bootstrap Verification

This runbook hardens the production bootstrap story for independent validators.

## Goal

Before a node is allowed to sign votes, verify that the local machine agrees with the intended network on the following invariants:

- chain id
- state schema version
- production consensus profile hash
- tx index hash
- validator epoch
- validator set hash
- optional trusted anchor

## Why this exists

Independent operators need a deterministic way to confirm they did not join the wrong network view or restart into a stale validator epoch.

`bootstrap_prod_node.sh` validates the operator posture and required secrets.
`verify_validator_bootstrap.py` verifies that the local DB, tx index, and protocol binary are still aligned.

## Usage

From `Weall-Protocol/`:

```bash
./scripts/bootstrap_prod_node.sh
python3 scripts/verify_validator_bootstrap.py
```

Machine-readable output:

```bash
python3 scripts/verify_validator_bootstrap.py --json
```

Verify against an expected trusted anchor file:

```bash
python3 scripts/verify_validator_bootstrap.py \
  --trusted-anchor ./trusted_anchor.json
```

## What the verifier checks

The script compares the runtime binary, tx index file, and persisted SQLite state.

It fails when it detects any of the following:

- chain id mismatch between chain config and persisted state
- production consensus profile hash mismatch between binary and persisted state
- tx index hash mismatch between generated tx index and persisted state
- schema version disagreement between SQLite metadata and state metadata
- trusted-anchor mismatch for height, finalized height, tip hash, state root, or finalized block id

## Recommended validator workflow

1. Run `./scripts/bootstrap_prod_node.sh`.
2. Start the node in observer / non-signing mode after any unclean shutdown.
3. Run `python3 scripts/verify_validator_bootstrap.py --json`.
4. Confirm the reported validator epoch and validator set hash match the intended network epoch.
5. Only then enable signing / voting.

## Output fields

The verifier emits:

- `protocol_profile_hash`
- `tx_index_hash`
- `validator_epoch`
- `validator_set_hash`
- `normalized_validators`
- `trusted_anchor.observed`
- `issues`

A non-empty `issues` array must be treated as a fail-closed condition for public-validator participation.
