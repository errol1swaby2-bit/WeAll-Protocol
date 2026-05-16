# Production Node Bootstrap

This runbook is for independent validator and public-node operators.

## Goal

Before a node is exposed to untrusted peers, validate that it is in a fail-closed production posture.

## Required inputs

- `configs/prod.chain.json` or a custom file referenced by `WEALL_CHAIN_CONFIG_PATH`
- `generated/tx_index.json`
- node identity keypair supplied through either environment variables or `*_FILE` secrets
- validator account secret if BFT validation is enabled
- trusted-anchor sync enabled for networked production nodes

## Fast validation

From `Weall-Protocol/`:

```bash
./scripts/bootstrap_prod_node.sh
```

That script validates:

- chain config shape and production-safe flags
- tx index presence
- db parent path writability
- presence of node identity keys when networking/BFT is enabled
- presence of validator account when BFT is enabled
- `WEALL_SIGVERIFY` is not disabled
- `WEALL_STATE_SYNC_REQUIRE_TRUSTED_ANCHOR` remains enabled for production networking

## Recommended secrets layout

```text
/run/secrets/weall_node_pubkey
/run/secrets/weall_node_privkey
/run/secrets/weall_validator_account
```

Then set:

```bash
export WEALL_NODE_PUBKEY_FILE=/run/secrets/weall_node_pubkey
export WEALL_NODE_PRIVKEY_FILE=/run/secrets/weall_node_privkey
export WEALL_VALIDATOR_ACCOUNT_FILE=/run/secrets/weall_validator_account
```

## Minimum operator checks after startup

- `GET /v1/status`
- `GET /v1/status/consensus`
- `GET /v1/status/operator`
- container/process logs for handshake, sync, and BFT timeout activity

## Fail-closed expectations

A production node should refuse startup or reject runtime participation if any of these are true:

- unsigned transactions are allowed
- signature verification is disabled
- BFT/networking is enabled without node identity keys
- BFT is enabled without a validator account
- trusted-anchor sync is disabled for a production networked node

## Fresh machine workflow

```bash
git clone <repo>
cd Weall-Protocol
python3 -m venv .venv
. .venv/bin/activate
pip install -e .
./scripts/bootstrap_prod_node.sh
```

Then start the intended production deployment profile.

After the local DB exists, run:

```bash
python3 scripts/verify_validator_bootstrap.py
```

See also `docs/validator_bootstrap_verification.md`.


## Observer onboarding vs production service boot

`boot_onboarding_node.sh` is the safe observer/onboarding wrapper. It now requires either a verified public observer bundle through `WEALL_NODE_OPERATOR_ONBOARDING_BUNDLE` or an already-passed observer preflight marker. It forces observer mode and must not be used as proof of production service authority.

`boot_node_operator.sh` is the production service wrapper for an already activated node operator. It runs `scripts/prod_node_preflight.sh` before entering `run_node_prod.sh`, so production service boot and production preflight remain one fail-closed path.

A two-machine rehearsal is connectivity/preflight only. The observer onboarding E2E is not complete until `scripts/external_observer_live_gate.sh` passes against the intended genesis API.
