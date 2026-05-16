# Promoted Observer to Validator Runbook

Purpose: safely move a second machine from external observer posture into full validator posture only after protocol authority exists on-chain.

This runbook is intentionally fail-closed. Observer onboarding proves account/device/peer/PoH-case creation. It does not prove node-operator authority, validator authority, BFT signing authority, or consensus peer acceptance.


## Two-machine boundary and BFT minimum

The current HotStuff/BFT production constant is `BFT_MIN_VALIDATORS = 4` in
`src/weall/runtime/bft_hotstuff.py`. A genesis node plus one promoted second
machine can prove observer onboarding, node-operator readiness, validator
readiness, validator-set plumbing, reboot posture, and fail-closed signing
boundaries. It does **not** prove full HotStuff/BFT finality or Byzantine fault
tolerance until the active validator set reaches the production minimum.

`scripts/promoted_validator_preflight.sh` and
`scripts/promoted_validator_live_gate.sh` therefore default their required active
validator count to the production BFT minimum. Setting
`WEALL_PROMOTED_VALIDATOR_MIN_ACTIVE_VALIDATORS` lower is allowed only for a
clearly labeled bootstrap/readiness rehearsal; it must not be represented as a
full BFT-active consensus proof.

## Required proof before reboot

The second machine may reboot as a validator only after all of these are true on the genesis/finalized chain:

1. Account exists.
2. Account has the required live verification state or an auditable bootstrap Tier2 grant.
3. The node key is registered through `ACCOUNT_DEVICE_REGISTER` with `device_type=node`.
4. `ROLE_NODE_OPERATOR_ENROLL` is committed.
5. `ROLE_NODE_OPERATOR_ACTIVATE` is committed by system/governance authority.
6. `NODE_OPERATOR_VALIDATOR_OPT_IN` is committed by the account and references the registered node key.
7. `VALIDATOR_READINESS_VERIFY` is committed with a live readiness receipt.
8. `ROLE_VALIDATOR_ACTIVATE` is committed by system/governance authority.
9. The active validator set/epoch has been updated through `VALIDATOR_SET_UPDATE` and exposes a non-empty validator set hash.
10. The local manifest/profile/tx-index hash matches the genesis node.
11. Full BFT-active signing is attempted only when the active validator count is at least `BFT_MIN_VALIDATORS` unless this is explicitly labeled as a bootstrap/readiness rehearsal.

## Commands on the second machine before reboot

Set the promoted account and node key values:

```bash
export WEALL_GENESIS_API_BASE="https://GENESIS_HOST_OR_LAN_IP:8000"
export WEALL_CHAIN_MANIFEST_PATH="./configs/chains/weall-genesis.json"
export WEALL_VALIDATOR_ACCOUNT="@promoted-account"
export WEALL_BOUND_ACCOUNT="$WEALL_VALIDATOR_ACCOUNT"
export WEALL_NODE_PRIVKEY_FILE="$HOME/.weall/node.key.json"
export WEALL_NODE_PUBKEY="<registered node public key>"
export WEALL_BFT_PUBKEY="<validator BFT public key if separate>"
export WEALL_CORS_ORIGINS="https://your-frontend-or-operator-origin.example"
```

Clear observer-only values. The reboot script does this again, but operators should understand the boundary:

```bash
unset WEALL_NODE_OPERATOR_ONBOARDING_BUNDLE
unset WEALL_OBSERVER_PREFLIGHT_ALREADY_PASSED
unset WEALL_EXTERNAL_OBSERVER_REQUIRE_LIVE_API
unset WEALL_EXTERNAL_OBSERVER_BOOT
unset WEALL_EXTERNAL_OBSERVER_WORK_DIR
```

Run preflight:

```bash
bash scripts/promoted_validator_preflight.sh
```

This checks the remote genesis API, manifest identity, tx-index hash, protocol-profile hash, active node-operator status, active validator responsibility, validator-readiness receipt binding, validator-set hash, and active validator count. This is authorization to attempt the reboot; it is not proof that the local process has already caught up or will be allowed to sign immediately.

## Reboot as validator

```bash
bash scripts/reboot_promoted_observer_as_validator.sh
```

The reboot script sets:

```text
WEALL_NODE_LIFECYCLE_STATE=production_service
WEALL_SERVICE_ROLES=node_operator,validator
WEALL_OBSERVER_MODE=0
WEALL_NET_ENABLED=1
WEALL_BFT_ENABLED=1
WEALL_VALIDATOR_SIGNING_ENABLED=1
```

It refuses to boot if observer posture remains active or if protocol authority is missing.


## State sync / catchup boundary before signing

A promoted validator must not treat remote genesis authority as local signing authority. After reboot, the local node must load or sync the finalized state that contains the node-operator activation, validator readiness receipt, validator activation, validator-set update, validator epoch, and validator-set hash. If the post-boot gate reports `local_signing_not_allowed_by_consensus_state`, `local_is_not_active_validator`, or a validator-set/hash mismatch, keep the node running in catchup/diagnostic mode and do not bypass the fail-closed signing check.

The correct outcome for stale local state is failure to sign, not forced signing.

## Post-boot live gate

In a second terminal, point to the local validator API and the genesis API:

```bash
export WEALL_LOCAL_VALIDATOR_API_BASE="http://127.0.0.1:8000"
export WEALL_GENESIS_API_BASE="https://GENESIS_HOST_OR_LAN_IP:8000"
export WEALL_VALIDATOR_ACCOUNT="@promoted-account"
export WEALL_NODE_PUBKEY="<registered node public key>"
bash scripts/promoted_validator_live_gate.sh
```

This gate checks:

- local chain identity matches genesis chain identity;
- local validator authority is effective;
- local signing is enabled and allowed by consensus state;
- local consensus status reports the node as an active validator;
- active validator count satisfies the production BFT minimum unless an explicit bootstrap/readiness override is set;
- peer diagnostics show an established/identity-verified consensus peer when peer diagnostics are available;
- operator-status reports active baseline node-operator and validator responsibility.

## Full observer-to-validator gate

After the observer live gate and the required protocol authority transitions have happened, run:

```bash
bash scripts/external_observer_to_validator_live_gate.sh public-observer-bundle.json
```

This script does not create system/governance authority by itself. It fails closed until the required protocol transitions are already committed.

## What each gate proves

| Gate | Proves | Does not prove |
|---|---|---|
| `external_observer_onboarding_smoke.sh` | Public bundle and observer posture are safe. | Signed onboarding or validator readiness. |
| `rehearse_external_observer_two_machine.sh` | Remote genesis API and identity are reachable. | Signed onboarding or authority promotion. |
| `external_observer_live_gate.sh` | Signed account/device/peer/PoH case onboarding txs commit. | Tier 1/Tier 2 finalization, node-operator activation, validator authority. |
| `promoted_validator_preflight.sh` | Protocol state says the account/node is validator-ready before reboot and validator count/hash are present. | Local validator process has joined consensus or full BFT finality below `BFT_MIN_VALIDATORS`. |
| `reboot_promoted_observer_as_validator.sh` | Boots only after fail-closed preflight. | Post-boot consensus acceptance by peers. |
| `promoted_validator_live_gate.sh` | Local validator process reports active/effective authority, matches genesis identity, and satisfies validator-count/peer-diagnostic checks when exposed. | Long-duration liveness under partitions or full BFT safety below `BFT_MIN_VALIDATORS`. |
