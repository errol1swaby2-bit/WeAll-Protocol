# Operator Promotion State Machine

WeAll is a pre-public-testnet protocol implementation under active hardening.

This document defines the canonical, fail-closed ladder from a Tier 2 observer account to baseline production service mode and, later, a promoted validator reboot. The ladder is intentionally not a shortcut from Tier 2 to validator authority.

## A. Account readiness

Required state:

- account exists;
- account key is ready in the browser/operator client;
- account session is active for owner-authenticated actions;
- account has Tier 2 / Trusted Verified Person status;
- account is unrestricted: not banned and not locked.

Tier 2 is only account readiness. It does not grant node-operator, validator, storage, or consensus authority.

## B. Node key readiness

Required state:

- a separate node key is generated locally;
- the node key file is downloaded and secured by the operator;
- the node public key is visible to the operator;
- the account recovery key is not reused as the node key.

The account key signs account-authority transactions. The node key identifies the node service. These are separate authority surfaces.

## C. Node device registration

Required transaction:

```text
ACCOUNT_DEVICE_REGISTER
```

Required payload properties:

- `device_type = node`;
- deterministic `device_id`, normally `node:@observer` for the observer account flow;
- `pubkey` equals the generated node public key.

Owner-authenticated account views may show enough device state to confirm the node device. Public-redacted account views must not leak private device state.

## D. Baseline node-operator enrollment

Required transaction:

```text
ROLE_NODE_OPERATOR_ENROLL
```

Authority:

- signed by the account key;
- binds to the intended account and, where supplied, the registered node key/device.

State transition:

- `not_opted_in` / `not_enrolled` moves to `eligible` or `active` only after registered node key, Tier 2 status, and unrestricted account state are proven;
- `ROLE_NODE_OPERATOR_ACTIVATE` remains a separate deterministic system/governance activation transaction.

## E. Validator responsibility opt-in

Required transaction:

```text
NODE_OPERATOR_VALIDATOR_OPT_IN
```

Authority and payload:

- signed by the account key;
- includes `account_id` and `node_pubkey`;
- uses the same canonical `pq-mldsa-v1` account signing path as `ACCOUNT_DEVICE_REGISTER` and `ACCOUNT_SESSION_KEY_ISSUE`;
- does not use a verifier fallback, alternate primitive context, session-key signature, or node-key signature.

Accepted opt-in is not validator authority. If the signature and canonical payload are valid but readiness or reputation is insufficient, the chain records opt-in and reports explicit blockers such as `validator_readiness_pending` or `validator_reputation_insufficient`. It must not surface this as `bad_sig`.

Validator authority requires readiness verification, reputation threshold satisfaction, and a canonical activation such as `ROLE_VALIDATOR_ACTIVATE` for the matching registered node key.

## F. Storage responsibility opt-in

Required transaction:

```text
NODE_OPERATOR_STORAGE_OPT_IN
```

Authority and payload:

- signed by the account key;
- includes `account_id`, `node_pubkey`, `storage_opt_in`, `declared_capacity_bytes`, and optional `storage_endpoint_commitment`.

Accepted opt-in is not storage allocation authority. Capacity proof/probe remains separate. Storage allocation remains blocked until protocol capacity proof verification succeeds.

## G. Production service reboot

Required script:

```bash
scripts/boot_node_operator.sh
```

Required environment:

- `WEALL_BOUND_ACCOUNT=@observer` or the exact account being checked;
- `WEALL_NODE_PRIVKEY_FILE` points to the downloaded separate node key file;
- `WEALL_API_BASE` or `WEALL_GENESIS_API_BASE` points to a chain API that can serve `GET /v1/accounts/{account}/operator-promotion-status`;
- the chain status proves baseline node-operator authority is active for the registered node public key.

Production service reboot allows baseline node-operator service only. It does not imply validator authority and must leave validator signing/BFT disabled.

## H. Promoted validator reboot

Required scripts:

```bash
scripts/promoted_validator_preflight.sh
scripts/reboot_promoted_observer_as_validator.sh
scripts/promoted_validator_live_gate.sh
```

Required state:

- baseline node operator active;
- validator opt-in recorded;
- validator readiness verified;
- reputation threshold satisfied, or the explicit blocker is reported;
- `ROLE_VALIDATOR_ACTIVATE` or equivalent canonical validator authority present;
- active validator authority bound to the same registered node key.

The reboot must fail closed otherwise. A genesis plus one promoted validator rehearsal is a bootstrap/readiness proof, not public multi-validator BFT readiness, unless the active validator count satisfies the production BFT minimum.

## Single status surface

The canonical API surface for scripts and frontend is:

```text
GET /v1/accounts/{account}/operator-promotion-status
```

It reports the ladder fields used by the UI and reboot scripts, including account tier, node registration, enrollment/activation, validator/storage opt-ins, blocker states, `service_reboot_allowed`, `validator_reboot_allowed`, `next_step`, and `blocking_reasons`.
