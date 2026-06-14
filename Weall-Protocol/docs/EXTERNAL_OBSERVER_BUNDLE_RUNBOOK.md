# External Observer Bundle Runbook

This runbook describes the external observer posture that Batch 615 expects release reviewers to preserve. An observer bundle must let a new participant read the chain and submit user transactions through an authorized upstream without receiving validator authority, validator secrets, or production signing permission.

## Required observer properties

An external observer node must boot with:

- `WEALL_MODE=prod`
- `WEALL_OBSERVER_MODE=1`
- `WEALL_VALIDATOR_SIGNING_ENABLED=0`
- `WEALL_NODE_LIFECYCLE_STATE=observer_onboarding`
- a required chain manifest path;
- trusted chain/state sync anchors;
- no bundled validator private keys;
- no bundled Genesis/bootstrap authority secrets;
- user write traffic routed through the signed transaction path or an explicitly trusted upstream.

The observer must be able to read public chain state, account state, PoH state, role state, peer status, and tx status. It must not be able to propose blocks, attest blocks, or sign as a validator unless the account and node later complete the on-chain validator responsibility path and production preflight.

## Minimum external test

1. Clone or unpack the observer bundle on a clean machine.
2. Install dependencies from the checked-in requirements files.
3. Start the observer using the observer/onboarding boot script.
4. Confirm `/v1/status` and `/v1/readyz` report observer posture.
5. Confirm validator signing is disabled.
6. Confirm public reads succeed.
7. Submit a normal user transaction through `/v1/tx/submit` or the configured upstream route.
8. Confirm the tx reaches the upstream node, appears in block inclusion, and is removed from the observer mempool after commit/sync.
9. Restart the observer.
10. Confirm chain identity, height, block root, state root, and mempool status remain consistent.

## Promotion boundary

Promotion from observer to validator is not a local config flip. The user and node must complete the chain-backed lifecycle:

1. account identity exists;
2. PoH tier is sufficient;
3. node device is registered;
4. node operator is enrolled and activated;
5. validator responsibility is explicitly opted into;
6. readiness proof is verified;
7. one-node-per-user and reputation gates pass;
8. validator candidate or activation state is committed;
9. BFT key and node key are bound to the active validator account;
10. production preflight passes before validator signing starts.

The Batch 615 local rehearsal proves this boundary in deterministic local form. External observer releases must still include separate multi-machine evidence before public beta claims.
