# First Controlled External Observer Test

Legacy contract alias: **Trusted External Observer**. This runbook keeps the historical trusted-observer gate name for release-test compatibility while treating the current public testnet path as open observer access through signed registry discovery.

This runbook is the production-style gate before inviting even one controlled external observer-node tester.
It proves that an observer on a different machine/network can use only a public onboarding bundle and a remote genesis API to submit signed onboarding transactions while remaining non-authoritative.

## Hard rule

This is a **NO-GO** unless every command in this document passes against a non-local genesis API.
Do not use `localhost`, `127.0.0.1`, IPv6 loopback, unspecified/link-local addresses, metadata-service addresses, genesis private keys, validator keys, named hosting-provider credentials, SMTP credentials, DNS credentials, OAuth, CAPTCHA, KYC, or any external identity-provider authority. LAN genesis API addresses are allowed only for a controlled home/LAN two-machine test with `WEALL_ALLOW_LAN_GENESIS_API=1`; public-trust testing should use a real non-local public URL.

## What this proves

The live gate performs the following actions from the observer machine:

Important boundary: this gate proves async PoH **case creation and evidence binding only**. It does not prove Tier 1 finalization, Tier 2/live verification, node-operator activation, validator readiness, validator-set inclusion, or BFT participation.


1. Verifies the public observer bundle against the production chain manifest.
2. Fetches remote `/v1/health`, `/v1/ready` or `/v1/readyz`, `/v1/status`, `/v1/chain/identity`, and `/v1/tx/status/:tx_id`.
3. Forces observer-only local posture:
   - `WEALL_OBSERVER_MODE=1`
   - `WEALL_VALIDATOR_SIGNING_ENABLED=0`
   - `WEALL_BFT_ENABLED=0`
   - `WEALL_HELPER_MODE_ENABLED=0`
   - `WEALL_BLOCK_LOOP_AUTOSTART=0`
4. Generates a fresh observer account key locally.
5. Generates a separate fresh observer node identity key locally.
6. Submits and waits for committed receipts/status for:
   - `ACCOUNT_REGISTER`
   - `ACCOUNT_DEVICE_REGISTER` for node-key binding
   - `PEER_ADVERTISE`
   - `PEER_REQUEST_CONNECT`
   - `POH_ASYNC_REQUEST_OPEN`
   - `POH_ASYNC_EVIDENCE_DECLARE`
   - `POH_ASYNC_EVIDENCE_BIND`
7. Checks the async PoH case is visible after commit.
8. Checks the observer account did not become a validator, BFT signer, node operator, helper, storage provider, juror, governance executor, or treasury authority.

## Genesis operator: build the public observer bundle

Run this on the genesis/operator machine after production manifest checks pass:

```bash
cd ~/WeAll-Protocol/Weall-Protocol

python3 scripts/build_external_observer_bundle.py   --manifest configs/chains/weall-genesis.json   --out /tmp/weall-external-observer-bundle.json   --genesis-api-base "https://<your-public-genesis-api>"

python3 scripts/verify_node_operator_onboarding_bundle.py   --bundle /tmp/weall-external-observer-bundle.json   --manifest configs/chains/weall-genesis.json   --json
```

Send the tester only:

- the public observer bundle;
- the repo commit/archive to test;
- the public genesis API base URL.

Never send anything from `secrets/`, `.env`, validator key files, node private key files, or genesis authority key material.

## Observer tester: run the live gate

Run this on the external observer machine:

```bash
cd ~/WeAll-Protocol/Weall-Protocol

export WEALL_GENESIS_API_BASE="https://<your-public-genesis-api>"
export WEALL_NODE_OPERATOR_ONBOARDING_BUNDLE="/path/to/weall-external-observer-bundle.json"
export WEALL_CHAIN_MANIFEST_PATH="configs/chains/weall-genesis.json"

bash scripts/external_observer_live_gate.sh "$WEALL_NODE_OPERATOR_ONBOARDING_BUNDLE"
```

The script intentionally rejects local/self API bases such as `http://127.0.0.1`, `http://localhost`, IPv6 loopback, unspecified/link-local addresses, and metadata-service addresses. For a same-LAN two-machine rehearsal only, set `WEALL_ALLOW_LAN_GENESIS_API=1`; do not use that override for a public external observer proof.

## Expected result

A passing run ends with:

```text
OK: controlled external observer live gate passed
OK: trusted external observer live gate passed
```

By default, the script deletes the temporary work directory after a passing run because it contains private key material. To retain the artifacts for debugging or operator archival, set `WEALL_EXTERNAL_OBSERVER_KEEP_WORK_DIR=1` before running the gate. If retained, the work directory contains:

- `observer-account.json` — local observer account private key;
- `observer-node-key.json` — separate local node identity private key;
- `live-gate-results.jsonl` — submitted transaction results and receipt/status evidence.

These files are local tester artifacts and must not be committed, uploaded, or sent back publicly.

## Failure meanings

- `remote_chain_id_mismatch`, `remote_tx_index_hash_mismatch`, or `remote_protocol_profile_hash_mismatch`: the observer is not talking to the intended chain/profile.
- `remote_protocol_profile_hash_missing`: the remote genesis API is not exposing the profile commitment needed for observer fail-closed checks.
- `tx not confirmed`: the genesis node accepted or saw the transaction but did not commit it before timeout.
- `observer_account_unexpected_validator_authority`, `observer_account_unexpected_authority:*`, or `observer_account_unexpected_operator_authority:*`: the gate detected an authority leak and the test is failed.
- `async_case_not_visible_after_commit`: the PoH onboarding transaction did not become visible in authoritative state after commit.
- any secret-variable failure: the observer machine has authority or external identity-provider material that must be removed before retrying.

## Go / no-go

A single controlled external observer-node tester is a **CONDITIONAL GO** only after this live gate passes and the resulting transaction statuses are archived privately by the operator.
Multiple observer testers remain a **NO-GO** until one tester completes this gate and relay/rate-limit capacity checks are repeated under load.


## Batch 437-446 external tester gates

Before inviting the first controlled external observer tester, run the explicit authority-lock gate from the observer machine or observer runtime environment:

```bash
WEALL_CHAIN_MANIFEST_PATH=./configs/chains/weall-genesis.json \
WEALL_OBSERVER_MODE=1 \
WEALL_VALIDATOR_SIGNING_ENABLED=0 \
WEALL_BFT_ENABLED=0 \
WEALL_HELPER_MODE_ENABLED=0 \
WEALL_BLOCK_LOOP_AUTOSTART=0 \
bash scripts/external_observer_authority_lock_gate.sh
```

If the observer node is already booted, also pass its API base so the gate checks runtime status surfaces:

```bash
WEALL_API_BASE=https://observer.example.org \
bash scripts/external_observer_authority_lock_gate.sh
```

A successful observer gate proves only this limited claim: the node is in observer posture, validator signing/BFT/helper authority/block-loop autostart are off, and no local validator/service authority role is requested. It does not promote the observer, prove multi-validator BFT, or activate economics.

Transaction results must be read as a lifecycle, not a single success word:

1. local validation accepted,
2. observer tx queue queued,
3. upstream submitted,
4. canonical node confirmed,
5. visible from another healthy compatible node.

Only step 4/5 should be described as committed on the shared test chain.

## Batch 464 Genesis API readiness contract

Before the observer submits signed onboarding transactions, the remote Genesis API must expose the read-only observer-readiness contract:

```bash
curl -fsS "$WEALL_GENESIS_API_BASE/v1/genesis/observer/readiness"
```

The response must report `stage: first_trusted_external_observer_rehearsal`, matching `chain_id`, `tx_index_hash`, and `protocol_profile_hash`, plus an explicit authority boundary showing that the observer receives no validator, BFT, helper, treasury, governance, or external identity-provider authority. This endpoint is a compatibility truth surface only; it does not grant authority and does not prove signed onboarding by itself.

Use the combined gate for the next real proof:

```bash
WEALL_RUN_TWO_MACHINE_OBSERVER_PREFLIGHT=1 \
WEALL_GENESIS_API_BASE="https://<your-public-genesis-api>" \
bash scripts/first_external_observer_reproducibility_gate.sh /path/to/weall-external-observer-bundle.json

WEALL_RUN_TWO_MACHINE_OBSERVER_PREFLIGHT=1 \
WEALL_RUN_SIGNED_OBSERVER_ONBOARDING=1 \
WEALL_GENESIS_API_BASE="https://<your-public-genesis-api>" \
bash scripts/first_external_observer_reproducibility_gate.sh /path/to/weall-external-observer-bundle.json
```

A first controlled external observer remains a no-go until the remote Genesis observer readiness contract, the two-machine preflight, and the signed onboarding gate all pass against the same non-local Genesis API.
