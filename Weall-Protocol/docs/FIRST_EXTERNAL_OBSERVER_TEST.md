# First Trusted External Observer Test

This runbook is the production-style gate before inviting even one trusted external observer-node tester.
It proves that an observer on a different machine/network can use only a public onboarding bundle and a remote genesis API to submit signed onboarding transactions while remaining non-authoritative.

## Hard rule

This is a **NO-GO** unless every command in this document passes against a non-local genesis API.
Do not use `localhost`, `127.0.0.1`, IPv6 loopback, unspecified/link-local addresses, metadata-service addresses, genesis private keys, validator keys, Cloudflare credentials, SMTP credentials, DNS credentials, OAuth, CAPTCHA, KYC, or any external identity-provider authority. Private LAN genesis API addresses are allowed only for a controlled home/LAN two-machine test with `WEALL_ALLOW_PRIVATE_GENESIS_API=1`; public-trust testing should use a real non-local public URL.

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

The script intentionally rejects local/self API bases such as `http://127.0.0.1`, `http://localhost`, IPv6 loopback, unspecified/link-local addresses, and metadata-service addresses. For a same-LAN two-machine rehearsal only, set `WEALL_ALLOW_PRIVATE_GENESIS_API=1`; do not use that override for a public external observer proof.

## Expected result

A passing run ends with:

```text
OK: trusted external observer live gate passed
```

By default, the script deletes the temporary work directory after a passing run because it contains private key material. To retain the artifacts for debugging or private operator archival, set `WEALL_EXTERNAL_OBSERVER_KEEP_WORK_DIR=1` before running the gate. If retained, the work directory contains:

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

A single trusted external observer-node tester is a **CONDITIONAL GO** only after this live gate passes and the resulting transaction statuses are archived privately by the operator.
Multiple observer testers remain a **NO-GO** until one tester completes this gate and relay/rate-limit capacity checks are repeated under load.
