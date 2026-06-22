# External Observer Node Rehearsal

This runbook is the connectivity/preflight gate before the signed live gate.
It rehearses the production journey from one genesis/bootstrap node to an
outbound-only observer node on another machine or network, but it is not the
complete signed onboarding E2E by itself. The observer onboarding E2E is complete
only after `scripts/external_observer_live_gate.sh` passes.

The observer is useful but non-authoritative:

- it can verify chain identity, tx canon identity, and protocol-profile identity
- it can submit signed onboarding transactions to the genesis API
- it can advertise a peer record and request connection
- it can open native async Proof-of-Humanity onboarding
- it cannot propose blocks
- it cannot sign validator messages
- it cannot enable BFT signing
- it cannot receive genesis, validator, or authority private keys
- relay/rendezvous is transport only and is not consensus authority

No email, SMTP, DNS, OAuth, CAPTCHA, KYC, or named hosting-provider dependency, inbox provider, or external
identity provider is required for observer onboarding.

## Machine A — Genesis/bootstrap node

1. Generate real production public keys outside the repository. Keep private keys
   outside git and outside the observer bundle.

2. Build the pinned production genesis ledger and chain manifest:

```bash
python3 scripts/build_production_genesis_manifest.py \
  --chain-id weall-prod \
  --founding-account '<FOUNDING_ACCOUNT_ID>' \
  --founding-pubkey '<64_HEX_FOUNDING_PUBLIC_KEY>' \
  --authority-pubkey '<64_HEX_AUTHORITY_PUBLIC_KEY>' \
  --genesis-time "$(date +%s)" \
  --genesis-out configs/genesis.ledger.prod.json \
  --manifest-out configs/chains/weall-genesis.json
```

3. Verify the manifest is pinned and non-placeholder:

```bash
bash scripts/prod_chain_manifest_check.sh configs/chains/weall-genesis.json
```

4. Build the public observer bundle:

```bash
python3 scripts/build_external_observer_bundle.py \
  --manifest configs/chains/weall-genesis.json \
  --genesis-api-base 'https://<GENESIS_HOST>' \
  --relay-urls 'https://<RELAY_HOST>' \
  --genesis-recipient-pubkey '<64_HEX_GENESIS_NODE_PUBLIC_KEY>' \
  --out dist/weall-external-observer-bundle.json
```

The bundle is public. It must contain no private keys and no authority-signer
secrets, and its `protocol_profile_hash` must match the pinned chain manifest.
If relay URLs are present, it must also contain
`observer.relay_recipient_pubkeys` so relay delivery is bound to the genesis
node public key.

5. Verify the bundle:

```bash
python3 scripts/verify_node_operator_onboarding_bundle.py \
  --bundle dist/weall-external-observer-bundle.json \
  --manifest configs/chains/weall-genesis.json \
  --json
```

6. Start the genesis node using the production manifest and ledger according to
   `docs/production_node_bootstrap.md` and `docs/operator_runbook_prod.md`.

## Machine B — External observer node

1. Clone the repository and install locked dependencies.

2. Copy only the public observer bundle and public chain manifest onto the
   observer machine:

```text
configs/chains/weall-genesis.json
dist/weall-external-observer-bundle.json
```

Do not copy founding private keys, validator private keys, authority private
keys, `.env` files, runtime databases, or local genesis-node data.

3. Run observer preflight:

```bash
WEALL_NODE_OPERATOR_ONBOARDING_BUNDLE='dist/weall-external-observer-bundle.json' \
WEALL_CHAIN_MANIFEST_PATH='configs/chains/weall-genesis.json' \
bash scripts/external_observer_onboarding_smoke.sh 'dist/weall-external-observer-bundle.json'
```

Expected posture after preflight:

```text
WEALL_NODE_LIFECYCLE_STATE=observer_onboarding
WEALL_OBSERVER_MODE=1
WEALL_VALIDATOR_SIGNING_ENABLED=0
WEALL_BFT_ENABLED=0
WEALL_HELPER_MODE_ENABLED=0
WEALL_BLOCK_LOOP_AUTOSTART=0
```

4. Boot the onboarding/observer node:

```bash
WEALL_NODE_OPERATOR_ONBOARDING_BUNDLE='dist/weall-external-observer-bundle.json' \
WEALL_CHAIN_MANIFEST_PATH='configs/chains/weall-genesis.json' \
bash scripts/boot_onboarding_node.sh
```

5. Run the signed live gate. This submits onboarding transactions to the genesis
   API through normal signed user transaction flow:

```bash
WEALL_NODE_OPERATOR_ONBOARDING_BUNDLE='dist/weall-external-observer-bundle.json' \
WEALL_CHAIN_MANIFEST_PATH='configs/chains/weall-genesis.json' \
WEALL_GENESIS_API_BASE='https://<GENESIS_HOST>' \
bash scripts/external_observer_live_gate.sh 'dist/weall-external-observer-bundle.json'
```

The initial observer path should include:

```text
ACCOUNT_REGISTER
PEER_ADVERTISE
PEER_REQUEST_CONNECT
POH_ASYNC_REQUEST_OPEN
POH_ASYNC_EVIDENCE_DECLARE
POH_ASYNC_EVIDENCE_BIND
```

6. Confirm results from the genesis API:

- submitted transactions become committed receipts
- observer account appears in finalized state
- peer advertisement appears in peer state
- async PoH case appears in PoH state
- observer remains unable to produce blocks or sign validator artifacts

## Failure rules

Stop the rehearsal if any of these occur:

- chain ID mismatch
- tx index hash mismatch
- protocol profile hash mismatch
- genesis hash/state root mismatch
- observer can produce a local block
- observer can sign validator messages
- relay reports authority other than `transport_only`
- relay URLs are configured without recipient public-key binding
- relay reports `allow_unbound_recipient_fetch=true` or `require_recipient_pubkey=false`
- bundle contains private key, secret, token, or credential-like fields
- external identity provider credentials are required

## Promotion gate

Only after this runbook and `scripts/external_observer_live_gate.sh` pass should
one trusted external observer tester be treated as proven. Multiple observers,
validator candidates, governance writes, and WeCoin/economics remain separate
gates.

## Batch 464 Genesis API compatibility surface

The remote Genesis API must expose the observer-readiness contract before the two-machine rehearsal is considered valid:

```bash
curl -fsS "$WEALL_GENESIS_API_BASE/v1/genesis/observer/readiness"
```

This read-only surface lets the observer fail closed before trusting a remote API. It must expose the chain/profile commitments, the expected public transaction submission/status endpoints, and the authority boundary proving that observer onboarding does not require genesis secrets, validator keys, BFT signing, helper authority, external identity providers, or frontend-granted authority.

The rehearsal command sequence should use the combined gate:

```bash
WEALL_RUN_TWO_MACHINE_OBSERVER_PREFLIGHT=1 \
WEALL_GENESIS_API_BASE='https://<GENESIS_HOST>' \
bash scripts/first_external_observer_reproducibility_gate.sh 'dist/weall-external-observer-bundle.json'

WEALL_RUN_TWO_MACHINE_OBSERVER_PREFLIGHT=1 \
WEALL_RUN_SIGNED_OBSERVER_ONBOARDING=1 \
WEALL_GENESIS_API_BASE='https://<GENESIS_HOST>' \
bash scripts/first_external_observer_reproducibility_gate.sh 'dist/weall-external-observer-bundle.json'
```

A successful remote Genesis observer readiness check proves compatibility only. A successful signed onboarding gate is still required before claiming the first trusted external observer path has been proven.
