# Trusted External Observer Tester Runbook

> Legacy controlled-observer runbook. For the updated open-download public observer testnet path, use `PUBLIC_OBSERVER_TESTNET_QUICKSTART.md`. This legacy trusted-tester path is not the public launch path and must not be used to imply the testnet is invite-only.

This runbook is for the first controlled external observer-node tester. It is intentionally observer-first: the tester can read/sync state, verify chain identity, submit onboarding transactions, and serve a local onboarding UI, but cannot propose blocks, vote in BFT, sign validator messages, act as a helper authority, or earn service rewards.

## Safety posture

The observer tester must not receive or configure:

- genesis private keys
- validator private keys
- authority signer private keys
- Cloudflare credentials
- SMTP credentials
- email oracle credentials
- OAuth, CAPTCHA, KYC, DNS, or inbox-provider credentials

The only required trust material is the public chain manifest and public onboarding bundle.

## Secret-safe release warning

Never send the tester anything from `secrets/`. The external observer needs the public chain manifest and public onboarding bundle only. If `secrets/weall_node_privkey` or any equivalent private key was ever included in a shared artifact, rotate that key before any real observer test.

Run before packaging or sharing artifacts:

```bash
bash scripts/secret_guard.sh
bash scripts/verify_release_tree.sh
bash scripts/prod_chain_manifest_check.sh
```

## Local gate before a second machine is available

If you cannot perform the real two-machine rehearsal yet, run the local readiness gate first:

```bash
bash scripts/local_observer_readiness_gate.sh
```

This does not replace the two-machine rehearsal. It proves the local prerequisites: the manifest is pinned, the public observer bundle can be generated and verified, observer-only posture is enforced, and no genesis/validator/authority/Cloudflare/SMTP/oracle secret is required by the observer path.

## Founder / genesis operator export

From the genesis/operator machine, create a public onboarding bundle after the production manifest has real pinned values:

```bash
python3 scripts/build_external_observer_bundle.py \
  --manifest configs/chains/weall-genesis.json \
  --out /tmp/weall-external-observer-bundle.json \
  --authority-url https://<genesis-authority-host> \
  --genesis-api-base https://<genesis-api-host> \
  --relay-urls https://<relay-host> \
  --genesis-recipient-pubkey <64_HEX_GENESIS_NODE_PUBLIC_KEY>
```

Verify before sending:

```bash
python3 scripts/verify_node_operator_onboarding_bundle.py \
  --bundle /tmp/weall-external-observer-bundle.json \
  --manifest configs/chains/weall-genesis.json \
  --json
```

The verifier must return `ok: true`. Do not send a bundle that contains placeholder trusted authority pubkeys or an empty protocol profile hash.

## Observer-machine preflight

On the external machine:

```bash
export WEALL_NODE_OPERATOR_ONBOARDING_BUNDLE=/path/to/weall-external-observer-bundle.json
export WEALL_CHAIN_MANIFEST_PATH=/path/to/weall-genesis.json
export WEALL_GENESIS_API_BASE=https://<genesis-api-host>

export WEALL_EXTERNAL_OBSERVER_REQUIRE_LIVE_API=1

bash scripts/external_observer_onboarding_smoke.sh "$WEALL_NODE_OPERATOR_ONBOARDING_BUNDLE"
```

For the final two-machine rehearsal before inviting the tester, use the stricter remote-only wrapper:

```bash
export WEALL_NODE_OPERATOR_ONBOARDING_BUNDLE=/path/to/weall-external-observer-bundle.json
export WEALL_CHAIN_MANIFEST_PATH=/path/to/weall-genesis.json
export WEALL_GENESIS_API_BASE=https://<genesis-api-host>
export WEALL_NET_RELAY_URLS=https://<relay-host>   # optional, comma-separated when present
export WEALL_NET_RELAY_RECIPIENT_PUBKEYS='{"genesis":"<64_HEX_GENESIS_NODE_PUBLIC_KEY>"}'

bash scripts/rehearse_external_observer_two_machine.sh "$WEALL_NODE_OPERATOR_ONBOARDING_BUNDLE"
bash scripts/external_observer_live_gate.sh "$WEALL_NODE_OPERATOR_ONBOARDING_BUNDLE"
```

The rehearsal wrapper refuses local/self genesis URLs, forces observer-only posture, checks `/v1/health`, `/v1/ready`, `/v1/chain/identity`, and verifies every configured relay reports `transport_only`. This rehearsal is connectivity/preflight only; it does not submit signed onboarding transactions.

This smoke path verifies:

- the bundle matches the local manifest
- the manifest is pinned and non-placeholder
- the remote genesis live API is reachable when `WEALL_EXTERNAL_OBSERVER_REQUIRE_LIVE_API=1` is set
- `/v1/health`, `/v1/status`, `/v1/ready` or `/v1/readyz`, `/v1/chain/identity`, and `/v1/tx/status/:tx_id` respond with the expected contract shape
- the remote genesis chain identity matches the bundle when `WEALL_GENESIS_API_BASE` is provided
- relay recipient public-key binding is present whenever relay URLs are configured
- observer mode is forced on
- validator signing is forced off
- BFT is forced off
- helper authority is forced off
- no external identity-provider credentials are required

## Observer boot

After the smoke check passes and before treating the observer as proven, run the signed live gate:

```bash
WEALL_NODE_OPERATOR_ONBOARDING_BUNDLE=/path/to/weall-external-observer-bundle.json \
WEALL_CHAIN_MANIFEST_PATH=/path/to/weall-genesis.json \
WEALL_GENESIS_API_BASE=https://<genesis-api-host> \
bash scripts/external_observer_live_gate.sh "$WEALL_NODE_OPERATOR_ONBOARDING_BUNDLE"
```

After the smoke check passes and the operator needs to start a local onboarding UI:

```bash
WEALL_NODE_OPERATOR_ONBOARDING_BUNDLE=/path/to/weall-external-observer-bundle.json \
WEALL_CHAIN_MANIFEST_PATH=/path/to/weall-genesis.json \
bash scripts/boot_onboarding_node.sh
```

The boot wrapper must report:

- allowed: read/sync state, serve local onboarding UI, submit account/PoH/enrollment transactions
- blocked: validator signing, block proposal, helper authority, storage/service rewards

## Allowed observer onboarding transactions

The tester may submit normal signed user transactions to the genesis API through public transaction submission only. The intended first-path transactions are:

1. `ACCOUNT_REGISTER`
2. `ACCOUNT_DEVICE_REGISTER` or account-key registration for the local node key
3. `PEER_ADVERTISE`
4. `PEER_REQUEST_CONNECT`
5. `PEER_RENDEZVOUS_TICKET_CREATE` if outbound-only rendezvous is needed
6. `POH_ASYNC_REQUEST_OPEN`
7. `POH_ASYNC_EVIDENCE_DECLARE`
8. `POH_ASYNC_EVIDENCE_BIND`
9. later, `POH_LIVE_REQUEST_OPEN` once Tier 1 is granted
10. later, `ROLE_NODE_OPERATOR_ENROLL` once Tier 2 and role requirements are satisfied

The tester must not call demo seed routes, local state mutation routes, or operator-only mutation routes.

## Success criteria for one trusted tester

The test is successful only if:

- the observer verifies chain identity and tx-index hash before boot
- the observer remains in observer mode after boot
- validator signing remains disabled
- BFT remains disabled
- the observer submits signed onboarding txs to the genesis node
- the genesis node includes the txs through normal mempool/block flow
- receipts and committed state become visible to the observer
- no email, Cloudflare, SMTP, DNS, OAuth, CAPTCHA, KYC, or inbox-provider authority is required

## Hard stop conditions

Stop the external test if any of these occur:

- manifest check fails
- bundle check fails
- relay URLs are configured without `WEALL_NET_RELAY_RECIPIENT_PUBKEYS`
- placeholder authority key is present
- protocol profile hash is empty
- observer boot enables validator signing
- observer boot enables BFT
- observer receives or asks for genesis/private authority secrets
- onboarding requires email, Cloudflare, SMTP, DNS, OAuth, CAPTCHA, or KYC
- the frontend/API shows success before a committed receipt or visible state reconciliation

## Batch 337 live-gate command sequence

Use this exact gate before inviting the first trusted external observer:

```bash
python3 -S scripts/check_tx_canon_artifacts.py
bash scripts/secret_guard.sh
bash scripts/verify_release_tree.sh
bash scripts/verify_release_dependencies.sh
bash scripts/prod_chain_manifest_check.sh configs/chains/weall-genesis.json

export WEALL_NODE_OPERATOR_ONBOARDING_BUNDLE=/path/to/weall-external-observer-bundle.json
export WEALL_CHAIN_MANIFEST_PATH=/path/to/weall-genesis.json
export WEALL_GENESIS_API_BASE=https://<genesis-api-host>
export WEALL_EXTERNAL_OBSERVER_REQUIRE_LIVE_API=1

bash scripts/external_observer_onboarding_smoke.sh "$WEALL_NODE_OPERATOR_ONBOARDING_BUNDLE"
bash scripts/rehearse_external_observer_two_machine.sh "$WEALL_NODE_OPERATOR_ONBOARDING_BUNDLE"
bash scripts/external_observer_live_gate.sh "$WEALL_NODE_OPERATOR_ONBOARDING_BUNDLE"

cd ../web
API_BASE="$WEALL_GENESIS_API_BASE" npm run contract-check
npm run production-safety-check
```

The first trusted observer is a no-go unless every command above passes, the live gate confirms the signed account/device/peer/async-PoH-case onboarding sequence, and the observer remains unable to sign validator blocks. This does not prove Tier 1 finalization, Tier 2/live verification, node-operator activation, validator readiness, or BFT participation.

## Batch 464: Production-oriented Genesis API check

The tester must verify the remote Genesis observer readiness contract before running signed onboarding:

```bash
curl -fsS "$WEALL_GENESIS_API_BASE/v1/genesis/observer/readiness"
```

Expected properties:

- `stage` is `first_trusted_external_observer_rehearsal`;
- `compatibility.chain_id`, `compatibility.tx_index_hash`, and `compatibility.protocol_profile_hash` match the public observer bundle;
- `observer_authority_boundary.observer_receives_validator_authority` is `false`;
- `observer_authority_boundary.requires_genesis_or_validator_private_keys` is `false`;
- `observer_authority_boundary.requires_external_identity_provider` is `false`;
- `public_tx_ingress.signed_user_tx_submit_enabled` is `true`;
- `public_tx_ingress.system_signer_rejected_from_public_ingress` and `system_flag_rejected_from_public_ingress` are `true`.

The preferred command path is now the combined external-observer gate:

```bash
WEALL_RUN_TWO_MACHINE_OBSERVER_PREFLIGHT=1 \
WEALL_GENESIS_API_BASE=https://<genesis-api-host> \
bash scripts/first_external_observer_reproducibility_gate.sh "$WEALL_NODE_OPERATOR_ONBOARDING_BUNDLE"

WEALL_RUN_TWO_MACHINE_OBSERVER_PREFLIGHT=1 \
WEALL_RUN_SIGNED_OBSERVER_ONBOARDING=1 \
WEALL_GENESIS_API_BASE=https://<genesis-api-host> \
bash scripts/first_external_observer_reproducibility_gate.sh "$WEALL_NODE_OPERATOR_ONBOARDING_BUNDLE"
```

Passing the Genesis observer readiness endpoint is necessary but not sufficient. Signed onboarding is proven only when the second command submits and confirms the account/device/peer/async-PoH transactions and then verifies that the observer account has no validator, BFT, helper, treasury, governance, storage-provider, or juror authority.
