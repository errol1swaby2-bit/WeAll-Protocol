# Trusted External Observer Tester Runbook

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

## Founder / genesis operator export

From the genesis/operator machine, create a public onboarding bundle after the production manifest has real pinned values:

```bash
python3 scripts/build_node_operator_onboarding_bundle.py \
  --manifest configs/chains/weall-genesis.json \
  --out /tmp/weall-external-observer-bundle.json \
  --profile production \
  --authority-profile production \
  --authority-url https://<genesis-authority-host>
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

bash scripts/external_observer_onboarding_smoke.sh "$WEALL_NODE_OPERATOR_ONBOARDING_BUNDLE"
```

For the final two-machine rehearsal before inviting the tester, use the stricter remote-only wrapper:

```bash
export WEALL_NODE_OPERATOR_ONBOARDING_BUNDLE=/path/to/weall-external-observer-bundle.json
export WEALL_CHAIN_MANIFEST_PATH=/path/to/weall-genesis.json
export WEALL_GENESIS_API_BASE=https://<genesis-api-host>
export WEALL_NET_RELAY_URLS=https://<relay-host>   # optional, comma-separated when present

bash scripts/rehearse_external_observer_two_machine.sh "$WEALL_NODE_OPERATOR_ONBOARDING_BUNDLE"
```

The rehearsal wrapper refuses localhost genesis URLs, forces observer-only posture, checks `/v1/health`, `/v1/ready`, `/v1/chain/identity`, and verifies every configured relay reports `transport_only`.

This smoke path verifies:

- the bundle matches the local manifest
- the manifest is pinned and non-placeholder
- the remote genesis chain identity matches the bundle when `WEALL_GENESIS_API_BASE` is provided
- observer mode is forced on
- validator signing is forced off
- BFT is forced off
- helper authority is forced off
- no external identity-provider credentials are required

## Observer boot

After the smoke check passes:

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
- placeholder authority key is present
- protocol profile hash is empty
- observer boot enables validator signing
- observer boot enables BFT
- observer receives or asks for genesis/private authority secrets
- onboarding requires email, Cloudflare, SMTP, DNS, OAuth, CAPTCHA, or KYC
- the frontend/API shows success before a committed receipt or visible state reconciliation
