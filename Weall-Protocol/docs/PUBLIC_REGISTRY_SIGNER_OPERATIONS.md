# Public Registry Signer Operations

This runbook governs the signer used for `configs/public_testnet_seed_registry.json` in an open-download public observer testnet.

The registry signer is a discovery trust root only. It does **not** grant validator authority, Tier 2 status, governance authority, storage-provider authority, juror authority, helper authority, or economic activation. Validator authority remains committed protocol state plus runtime signing gates.

## Launch policy

Before a public observer launch claim, operators must publish a real signed registry and a pinned registry public key:

```bash
export WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PUBKEY=<published-registry-public-key>
export WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PRIVKEY=<offline-private-key-only-for-signing-command>

PYTHONPATH=src:scripts python scripts/sign_public_seed_registry_v1_5.py \
  --input /secure/operator/unsigned-public-registry.json \
  --output configs/public_testnet_seed_registry.json \
  --registry-public-key "$WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PUBKEY"

PYTHONPATH=src WEALL_PUBLIC_TESTNET=1 \
  WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PUBKEY="$WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PUBKEY" \
  python scripts/sign_public_seed_registry_v1_5.py \
  --input /secure/operator/unsigned-public-registry.json \
  --output configs/public_testnet_seed_registry.json \
  --registry-public-key "$WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PUBKEY" \
  --check
```

Do not commit or publish:

- registry private keys
- validator endpoint private keys
- endpoint-key-map files
- one-off operator signing shells containing secrets

## Required registry values

A launch registry must contain real, non-placeholder values for:

- `network_id`
- `chain_id`
- `genesis_hash`
- `protocol_profile_hash`
- `tx_index_hash`
- `seed_api_urls`
- `seed_p2p_urls`
- `seed_registry_signer`
- `seed_registry_signature`
- signed `validator_endpoints` when validators are public connection targets

The runtime rejects placeholder strings such as `<set-before-public-launch>`, `.example` hosts, and unsigned production launch tokens.

## Rotation policy

Use overlap rotation:

1. Generate a new offline registry signing key.
2. Add the new public key to the published pin set with the old key still accepted.
3. Publish a registry signed by the new key.
4. Run a fresh public observer launch transcript against the new signed registry.
5. Remove the old public key from the pin set after observers have had a transition window.
6. Regenerate launch evidence artifacts and release manifest.

## Emergency revocation

If the registry signing key may be compromised:

1. Stop public launch claims immediately.
2. Remove the compromised public key from the accepted pin set.
3. Generate a new offline key.
4. Publish a new registry signed by the new key.
5. Re-run the public observer launch transcript and state-sync proof.
6. Publish a visible advisory that seed discovery was rotated.

A compromised registry signer can cause network eclipse or denial of service by pointing observers at malicious or blackhole endpoints. It still cannot create validator authority because validator status comes from protocol state and signing gates.

## Evidence command

```bash
PYTHONPATH=src:scripts python scripts/gen_public_registry_signer_operations_v1_5.py --check
```
