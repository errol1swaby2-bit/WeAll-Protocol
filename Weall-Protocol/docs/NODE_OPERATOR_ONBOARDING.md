# WeAll Node Operator Onboarding

This document describes the normal production-oriented onboarding flow for a new WeAll node operator.

A normal node operator verifies chain state and public oracle anchors. A normal node operator does **not** need mail-transport credentials, oracle signing keys, external provider API tokens, or authority snapshot signer private keys.

## Roles

| Role | Holds | Does not hold |
|---|---|---|
| Normal node operator | Their own node/account signing key and public chain/oracle anchors | SMTP credentials, PoH oracle signing key, authority signer private keys |
| Validator / consensus participant | Validator/node key material and finalized chain state | Email transport credentials or oracle private keys |
| PoH email oracle operator | WeAll-hosted PoH email oracle config, SMTP/Stalwart credentials, registered oracle signing key | Normal node private keys owned by other operators |
| Authority snapshot signer | Authority snapshot signing key, when this deployment profile uses signed authority snapshots | SMTP credentials, normal node keys |

## Public onboarding bundle

A public onboarding bundle gives the operator the chain and oracle anchors needed to verify they are connecting to the correct network and public PoH oracle profile.

It contains public values only:

- chain id
- genesis hash
- genesis state root
- tx index hash
- PoH oracle URL, when the deployment publishes one
- chain authority URL
- trusted authority snapshot signer public keys

It must not contain private key material.

## Install the public anchors

```bash
cd ~/WeAll-Protocol/Weall-Protocol

python3 scripts/verify_node_operator_onboarding_bundle.py \
  --bundle node-operator-onboarding-bundle.json \
  --manifest configs/chains/weall-genesis.json \
  --json

python3 scripts/install_node_operator_onboarding_bundle.py \
  --bundle node-operator-onboarding-bundle.json \
  --manifest configs/chains/weall-genesis.json \
  --out .weall-node-operator.env

source .weall-node-operator.env
```

The generated `.weall-node-operator.env` file is local shell configuration. It contains public anchors only.

## Configure local node identity separately

After the public anchors are installed, configure the operator's local node/account identity through the node's normal key-management process.

The operator must eventually provide:

```text
WEALL_ORACLE_OPERATOR_ACCOUNT
WEALL_NODE_PUBKEY
WEALL_NODE_PRIVKEY_FILE or equivalent local signer configuration
```

Do not put PoH email oracle signing keys, SMTP passwords, authority signer keys, or unrelated provider credentials in the normal node operator environment.

## Run preflight

```bash
bash scripts/prod_node_operator_from_bundle_preflight.sh node-operator-onboarding-bundle.json
```

This checks:

- bundle matches the local production chain manifest;
- public chain/oracle anchors are exported;
- oracle-service and authority-signer secrets are absent from the normal node environment;
- optional live authority/key checks if node account/key variables are configured.

## Email oracle use

A normal node operator does not send verification email. It verifies chain state and submits normal signed transactions. A PoH email oracle operator runs the separate WeAll-hosted oracle service and its selected mail transport, such as Stalwart SMTP.

The default PoH email path is:

```text
WeAll API -> WeAll-hosted PoH email oracle -> Stalwart/SMTP transport -> signed email-control receipt -> WeAll chain verification
```

## Trust boundary

A node operator does not prove authority by knowing an oracle URL. The chain accepts PoH email-control results only when the submitted proof is bound to the expected chain context and signed by an allowed oracle authority for the active deployment profile.
