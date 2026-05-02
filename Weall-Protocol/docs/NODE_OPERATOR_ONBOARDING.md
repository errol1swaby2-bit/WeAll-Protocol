# WeAll Node Operator Onboarding

This document describes the normal production-oriented onboarding flow for a new WeAll node operator.

A normal node operator verifies chain state and public chain authority anchors. A normal node operator does **not** need mail-transport credentials, authority signer keys, external provider API tokens, or authority snapshot signer private keys.

## Roles

| Role | Holds | Does not hold |
|---|---|---|
| Validator / consensus participant | Validator/node key material and finalized chain state | Email transport credentials, external identity-provider credentials, or authority private keys |

## Public onboarding bundle

A public onboarding bundle gives the operator the chain and authority anchors needed to verify they are connecting to the correct network and public chain authority profile.

It contains public values only:

- chain id
- genesis hash
- genesis state root
- tx index hash
- chain authority URL, when the deployment publishes one
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
WEALL_BOOTSTRAP_OPERATOR_ACCOUNT
WEALL_NODE_PUBKEY
WEALL_NODE_PRIVKEY_FILE or equivalent local signer configuration
```


## Run preflight

```bash
bash scripts/prod_node_operator_from_bundle_preflight.sh node-operator-onboarding-bundle.json
```

This checks:

- bundle matches the local production chain manifest;
- public chain/authority anchors are exported;
- external identity-provider and authority-signer secrets are absent from the normal node environment;
- optional live authority/key checks if node account/key variables are configured.

## Proof-of-Humanity use

Normal node operators do not run external identity-provider verification services.
Proof-of-Humanity is protocol-native: Tier 1 is async juror-attested review, and
Tier 2 is live juror-attested review. Nodes verify committed chain state and submit
normal signed transactions. No email, SMTP, DNS, Cloudflare, CAPTCHA, phone, OAuth, KYC, app-store identity, or third-party AI scoring service is part of the
required PoH architecture.

## Trust boundary

A node operator does not prove authority by knowing any external service endpoint. PoH authority comes from protocol rules, chain state, and native juror-attested review.

<!-- WEALL_RELEASE_TRUTH_CHECKPOINT_START -->
## Release truth checkpoint

- Current transaction canon checkpoint: **225 transaction types**, canon version **1.24.0**.
- Proof-of-Humanity model: **Tier 0 = account only**, **Tier 1 = native async verified human**, **Tier 2 = native live verified human**.
- There is no required user-facing Tier 3.
- No required email, no required Cloudflare, no required SMTP, and no required DNS are part of PoH authority.
- Production validator posture must **fail closed** unless BFT is enabled and effective for validator/service signing.
- Production tx payload limits are **profile-pinned** and local payload env overrides must not change consensus validity.
- Public API redaction is required for public snapshots and unauthenticated account reads.
- Release safety requires tx canon artifact verification, secret guard, and release tree verification.
<!-- WEALL_RELEASE_TRUTH_CHECKPOINT_END -->

