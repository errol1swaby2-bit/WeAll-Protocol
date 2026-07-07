# WeAll Node Operator Onboarding

This document has been superseded by the current first-run operator guide:

```text
./docs/NEW_NODE_OPERATOR_QUICKSTART.md
```

Use that guide for the production-shaped onboarding flow:

1. start an observer/onboarding node with `./scripts/boot_onboarding_node.sh`;
2. create an account through the local app;
3. save the account recovery key;
4. complete Verified Person / Tier 1 async review;
5. complete Trusted Verified Person / Tier 2 live review;
6. generate a separate node key;
7. register the node public key;
8. submit node-operator enrollment;
9. let the protocol automatically activate baseline Node Operator status once deterministic prerequisites pass;
10. opt into validator or storage responsibilities separately;
11. start explicit production service mode with `./scripts/boot_node_operator.sh` only after eligibility is active.

## Current authority model

- Baseline Node Operator status is the infrastructure identity.
- Validator responsibility is an optional responsibility under Node Operator status.
- Storage responsibility is an optional responsibility under Node Operator status.
- Baseline Node Operator status does not automatically grant validator authority.
- Baseline Node Operator status does not automatically grant storage allocation authority.
- Declared storage capacity is not proven capacity.
- Proof pending is not allocation eligible.
- The node key must be separate from the account recovery key.

## Production boot split

Use the onboarding boot for first-run account setup and verification:

```bash
./scripts/boot_onboarding_node.sh
```

Use the production service boot only after baseline Node Operator status is active:

```bash
WEALL_NODE_PRIVKEY_FILE=/secure/path/weall-node.key \
WEALL_NODE_PUBKEY=<registered-node-public-key> \
WEALL_BOUND_ACCOUNT=@yourhandle \
./scripts/boot_node_operator.sh
```

This document is intentionally short to avoid maintaining two competing onboarding sources.
<!-- WEALL_RELEASE_TRUTH_CHECKPOINT_START -->
## Release truth checkpoint

- Current transaction canon checkpoint: **230 transaction types**, canon version **1.25.0**.
- Proof-of-Humanity model: **Tier 0 = account only**, **Tier 1 = native async verified human**, **Tier 2 = native live verified human**.
- There is no required user-facing Tier 3.
- No required email, no required SMTP, no required DNS, and no required named hosting provider are part of PoH authority.
- Production validator posture must **fail closed** unless BFT is enabled and effective for validator/service signing.
- Production tx payload limits are **profile-pinned** and local payload env overrides must not change consensus validity.
- Public API redaction is required for public snapshots and unauthenticated account reads.
- Release safety requires tx canon artifact verification, secret guard, and release tree verification.
<!-- WEALL_RELEASE_TRUTH_CHECKPOINT_END -->
