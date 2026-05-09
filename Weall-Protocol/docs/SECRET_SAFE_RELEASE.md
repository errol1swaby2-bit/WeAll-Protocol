# Secret-Safe Release Gate

This repository may be used to generate real genesis and node/operator keys during production rehearsal. Those local key files must never be committed, exported, or sent to an external tester.

## Non-negotiable rule

A releaseable tree may contain only these files under `secrets/`:

- `secrets/.gitignore`
- `secrets/README.md`
- `secrets/README`

Everything else under `secrets/` is treated as local operator material and blocks release verification, including public-key files. The authoritative public founding/authority key is pinned in `configs/chains/weall-genesis.json`; external testers do not need files from `secrets/`.

## Before creating a release package

Run:

```bash
bash scripts/clean_release_artifacts.sh
bash scripts/secret_guard.sh
bash scripts/verify_release_tree.sh
bash scripts/prod_chain_manifest_check.sh
```

If verification fails on `secrets/`, move the local keys outside the repo or remove them intentionally after backing them up securely.

Do not use `clean_release_artifacts.sh` as a key shredder. It intentionally refuses to silently delete `secrets/` material because those files may be real production keys.

## If a private key was shared

If `secrets/weall_node_privkey` or any equivalent private key file was included in a shared artifact, treat that key as compromised. Rotate the key before any real production network, observer test, validator rehearsal, or public release.

## Local observer readiness without a second machine

When a second machine is not available, run:

```bash
bash scripts/local_observer_readiness_gate.sh
```

This proves the local prerequisites for a future observer test:

- tx canon is synchronized
- production chain manifest is pinned
- public observer bundle can be generated and verified
- observer-mode preflight forces validator signing, BFT, helper authority, and block loop off
- no authority, validator, Cloudflare, SMTP, or oracle private secret is required

This is not a substitute for:

```bash
bash scripts/rehearse_external_observer_two_machine.sh
```

The real two-machine rehearsal remains required before inviting an outside observer-node tester.
