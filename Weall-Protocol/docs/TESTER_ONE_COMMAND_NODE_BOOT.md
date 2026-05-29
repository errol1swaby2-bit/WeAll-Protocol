# One-command tester node boot

This runbook defines the safe one-command path for a first external tester to build, install, and run a WeAll observer/onboarding node without needing validator, BFT, helper, treasury, authority, oracle, Cloudflare, or external identity-provider secrets.

## Normal external tester command

From a cloned repository:

```bash
bash Weall-Protocol/scripts/weall_tester_node.sh \
  --bundle ./weall-external-observer-bundle.json \
  --genesis-api-base https://genesis.example
```

For a private LAN rehearsal only:

```bash
bash Weall-Protocol/scripts/weall_tester_node.sh \
  --bundle ./weall-external-observer-bundle.private-rehearsal.json \
  --genesis-api-base http://192.168.1.50:8000 \
  --mode private-rehearsal \
  --allow-private-genesis-api
```

The script verifies the public bundle, installs public chain anchors into a local env file, creates runtime paths outside the repository, starts the frontend helper when possible, and then starts the observer/onboarding node.

## Safety invariants

The tester path runs in observer onboarding mode. It does not grant validator authority, BFT signing, helper authority, block production, treasury authority, or governance authority.

The script refuses unsafe observer environments through the shared observer secret boundary. In observer mode it rejects node private key material, validator signing flags, BFT/helper/block-loop authority, authority-signer secrets, oracle secrets, and external identity-provider service credentials.

Public production bundles must use HTTPS Genesis API bases. Private or LAN Genesis APIs are only allowed when the operator explicitly passes `--allow-private-genesis-api`, and the output remains a private rehearsal claim, not a public external observer claim.

## Expected success output

A successful tester boot prints:

```text
OK: WeAll tester observer node environment is installed.
- mode: observer onboarding
- local API: http://127.0.0.1:8000
- frontend: http://127.0.0.1:5173
- validator signing: disabled
- BFT/helper/block production: disabled
```

The tester then opens the frontend, creates or restores an account, verifies their recovery file, and begins account verification/onboarding.

## Founder/operator private Genesis rehearsal

The founder/operator-only helper is:

```bash
bash scripts/weall_genesis_rehearsal.sh \
  --producer-pubkey-file ~/.weall/secrets/weall_node_pubkey \
  --producer-privkey-file ~/.weall/secrets/weall_node_privkey \
  --genesis-api-base http://172.27.152.123:8000 \
  --allow-private-genesis-api
```

This helper is not for normal testers. It verifies that the supplied producer public key matches the canonical Genesis validator pubkey in `configs/genesis.ledger.prod.json`, then starts the Docker Genesis API and producer for a private rehearsal. The private key is never printed or committed to the repository.

## Truth boundary

Passing the one-command tester boot means a node is locally prepared for observer onboarding. It does not prove public multi-validator BFT, mainnet readiness, live economics, production-grade private messaging, or validator promotion. Signed external observer onboarding is proven only when `scripts/first_external_observer_reproducibility_gate.sh` is run with both remote preflight and signed onboarding enabled and the live gate confirms the transaction sequence.
