# One-command tester node start after prerequisites

This runbook defines the safe **one-command start path after explicit prerequisites** for an external tester running a WeAll observer/onboarding node. It is not a blank-machine installer and does not claim to acquire the external observer bundle or Genesis API endpoint for the tester.

The path does not require validator, BFT, helper, treasury, authority, oracle, named hosting-provider, or external identity-provider secrets.

## Required prerequisites

From a fresh clone, prepare the hash-locked backend environment first:

```bash
cd WeAll-Protocol/Weall-Protocol
python3 -m venv .venv
.venv/bin/python -m pip install --require-hashes -r requirements.lock
.venv/bin/python -m pip install -e . --no-deps
cd ..
```

You must also have:

- a verified external observer bundle available as a local path or HTTPS URL;
- the usable Genesis API base for the rehearsal/network being tested;
- `npm` when the default frontend path is requested, or pass `--skip-frontend` explicitly.

The tester script fails closed if the prepared backend virtual environment is absent. It does not fall back to ambient Python packages.

## Normal external tester command

After those prerequisites:

```bash
bash Weall-Protocol/scripts/weall_tester_node.sh \
  --bundle ./weall-external-observer-bundle.json \
  --genesis-api-base https://genesis.example
```

For a LAN rehearsal only:

```bash
bash Weall-Protocol/scripts/weall_tester_node.sh \
  --bundle ./weall-external-observer-bundle.private-rehearsal.json \
  --genesis-api-base http://192.168.1.50:8000 \
  --mode private-rehearsal \
  --allow-lan-genesis-api
```

The script verifies the public bundle, installs public chain anchors into a local env file, creates runtime paths outside the repository, starts the frontend when requested, and then starts the observer/onboarding node. These actions occur only after the locked backend environment prerequisite above has been satisfied.

## Safety invariants

The tester path runs in observer onboarding mode. It does not grant validator authority, BFT signing, helper authority, block production, treasury authority, or governance authority.

The script refuses unsafe observer environments through the shared observer secret boundary. In observer mode it rejects node private key material, validator signing flags, BFT/helper/block-loop authority, authority-signer secrets, oracle secrets, and external identity-provider service credentials.

Public production bundles must use HTTPS Genesis API bases. Private or LAN Genesis APIs are only allowed when the operator explicitly passes `--allow-lan-genesis-api`, and the output remains a LAN rehearsal claim, not a public external observer claim.

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
  --allow-lan-genesis-api
```

This helper is not for normal testers. It verifies that the supplied producer public key matches the canonical Genesis validator pubkey in `configs/genesis.ledger.prod.json`, then starts the Docker Genesis API and producer for a LAN rehearsal. The private key is never printed or committed to the repository.

## Truth boundary

Passing the one-command tester boot means a node is locally prepared for observer onboarding. It does not prove public multi-validator BFT, mainnet readiness, live economics, external communications, or validator promotion. Signed external observer onboarding is proven only when `scripts/first_external_observer_reproducibility_gate.sh` is run with both remote preflight and signed onboarding enabled and the live gate confirms the transaction sequence.
