# Reviewer LAN Rehearsal Quickstart

This guide is the controlled two-machine reviewer path for WeAll.

It uses a disposable reviewer Genesis chain generated locally for the rehearsal.
It does not use the canonical production Genesis private key.

## What this proves

A successful full run proves:

- a clean clone can prepare the Python environment.
- the Genesis machine can generate a disposable reviewer chain.
- the disposable Genesis API can produce blocks with local-only generated keys.
- the Genesis machine can expose only public reviewer artifacts.
- the observer machine can pull the public observer bundle and reviewer manifest.
- the public observer bundle can be generated and verified.
- the observer machine can verify the remote Genesis API.
- the observer machine can submit signed onboarding transactions.
- signed observer onboarding transactions can confirm.
- committed observer account, device, peer, and async Proof-of-Humanity case state become visible.
- the observer does not receive validator, BFT, helper, treasury, governance, or service authority.

## What this does not prove

This rehearsal does not prove:

- canonical production Genesis authority.
- public mainnet readiness.
- public multi-validator BFT readiness.
- live economics.
- validator promotion.
- full public Proof-of-Humanity bootstrap.
- user-to-user communication tooling, which is outside protocol scope.
- production-grade public moderation or governance.

## Machine A: Genesis

From the backend repository root, run:

    bash scripts/reviewer_setup_env.sh
    bash scripts/reviewer_lan_genesis_rehearsal.sh

Leave the Genesis terminal running.

The Genesis script prints:

- the detected Genesis API base.
- the disposable reviewer work directory.
- the public reviewer artifact directory.
- the artifact index route.
- the observer command.
- Windows PowerShell port-forwarding commands when running under WSL.

The script waits for local block height to advance before printing the observer command.

## Machine B: Observer

Clone the repo and prepare the environment:

    git clone https://github.com/errol1swaby2-bit/WeAll-Protocol.git
    cd WeAll-Protocol/Weall-Protocol
    bash scripts/reviewer_setup_env.sh

Run the observer proof with the Genesis API base printed by Machine A:

    bash scripts/reviewer_observer_rehearsal.sh \
      --genesis-api-base http://GENESIS_LAN_IP:8000 \
      --pull-reviewer-artifacts \
      --allow-lan-genesis-api

The observer script downloads these public files automatically:

    ~/weall-observer/weall-external-observer-bundle.json
    ~/weall-observer/reviewer-chain-manifest.json
    ~/weall-observer/artifact-index.json

## Expected success

The Genesis side should report:

    OK: disposable reviewer Genesis is producing blocks

The observer side should end with:

    OK: reviewer observer rehearsal passed

## Public artifact routes

The Genesis API exposes only public reviewer files when reviewer artifacts are enabled:

    /v1/reviewer/artifacts
    /v1/reviewer/artifacts/bundle
    /v1/reviewer/artifacts/manifest

These routes must not expose:

- reviewer-genesis.env.
- reviewer private keys.
- local ledger files.
- runtime databases.
- authority or validator private material.

## Common failures

### No module named weall

Run:

    bash scripts/reviewer_setup_env.sh

### production_authority_url_must_be_https

Use the reviewer Genesis script. It builds the public observer bundle with a safe HTTPS authority metadata URL while keeping the LAN Genesis API as the actual transaction endpoint.

### Artifact route missing

Confirm Genesis was started by the reviewer Genesis script and that the terminal reported:

    OK: disposable reviewer Genesis is producing blocks

Then check:

    curl -fsS http://GENESIS_LAN_IP:8000/v1/reviewer/artifacts

### LAN API rejected

Use:

    --allow-lan-genesis-api

This is valid only for controlled LAN rehearsal.

### Second machine cannot connect

When Genesis runs inside WSL, the Windows host may need port forwarding. The Genesis script prints the exact PowerShell commands to run as Administrator.

## Correct claim after success

Use this wording:

    The controlled two-machine reviewer rehearsal passed on a disposable reviewer chain: the observer pulled public reviewer artifacts from Genesis, verified Genesis compatibility, remained non-authoritative, submitted signed onboarding transactions, and verified committed account/device/peer/async-PoH state through the Genesis API.

Do not claim canonical production Genesis authority, public mainnet readiness, public multi-validator BFT readiness, live economics, validator promotion, or production-grade public governance from this rehearsal alone.
