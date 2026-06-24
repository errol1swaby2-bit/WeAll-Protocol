# Clean Clone Tester Boot Rehearsal

This document defines the clean-clone proof path for a WeAll external tester.

## Goal

A fresh clone should be able to:

1. Install backend dependencies from locked requirements.
2. Pass release and reviewer gates.
3. Start a private Genesis producer rehearsal when the canonical Genesis producer key is supplied locally.
4. Build or use a public observer bundle.
5. Boot a tester observer node with one command.
6. Keep validator signing, BFT, helper authority, and block production disabled for the tester node.
7. Start the frontend on a tester-selected port.
8. Guide the tester into account creation, recovery verification, and onboarding.

## Truth boundary

Passing this rehearsal proves a private-network clean-clone tester boot path.

It does not prove:

- public mainnet readiness
- public multi-validator BFT readiness
- live economics readiness
- external private communication tooling; protocol-native private messaging is unsupported
- public HTTPS external observer readiness

Public external tester readiness still requires a reachable HTTPS Genesis API and a public observer bundle that does not rely on `WEALL_ALLOW_PRIVATE_GENESIS_API=1`.

## Fresh clone dependency setup

Run:

    cd ~/WeAll-Protocol/Weall-Protocol
    /usr/bin/python3 -m venv .venv
    source .venv/bin/activate
    python -m pip install -U pip setuptools wheel
    python -m pip install -r requirements.lock
    python -m pip install -r requirements-dev.lock

## Clean release and reviewer gates

Before running release/reviewer gates, remove local runtime artifacts:

    cd ~/WeAll-Protocol/Weall-Protocol
    source .venv/bin/activate
    export PYTHONDONTWRITEBYTECODE=1
    rm -rf ../web/node_modules ../web/dist ../web/tsconfig.tsbuildinfo
    find . -type d \( -name "__pycache__" -o -name ".pytest_cache" -o -name ".weall-devnet" -o -name ".weall" -o -name "data" -o -name "*.aux_helper_lanes" \) -prune -exec rm -rf {} +
    find . -type f \( -name "*.pyc" -o -name "*.pyo" -o -name "*.db" -o -name "*.db-wal" -o -name "*.db-shm" -o -name "*.sqlite" -o -name "*.aux.sqlite" -o -name "*.db.bft_journal.jsonl" \) -delete
    python -B -S scripts/check_tx_canon_artifacts.py
    bash scripts/secret_guard.sh
    bash scripts/verify_release_tree.sh
    bash scripts/verify_release_dependencies.sh
    bash scripts/reviewer_production_readiness_gate.sh

## Private Genesis rehearsal

Founder/operator-only. Requires the canonical Genesis producer key outside the repository.

    cd ~/WeAll-Protocol/Weall-Protocol
    source .venv/bin/activate
    GENESIS_IP="$(hostname -I | awk '{print $1}')"
    bash scripts/weall_genesis_rehearsal.sh \
      --producer-pubkey-file "$HOME/.weall/secrets/weall_node_pubkey" \
      --producer-privkey-file "$HOME/.weall/secrets/weall_node_privkey" \
      --genesis-api-base "http://${GENESIS_IP}:8000" \
      --allow-private-genesis-api

The private key must never be printed, committed, copied into the repo, or included in an observer bundle.

## Private observer bundle

Build the bundle:

    cd ~/WeAll-Protocol/Weall-Protocol
    GENESIS_IP="$(hostname -I | awk '{print $1}')"
    mkdir -p /tmp/weall-observer
    python3 scripts/build_external_observer_bundle.py \
      --out /tmp/weall-observer/weall-external-observer-bundle.private-rehearsal.json \
      --genesis-api-base "http://${GENESIS_IP}:8000"

Then mark the bundle as private rehearsal by setting profile=rehearsal, authority.profile=rehearsal, and rehearsal_boundary.private_genesis_api_allowed_only_with_WEALL_ALLOW_PRIVATE_GENESIS_API=true.

## One-command tester observer boot

Use a different local API/frontend port than Genesis:

    cd ~/WeAll-Protocol/Weall-Protocol
    GENESIS_IP="$(hostname -I | awk '{print $1}')"
    bash scripts/weall_tester_node.sh \
      --bundle /tmp/weall-observer/weall-external-observer-bundle.private-rehearsal.json \
      --genesis-api-base "http://${GENESIS_IP}:8000" \
      --mode private-rehearsal \
      --allow-private-genesis-api \
      --api-port 8001 \
      --frontend-port 5174

Expected output includes:

    OK: WeAll tester observer node environment is installed.
    validator signing: disabled
    BFT/helper/block production: disabled

The observer node must run without:

- `WEALL_NODE_PRIVKEY`
- `WEALL_NODE_PRIVKEY_FILE`
- validator signing authority
- BFT authority
- helper authority
- block production authority

## Frontend flow after tester boot

The frontend should guide the tester through:

1. Create or restore account.
2. Download or copy recovery file.
3. Verify recovery file or recovery key.
4. Continue to verification/onboarding.

The frontend must not allow account setup to proceed merely because a user clicked a checkbox. Recovery proof must be verified.
