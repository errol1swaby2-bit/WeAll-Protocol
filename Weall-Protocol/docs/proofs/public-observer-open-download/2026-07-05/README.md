# Public Observer Open-Download Transcript Template — 2026-07-05

Status: TEMPLATE ONLY — not completed external evidence.

This directory is a **template**, not completed external evidence.

This template does not close the blocker.

It prepares `AUD-628-P1-001`, the external public observer open-download / state-sync / rendered journey transcript blocker. It must not be cited as blocker closure until an external tester uses the capture script from a clean clone on a machine not controlled by the founder and attaches the completed transcript package.

## Claim boundary

This template does not claim:

- public beta readiness;
- mainnet readiness;
- public multi-validator BFT readiness;
- public validator safety;
- live economics readiness;
- automatic protocol upgrade readiness;
- production helper execution readiness;
- legal/compliance approval;
- public storage-market readiness.

## External tester prerequisites

The operator must record:

- operator name or pseudonymous handle;
- machine/OS/browser;
- network context;
- repository URL;
- exact branch and commit;
- whether the machine/operator is external to the founder;
- signed registry path and SHA-256 digest;
- pinned registry signer public key source;
- seed/genesis API base URL;
- frontend URL used for the rendered journey.

## Capture command

From a fresh external clone:

```bash
cd WeAll-Protocol
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.lock
pip install -e .

export WEALL_PUBLIC_TESTNET=1
export WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PUBKEY=<published-registry-signer-public-key>

bash scripts/boot_public_observer_testnet.sh

bash scripts/capture_public_observer_open_download_transcript_v1_5.sh \
  --api-base https://<public-seed-or-genesis-api> \
  --registry configs/public_testnet_seed_registry.json \
  --out-dir docs/proofs/public-observer-open-download/<yyyy-mm-dd>/<operator-or-host>/ \
  --frontend-url http://127.0.0.1:5173
```

If frontend rendering is captured by Playwright or screen recording instead of manual screenshots, store that artifact under the output directory and list it in the final notes.

## Minimum files expected in the completed package

- `environment.txt`
- `claim-boundary.txt`
- `commands.txt`
- `public_observer_launch_runtime_transcript_v1_5.json`
- `api/v1_status.json`
- `api/v1_chain_identity.json`
- `api/v1_chain_head.json`
- `api/v1_nodes_seeds.json`
- `api/v1_nodes_validators.json`
- `api/v1_observer_edge_status.json`
- `frontend/RENDERED_JOURNEY_CHECKLIST.md`
- `manifest.json`
- screenshot, video, or rendered test output showing the frontend journey

## Closure rule

`AUD-628-P1-001` can only be considered for closure after the transcript proves:

1. external clean clone;
2. exact branch/commit;
3. dependency install;
4. trust root / signer pin verification;
5. signed seed registry verification;
6. observer boot;
7. chain identity check;
8. state sync or honest fail-closed state-sync result;
9. frontend load;
10. rendered operator journey;
11. transaction forwarding behavior or honest fail-closed result;
12. no public beta/mainnet/public validator/live economics/automatic upgrade/helper/legal/storage overclaim.
