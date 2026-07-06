# WeAll Protocol Backend

This directory contains the WeAll backend node/runtime, public API, generated artifacts, Docker/operator helpers, and backend test surfaces for the current local/devnet/public-observer-oriented hardening track.

Current allowed claim: **WeAll is a pre-public-testnet protocol implementation under active hardening, with local/devnet/public-observer-oriented evidence present and public beta readiness still blocked by explicit external observer, replay, validator/operator, storage, legal, upgrade-execution, and helper-topology gates.**

This backend README is not a public beta, public mainnet, public validator, public multi-validator BFT, live-economics, automatic-upgrade, production-helper, legal-approval, or public storage-market readiness claim.

## Public-only civic protocol direction

The backend is reviewed as public-only civic protocol infrastructure. Protocol-native social, civic, governance, moderation, dispute, group, reputation, validator/operator, and node activity is intended to be publicly inspectable. Group membership may gate posting, commenting, voting, moderation, invitation, and administration behavior, but not read visibility for protocol-native group content.

Private/direct/encrypted messaging is not part of the NLnet/public-testnet claim. Any historical private messaging language is legacy/out-of-scope unless explicitly labeled unsupported or disabled.

## Current status

| Surface | Status | Backend meaning |
|---|---:|---|
| Local/devnet/public-observer-oriented evidence | GO for local review only | Backend artifacts, generated evidence, and local gates support bounded local/devnet/public-observer-oriented rehearsal packaging. |
| Public beta readiness | NO-GO | `generated/public_beta_blocker_report_v1_5.json` keeps `public_beta_ready=false`. |
| Public observer launch claim | NO-GO | External clean-clone/open-download observer evidence is still required. |
| Public validator/BFT readiness | NO-GO | Independent validator/operator evidence remains required. |
| Live economics | NO-GO | Economics remain locked; do not treat local wallet/status surfaces as live-economics authority. |
| Automatic upgrade execution | NO-GO | Upgrade records are public metadata only; software apply, migrations, and rollbacks are not enabled. |
| Legal/compliance approval | NO-GO | Legal materials remain non-lawyer drafts pending review. |
| Public storage-market readiness | NO-GO | Storage/IPFS tests are not a public storage-provider market claim. |

Current tx canon checkpoint: **236 tx types, version 1.25.0**.

Proof-of-Humanity checkpoint: **Tier 0 = account only**, **Tier 1 = native async verified human**, and **Tier 2 = native live verified human**. There is no required user-facing Tier 3. There is no required email, no required SMTP, no required DNS, and no required named hosting provider as PoH authority.

## Backend purpose in the reviewer flow

The backend is responsible for:

- canonical transaction type indexing and tx-contract evidence;
- deterministic admission, lifecycle, receipt, and status surfaces;
- public-only account/profile, social, group, governance, dispute/review, reputation, node/operator, and observer APIs;
- signed/pinned public-testnet discovery inputs;
- generated public-readiness and release-evidence artifacts;
- fail-closed release hygiene and secret/export safety checks.

The frontend can render backend state, but frontend state is not protocol authority. Local scripts can collect evidence, but local scripts are not public-readiness authority without the external transcript gates.

## Canonical backend quickstart

From the repository root:

```bash
./scripts/quickstart_tester.sh
```

From this backend directory:

```bash
./scripts/quickstart_tester.sh
```

That helper should verify local ports, create runtime directories, generate `generated/tx_index.json`, start the local stack, wait for API readiness, and print health/operator URLs.

Most testers should use the repository root full-stack command for local UI inspection:

```bash
cd ..
./scripts/dev_boot_full_stack.sh
```

That root-level flow wraps backend startup, demo bootstrap, frontend startup, and local session bootstrap. Demo bootstrap output is for local inspection only; it is not public-testnet proof.

## Reviewer verification path

Run these checks from this directory before relying on reviewer-facing backend claims:

```bash
cd ~/WeAll-Protocol/Weall-Protocol
source .venv/bin/activate

PYTHONPATH=src:scripts python scripts/gen_public_beta_blocker_report_v1_5.py --check
PYTHONPATH=src python scripts/gen_release_evidence_manifest_v1_5.py --check
PYTHONPATH=src python scripts/check_v15_public_readiness_artifacts.py
PYTHONPATH=src python scripts/check_reviewer_truth_boundaries.py
PYTHONPATH=src python -m pytest -q \
  tests/test_release_docs_truth_sync.py \
  tests/test_reviewer_language_cleanup.py \
  tests/prod/test_final_public_observer_controlled_testnet_go_gate.py \
  tests/prod/test_public_beta_evidence_gates.py \
  tests/prod/test_public_observer_testnet_readiness_docs.py \
  tests/test_public_readiness_artifacts_v15.py
```

If README or reviewer docs changed, also run:

```bash
PYTHONPATH=src python scripts/check_release_hygiene_v1_5.py
```

## Controlled-devnet same-machine proof path

For protocol-review sessions, the expected backend path is the non-seeded dual-node controlled-devnet readiness suite that runs on one machine:

```bash
cd ~/WeAll-Protocol/Weall-Protocol
source .venv/bin/activate

pytest -q
WEALL_DEVNET_SUITE_RUN_TIER2=1 \
WEALL_DEVNET_SUITE_RUN_LIVE=1 \
bash scripts/devnet_controlled_readiness_suite.sh
```

This flow uses normal public transaction submission paths. It verifies direct API permission gating, auto-starts a controlled genesis node and a joining node on the same machine, resets stale controlled-devnet state when auto-starting, creates a fresh account, verifies Tier-1 native async PoH through protocol commitments, syncs node 2, submits a Tier-1-gated action from node 2, syncs node 1 back from node 2, completes Tier-2 native live PoH, proves both nodes converge on the same tip and state root, and verifies restart/catch-up.

The readiness suite intentionally never calls `/v1/dev/demo-seed`.

## Public observer boot path

Operator-facing public observer startup remains:

```bash
git clone <repo-url> WeAll-Protocol
cd WeAll-Protocol/Weall-Protocol
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.lock
pip install -e .
WEALL_PUBLIC_TESTNET=1 bash scripts/boot_public_observer_testnet.sh
```

The checked-in public-testnet chain commitments, signed seed registry, trust roots, and validator endpoint evidence must match before boot proceeds. Endpoint advertisements are connection hints and freshness evidence; they do not grant validator authority.

## Evidence package map

| Evidence area | Backend path |
|---|---|
| Public beta blocker report | `generated/public_beta_blocker_report_v1_5.json` |
| Release evidence manifest | `generated/release_evidence_manifest_v1_5.json` |
| Final controlled/public-observer go-gate artifact | `generated/final_public_observer_controlled_testnet_go_gate_v1_5.json` |
| API contract map | `generated/api_contract_map_v1_5.json` |
| API response vectors | `generated/api_response_vectors_v1_5.json` |
| Failure code registry | `generated/failure_code_registry_v1_5.json` |
| Tx canon artifacts | `generated/tx_index.json`, `generated/tx_contract_map.json` |
| External proof templates | `docs/proofs/` |
| Reviewer documents | `docs/reviewer/`, including `docs/reviewer/README_TO_IMPLEMENTATION_TRACEABILITY.md` |
| Testnet runbooks | `docs/testnet/` |

The blocker catalog remains explicit: 14 total entries, 7 closed in repository, and 7 open as external evidence or mainnet-hardening gates.

## Major backend surfaces

- **Account/profile:** account/profile reads, session identity, public API redaction, and native PoH state.
- **Public social:** public feed/content/comment/notice routes and tx lifecycle visibility.
- **Public groups:** public group reads with member-gated participation and administration.
- **Governance:** public proposal/vote/tally/finalization records, block-height progression, and record-only protocol-upgrade metadata.
- **Disputes/reviews:** public reports, review assignment, votes, receipts, outcomes, and restricted private-identity-evidence boundaries.
- **Transaction lifecycle:** tx admission, mempool/status, receipts, block inclusion evidence, and current 236 tx type canon.
- **Node/operator:** readiness/status, discovery, validator authority gates, observer status, release hygiene, and secret guard.
- **Observer boot:** signed/pinned chain/seed/endpoint checks before public-observer startup.
- **External evidence packages:** observer, replay, validator/operator, storage/IPFS, legal, upgrade, and helper-topology transcripts.

## What is intentionally disabled

- Live economics are not enabled: fees, transfers, rewards, treasury spend, and slashing are not claimed live.
- Public validator and public multi-validator BFT readiness are not claimed.
- Automatic protocol upgrades are not enabled.
- Executable migrations and rollbacks are not enabled.
- Production helper execution is not enabled.
- Public storage-market readiness is not claimed.
- Legal/compliance approval is not claimed.
- Protocol-native encrypted DMs, private groups, member-only-readable protocol-native group content, and opaque consensus-affecting social payloads are unsupported.

## Useful backend URLs

When the local backend is healthy, these should work:

- `http://127.0.0.1:8000/v1/readyz`
- `http://127.0.0.1:8000/v1/status`
- `http://127.0.0.1:8000/docs`

## Docker diagnostics

```bash
docker compose ps
docker compose logs weall_api --tail 200
docker compose logs weall_producer --tail 200
docker compose logs kubo --tail 200
docker inspect weall-protocol-weall_api-1 --format '{{json .State.Health}}'
```

## Local demo bootstrap

After the backend is ready, the local demo bootstrap is:

```bash
./scripts/demo_bootstrap_tester.sh
```

It writes `generated/demo_bootstrap_result.json`; the root dev flow can copy that into `web/public/dev-bootstrap.json` for local UI inspection. Demo seed state is useful for review ergonomics, but it is not external evidence and must not be used to close public beta blockers.

## Pass 33 crypto posture

WeAll is a pre-public-testnet protocol implementation under active hardening.

The controlled-testnet target signing profile is now `pq-mldsa-v1`. `legacy-ed25519-v1` is legacy/transitional/dev-only unless a chain configuration explicitly allows it for migration tests. This does not claim completed production cryptographic audit, public mainnet readiness, live economics, public multi-validator BFT readiness, production constitutional governance readiness, or public beta readiness. Public-only protocol surfaces remain public.

See `Weall-Protocol/docs/security/CRYPTO_AGILITY_AND_QUANTUM_POSTURE.md` for the crypto inventory and remaining blockers.

### Pass 33 signature-profile truth boundary

WeAll is a pre-public-testnet protocol implementation under active hardening. The controlled-testnet target signature profile is `pq-mldsa-v1`; `legacy-ed25519-v1` is legacy/transitional/dev-only unless explicitly allowed by chain configuration. This does not claim completed production cryptographic audit, mainnet readiness, live economics, public multi-validator BFT readiness, production constitutional governance readiness, or public beta readiness. Public-only protocol surfaces remain public.
