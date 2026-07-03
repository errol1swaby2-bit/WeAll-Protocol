# Closed testnet / public observer rehearsal readiness v1.5

Status: late-stage pre-public-testnet readiness audit.

This document is a bounded rehearsal checklist, not a public-mainnet claim. It separates what a fresh reviewer/operator can verify locally from what still requires a coordinated closed testnet or public observer cohort.

## Truth boundary

A successful closed-testnet rehearsal may prove that the current repository can boot, expose public observer surfaces, keep economics locked, preserve public-only civic state, and capture replay evidence under the documented harness. It does not prove public mainnet safety, global throughput, adversarial public multi-validator BFT readiness, or live economic activation.

## Fresh clone setup

Run from a clean checkout:

```bash
git rev-parse --abbrev-ref HEAD
git rev-parse HEAD
git status --short

cd Weall-Protocol
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r requirements-dev.lock
python3 -m pip install -e .
```

Expected: dependencies install from checked-in lockfiles. If a zip export is used, record that commit identity must be supplied separately from the source checkout.

## Testnet identity and discovery

Verify the checked-in testnet identity and discovery posture:

```bash
PYTHONPATH=src python scripts/check_v15_public_readiness_artifacts.py
PYTHONPATH=src python scripts/check_release_hygiene_v1_5.py
pytest -q \
  tests/prod/test_public_testnet_v1_chain_identity.py \
  tests/prod/test_public_observer_checked_in_registry_primary.py \
  tests/prod/test_public_observer_provider_not_authority.py \
  tests/prod/test_public_observer_seed_discovery.py \
  tests/prod/test_public_observer_registry_auto_dial.py
```

Expected: chain identity and seed registry checks pass. Provider-hosted bytes may help distribute data, but signatures, chain commitments, and protocol state remain the authority.

## Public observer boot

Use the existing observer boot path:

```bash
WEALL_PUBLIC_TESTNET=1 bash scripts/boot_public_observer_testnet.sh
```

Capture:

- command used;
- environment variables, with secrets redacted;
- chain_id/network_id reported by the node;
- seed registry source and signature/commitment verification result;
- observer authority boundary proving validator signing is not enabled;
- sync height and state commitment;
- any failure recovery steps.

Targeted evidence checks:

```bash
pytest -q \
  tests/prod/test_public_observer_boot_and_evidence_scripts.py \
  tests/prod/test_observer_bundle_contains_no_authority_secrets.py \
  tests/prod/test_observer_cannot_enable_validator_signing.py \
  tests/prod/test_public_observer_launch_transcript_artifacts.py
```

## Minimum coherent civic loop for rehearsal

The closed rehearsal should exercise, or explicitly mark as out of scope for that run:

1. account registration or account state readback;
2. Proof-of-Humanity / human-verification state where implemented;
3. public posting or other public social/civic activity;
4. public group read visibility with membership gating participation only;
5. governance proposal creation;
6. block-height-based governance lifecycle progression and finalization;
7. dispute creation, review, appeal/final-receipt behavior, and public outcome visibility;
8. reputation event visibility where a flow mutates reputation;
9. protocol upgrade declaration and scheduled activation record;
10. observer/node status and replay evidence;
11. economics inactive/locked status.

Recommended targeted checks:

```bash
pytest -q \
  tests/test_group_governance_contract.py \
  tests/test_public_only_protocol_redesign.py \
  tests/test_protocol_upgrade_record_only_boundary.py \
  tests/test_protocol_upgrade_height_scheduled_lifecycle.py \
  tests/test_governance_due_height_trust_boundary.py \
  tests/test_dispute_height_lifecycle_boundaries.py
```

## Protocol upgrade rehearsal boundary

Protocol-upgrade transactions remain record-only. A successful upgrade rehearsal should prove:

- declaration is public protocol state;
- declaration/activation receipts require SYSTEM queue or receipt-only parent provenance;
- governance approval records a deterministic future `activation_height`;
- unsupported targets are rejected when supported-target configuration is present;
- activation records do not fetch artifacts, apply patches, run migrations, restart processes, roll back nodes, activate transfers, activate fees, activate rewards, or activate economics;
- leader/follower/observer replay produces the same scheduled record.

The rehearsal must not claim automatic upgrade delivery or software migration support.

## Reviewer-facing lifecycle status surface

`GET /v1/status/testnet-capabilities` now exposes a compact reviewer map for:

- protocol-upgrade lifecycle: public record-only declaration and block-height scheduled activation, with governance/system-queue parent provenance and automatic software apply disabled;
- governance lifecycle: block-height scheduler truth with UI wall-clock estimates treated as display-only;
- dispute lifecycle: block-height review/appeal/timeout windows with private identity evidence protected;
- minimum civic loop: frontend entrypoints for account state (`/profile` or `/account/:account`), verification (`/verification`), feed (`/feed`), groups (`/groups`), governance/decisions (`/decisions`), disputes/reports (`/reports`), review center (`/reviews`), activity/reputation visibility (`/activity`), node status (`/node`), and economics lock status (`/economics`).

Canonical reviewer route boundary: the current frontend uses **Decisions** at `/decisions` for governance proposal/vote/finalization surfaces and **Reports** at `/reports` for dispute/outcome surfaces. Legacy `/proposals` and `/disputes` aliases are intentionally not part of the reviewer route map.

This status surface is not itself a public-beta claim. It is a reviewer navigation and claim-boundary surface that should match the code and tests in the submitted commit.

## Performance evidence packaging

When sustained-load evidence is captured, store a transcript or JSON evidence file with:

- command used;
- machine/CPU/RAM/storage notes;
- candidate TPS;
- observed TPS per block;
- average observed TPS;
- block count;
- max leader block wall time;
- max follower apply wall time;
- max observer apply wall time;
- schedule pass/fail;
- follower replay pass/fail;
- observer replay pass/fail;
- bottleneck fields such as block admission, execution helper, system queue binding, and post-system emitter wall time;
- known limitations.

Allowed wording: “Local sustained-load testing reached approximately 2350 TPS under the documented harness” only if a matching evidence artifact exists for the submitted commit. Do not claim global/public-mainnet throughput from a local harness.

## Closed-testnet evidence bundle

A reviewer-ready evidence bundle should include:

```bash
git rev-parse --abbrev-ref HEAD
git rev-parse HEAD
git status --short
git diff --check
PYTHONPATH=src python -m compileall -q src/weall
bash scripts/secret_guard.sh
PYTHONPATH=src python scripts/check_v15_public_readiness_artifacts.py
PYTHONPATH=src python scripts/check_release_hygiene_v1_5.py
python3 -B -S scripts/check_tx_canon_artifacts.py
pytest -q tests/test_protocol_upgrade_record_only_boundary.py tests/test_protocol_upgrade_height_scheduled_lifecycle.py tests/test_governance_due_height_trust_boundary.py tests/test_dispute_height_lifecycle_boundaries.py
```

Add broader test output when available. If the full suite is skipped because of time or environment limits, state that directly.

## Remaining hardening before public-mainnet claims

- adversarial multi-node validator rehearsals;
- independent public observer cohort evidence;
- deterministic upgrade artifact verification and migration vectors;
- operator runbooks for incident response and rollback coordination;
- frontend end-to-end rehearsal for the full civic loop;
- independent security/release review;
- public network performance evidence separate from local harness throughput.
