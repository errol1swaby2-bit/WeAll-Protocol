# Public observer / controlled testnet readiness plan v1.5

Status: canonical bounded-testnet readiness plan.

This plan defines the next launch target for WeAll v1.5. It is intentionally
narrower than public beta, public mainnet, public multi-validator BFT, live
economics, automatic upgrade, or production helper readiness.

## Current target statement

Allowed target statement:

> WeAll is ready to prepare a bounded public observer / controlled testnet
> launch candidate. Public beta, mainnet, public multi-validator BFT, live
> economics, automatic upgrade, production helper, public validator, public
> storage-market, and legal/compliance readiness remain unclaimed until the
> explicit external evidence and hardening gates are satisfied.

If external observer evidence is still missing, use the narrower statement:

> Ready for controlled internal/public-observer rehearsal candidate, with public
> beta readiness still blocked by explicit external evidence gates. In short,
> public beta readiness still blocked until external evidence exists.

## Readiness tiers

| Tier | Name | What it may prove | Required evidence | Claims still forbidden |
| --- | --- | --- | --- | --- |
| Tier A | Controlled local reviewer testnet | Clean local checkout can run deterministic reviewer gates, generated artifacts are fresh, public-only/economics-off boundaries hold, and controlled-testnet mechanisms are ready to rehearse. | Clean repo, release hygiene, v1.5 artifact freshness, targeted backend tests, frontend source/rendered evidence where applicable. | Public beta, public validator safety, public BFT, mainnet, live economics, automatic upgrades, production helper execution, legal clearance. |
| Tier B | Public observer testnet | A normal external tester can open-download/clone, verify trust roots, boot observer mode, sync state, load the frontend, understand their role, and submit or forward transactions with honest lifecycle status. | External open-download transcript, branch/commit, install log, trust-root and seed-registry verification, observer boot, chain identity, state sync, frontend rendered journey, tx forwarding or honest fail-closed result. | Public validator safety, public BFT, mainnet, live economics, automatic upgrades, production helper execution, legal clearance, public storage-market readiness. |
| Tier C | Controlled validator rehearsal | Invited operators can rehearse node-operator and validator-candidate flows while authority boundaries remain fail-closed. | Independent/operator transcript, validator-candidate readiness receipts, activation rehearsal, restart/fail-closed evidence, observer cannot bypass validator authority. | Public permissionless validator safety, public BFT, mainnet, live economics, automatic upgrades, legal clearance. |
| Tier D | Public validator beta / mainnet hardening | Future hardening target for public validator, storage, helper, upgrade, economics, and legal/compliance readiness. | Counsel attestation, independent multi-operator BFT proof, executable upgrade staging/rollback proof, real storage/IPFS operator transcript, production helper safety proof, public network evidence. | Mainnet or live economics until every applicable gate is satisfied. |

## Current repository classification

The current blocker catalog preserves 14 entries for audit continuity. Seven are
closed by repository evidence. Seven remain open and continue to block public
beta claims.

| Blocker | Current class | Tier that can close it | Closure evidence |
| --- | --- | --- | --- |
| `AUD-618-P0-001` | External evidence / future public validator hardening | Tier C can reduce; Tier D closes public-validator beta claim | Independent public validator/operator transcript with fresh checkout, operator-signed transcript, validator-candidate activation rehearsal, restart/fail-closed proof, and transcript digest replay. |
| `AUD-618-P0-002` | Legal/compliance attestation | Tier D | Counsel-reviewed attestation covering launch claims, token/economics disabled state, governance claims, public-only content posture, treasury/staking/fees disabled matrix, and compliance limitations. |
| `AUD-618-P0-003` | Future executable upgrade hardening | Tier D | Signed upgrade artifact manifests, deterministic migration vectors, rollback semantics, operator approval policy, staged multi-node rollout and rollback transcript. Current implementation remains record-only. |
| `AUD-618-P1-003` | External replay evidence | Tier B can reduce; Tier D/public beta package should close or explicitly defer | External machine or two-physical-machine replay transcript proving identical state roots, vectors, and tx index hash on the same commit. |
| `AUD-618-P1-004` | Real storage/IPFS operator evidence | Tier D | Real daemon/operator transcript with publish, retrieve, wrong/corrupt content rejection, durability proof, and bounded storage-market claims. |
| `AUD-618-P1-005` | Production helper topology hardening | Tier D | Production helper enablement gate, serial equivalence, deterministic assignment/lane ordering/merge, crash-safety, Byzantine-output rejection, and multi-node adversarial proof. |
| `AUD-628-P1-001` | External public observer journey evidence | Tier B | External open-download/clean-clone transcript with dependency install, trust-root verification, signed seed registry verification, observer boot, chain identity check, state sync, frontend rendered operator journey, and tx forwarding or honest fail-closed behavior. |

## Flow readiness classification framework

Every launch-prep pass should classify each flow as one of:

- complete and tested;
- frontend readable but needs rendered test;
- backend implemented but UX incomplete;
- docs incomplete;
- external evidence required;
- unsafe/not ready.

The strongest allowed claim is determined by the weakest critical flow. Local
source tests can close repository UX/documentation gaps. They cannot close
external evidence, counsel attestation, real-operator, or future mainnet
hardening gates.

## Canonical next external transcript: public observer open-download journey

The next evidence package should target `AUD-628-P1-001`. It must be captured on
a machine not controlled by the founder, or it must be explicitly labeled local
practice evidence and kept open.

### Transcript metadata

Record these fields at the top of the transcript:

```text
operator_name_or_handle: <external tester>
machine_owner: <external tester / organization>
os_and_version: <example: Ubuntu 24.04 / Windows WSL2 Ubuntu 24.04>
network_type: <home ISP / mobile hotspot / shelter Wi-Fi / VPS>
repo_url: <clone URL>
branch: <branch used>
commit: <git rev-parse HEAD>
transcript_started_utc: <ISO timestamp>
transcript_completed_utc: <ISO timestamp>
claim_boundary: public observer transcript only; not public beta, mainnet, public validator, live economics, automatic upgrade, or production helper readiness
```

### Command checklist

Run from a clean directory on the external machine:

```bash
set -euo pipefail

mkdir -p ~/weall-transcripts
TRANSCRIPT="$HOME/weall-transcripts/public-observer-open-download-$(date -u +%Y%m%d-%H%M%S).txt"
exec > >(tee -a "$TRANSCRIPT") 2>&1

date -u
uname -a || true
python3 --version
node --version || true
npm --version || true

rm -rf ~/WeAll-Protocol-external-observer
# Replace this URL with the reviewed repository URL for the selected branch.
git clone <REPO_URL> ~/WeAll-Protocol-external-observer
cd ~/WeAll-Protocol-external-observer

git rev-parse --abbrev-ref HEAD
git rev-parse HEAD
git status --short

cd Weall-Protocol
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r requirements-dev.lock
python3 -m pip install -e .

PYTHONPATH=src python scripts/check_v15_public_readiness_artifacts.py
PYTHONPATH=src python scripts/check_release_hygiene_v1_5.py
PYTHONPATH=src python scripts/verify_public_seed_registry_signature_v1_5.py --check || true
PYTHONPATH=src python -m pytest -q \
  tests/prod/test_public_testnet_v1_chain_identity.py \
  tests/prod/test_public_observer_checked_in_registry_primary.py \
  tests/prod/test_public_observer_provider_not_authority.py \
  tests/prod/test_public_observer_seed_discovery.py \
  tests/prod/test_public_observer_registry_auto_dial.py \
  tests/prod/test_observer_cannot_enable_validator_signing.py

WEALL_PUBLIC_TESTNET=1 bash scripts/boot_public_observer_testnet.sh || true

cd ../web
npm install
npm run typecheck
npm run build
node scripts/test_node_dashboard_source.mjs
node scripts/test_step9_p2_ux_source.mjs
node scripts/test_rendered_civic_loop_source.mjs

echo "TRANSCRIPT=$TRANSCRIPT"
```

Notes:

- If a command is allowed to fail for environmental reasons, the transcript must
  explain whether the result is an honest fail-closed outcome or a setup issue.
- The transcript must not treat seed registry hints, frontend state, local
  scripts, or environment flags as protocol authority.
- A local founder-run transcript may improve the runbook, but it must not close `AUD-628-P1-001`.

## Reviewer package required for Tier B

A Tier B package should contain:

1. the external transcript text;
2. the exact branch and commit;
3. a short machine/network note;
4. the generated blocker report showing public beta still false;
5. screenshots or captured output for frontend load and node/operator role
   surfaces where available;
6. a summary of any skipped or failed commands;
7. an explicit statement that public beta/mainnet/public BFT/live economics are
   not claimed.

## Current non-claims

This plan does not claim:

- public beta readiness;
- public mainnet readiness;
- public multi-validator BFT readiness;
- public validator safety;
- live economics readiness;
- automatic protocol upgrade readiness;
- production helper execution readiness;
- legal/compliance approval;
- public storage-market readiness;
- complete anti-Sybil/collusion detection;
- complete public identity infrastructure.

## Verification commands for this plan

```bash
cd ~/WeAll-Protocol/Weall-Protocol
source .venv/bin/activate

PYTHONPATH=src python -m pytest -q tests/prod/test_public_observer_testnet_readiness_docs.py
PYTHONPATH=src python scripts/check_v15_public_readiness_artifacts.py
PYTHONPATH=src python scripts/check_release_hygiene_v1_5.py
```
