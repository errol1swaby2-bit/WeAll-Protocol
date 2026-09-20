# Current testnet readiness statement

Status: bounded public observer / pre-public-testnet hardening framing; controlled-testnet mechanism completion is NO-GO.

This is the canonical current-state statement for the repository. It must be read together with:

- `generated/public_beta_blocker_report_v1_5.json`;
- `generated/controlled_testnet_go_gate_v1_5.json`;
- `docs/reviewer/PUBLIC_BETA_BLOCKER_STATUS.md`;
- `docs/audits/public_observer_testnet_readiness_plan_v1_5.md`.

## Current allowed claim

WeAll is a pre-public-testnet implementation under active hardening with a conservative public-beta blocker
inventory. The repository evidence supports continued bounded local/devnet/public-observer preparation, but
controlled-testnet mechanism completion remains NO-GO until production helper state-root/restart equivalence
is proven. Public beta remains unclaimed until all still-open external evidence and mainnet-hardening gates are
satisfied.

If the external public observer transcript has not been captured yet, the
strongest allowed claim is:

> Pre-public-testnet protocol implementation under active hardening, with local/devnet/public-observer-oriented evidence present and public
> beta readiness still blocked by explicit external evidence gates.

## Current blocker count semantics

The blocker catalog and open/closed totals are generated facts, not durable prose facts.
Read the current values directly from `generated/public_beta_blocker_report_v1_5.json`
and the final go-gate artifact. This document intentionally does not duplicate numeric
counts. `public_beta_ready` must remain `false` while any still-open blocker remains.

## Readiness tier summary

- Tier A — controlled local verification testnet: repository hygiene, deterministic
  artifact checks, public-only/economics-off boundaries, and local verification
  flows.
- Tier B — public observer testnet: external open-download observer transcript,
  state sync, frontend rendered journey, honest transaction lifecycle, and every
  generated blocker required before public-observer wording, including the
  post-transition cryptographic-review gate.
- Tier C — controlled validator rehearsal: invited operator/validator-candidate
  rehearsal with authority boundaries fail-closed.
- Tier D — public validator beta / mainnet hardening: counsel attestation,
  public BFT/operator proof, executable upgrade proof, real storage proof,
  production helper proof, independent cryptographic review, and public network hardening.

## Remaining blockers by tier

| Blocker | Required tier/evidence |
| --- | --- |
| `AUD-628-P1-001` | Tier B external public observer open-download/state-sync/rendered journey transcript. |
| `AUD-618-P1-003` | Tier B or later external/two-machine replay transcript proving identical state roots and tx index hash. |
| `AUD-618-P0-001` | Tier C rehearsal can reduce; Tier D/public validator evidence needed before public validator safety claims. |
| `AUD-618-P0-002` | Tier D counsel attestation. |
| `AUD-618-P0-003` | Tier D executable protocol upgrade staging/rollback proof. |
| `AUD-633-P0-004` | Fresh profile-aware post-transition rehearsal evidence, browser/local signing-boundary review, helper/evidence-signing production gate, and external cryptographic review before public-observer or long-lived public-network claims. |
| `AUD-618-P1-004` | Tier D real storage/IPFS operator transcript. |
| `AUD-618-P1-005` | Tier D production helper topology enablement proof. |

## What is currently unclaimed

The repository must not claim:

- public beta readiness;
- public mainnet readiness;
- public multi-validator BFT readiness;
- public validator safety;
- live economics readiness;
- automatic software upgrade readiness;
- executable migration/rollback readiness;
- production helper execution readiness;
- legal/compliance approval;
- public storage-market readiness;
- completed production cryptographic audit or production post-quantum security;
- unconditional or universal post-quantum security;
- complete anti-Sybil/collusion detection;
- complete public identity infrastructure.

## Next recommended evidence passes

Two current external-evidence tracks must remain visible:

1. `AUD-628-P1-001` — capture the external public-observer open-download/state-sync/rendered journey transcript.
2. `AUD-633-P0-004` — capture fresh profile-aware post-transition rehearsal evidence and obtain the independent cryptographic review required by the generated blocker report.

The observer checklist is maintained in
`docs/audits/public_observer_testnet_readiness_plan_v1_5.md` under “Canonical
next external transcript.” Founder-run local rehearsal can improve scripts or
documentation, but it must not close either external blocker.

## Verification

```bash
cd ~/WeAll-Protocol/Weall-Protocol
source .venv/bin/activate

PYTHONPATH=src python -m pytest -q tests/prod/test_public_observer_testnet_readiness_docs.py
PYTHONPATH=src python scripts/check_v15_public_readiness_artifacts.py
PYTHONPATH=src python scripts/check_release_hygiene_v1_5.py
```

## Current final go-gate package

The final repository-side go-gate package is maintained in `generated/final_public_observer_controlled_testnet_go_gate_v1_5.json`, `docs/reviewer/EVIDENCE_INDEX.md`, `docs/reviewer/CURRENT_READINESS_STATEMENT.md`, `docs/testnet/PUBLIC_OBSERVER_QUICKSTART.md`, `docs/testnet/TESTNET_LAUNCH_CHECKLIST.md`, and `docs/testnet/FINAL_PUBLIC_OBSERVER_CONTROLLED_TESTNET_GO_GATE.md`.

The current verdict is NO-GO for controlled-testnet mechanism completion because production helper state-root/restart equivalence is not yet proven. Bounded local/devnet/public-observer-oriented rehearsal remains available; public beta, public observer launch claims, mainnet, public validator/BFT, live economics, automatic upgrades, production helpers, legal approval, and public storage-market readiness remain NO-GO until their gates are satisfied.
