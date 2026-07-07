# Generated Artifact Index

This repository keeps generated JSON evidence under `Weall-Protocol/generated/`. The directory is intentionally committed because reviewers need stable, inspectable proof artifacts without rerunning every long rehearsal. These files are still generated outputs: update them through canonical scripts, not manual edits.

## Release-blocking freshness checks

Run these from `Weall-Protocol/` before publishing reviewer/operator materials:

```bash
PYTHONPATH=src python scripts/check_v15_public_readiness_artifacts.py
PYTHONPATH=src python scripts/check_release_hygiene_v1_5.py
```

If either command reports a stale artifact, find the corresponding generator in `scripts/`, rerun it, rerun it a second time, and confirm `git diff` does not change on the second run.

## Canonical release evidence

These artifacts are part of the current reviewer/release surface and should remain fresh:

| Artifact | Purpose | Usual producer/check |
| --- | --- | --- |
| `api_contract_map_v1_5.json` | Public API contract map used by docs, tests, and frontend contract review. | `scripts/gen_api_contract_map.py`; `scripts/check_v15_public_readiness_artifacts.py` |
| `failure_code_registry_v1_5.json` | Stable error/failure-code registry for release review. | `scripts/gen_failure_code_registry_v1_5.py`; release hygiene check |
| `release_evidence_manifest_v1_5.json` | Top-level release evidence manifest tying generated proof files together. | `scripts/gen_release_evidence_manifest_v1_5.py`; release hygiene check |
| `public_beta_blocker_report_v1_5.json` | Public-beta blocker truth source; must not hide unresolved blockers. | `scripts/gen_public_beta_blocker_report_v1_5.py`; readiness checks |
| `public_only_protocol_audit_v1_5.json` | Evidence for the public-only protocol redesign and unsupported private surfaces. | public-only audit generator/tests; readiness checks |
| `public_discovery_provider_independence_v1_5.json` | Evidence that discovery trust is signature/commitment based, not provider based. | provider-independence generator/tests |
| `public_observer_launch_evidence_requirements_v1_5.json` | Public observer launch evidence requirements. | `scripts/gen_public_observer_launch_evidence_requirements_v1_5.py --check` |
| `public_frontend_operator_journey_v1_5.json` | Frontend operator journey evidence for public observer/testnet surfaces. | `scripts/gen_public_frontend_operator_journey_v1_5.py --check` |
| `public_registry_signer_operations_v1_5.json` | Registry signer operational evidence and expectations. | `scripts/gen_public_registry_signer_operations_v1_5.py --check` |
| `public_validator_endpoint_churn_proof_v1_5.json` | Validator endpoint freshness/churn proof for discovery. | `scripts/gen_public_validator_endpoint_churn_proof_v1_5.py --check` |
| `state_root_vectors_v1_5.json` | Deterministic state-root evidence vectors. | state-root generator/tests |
| `tx_index.json` | Canonical transaction index generated from schema/canon sources. | `scripts/gen_tx_index.py`; tx-canon checks |
| `tx_contract_map.json` | Transaction contract map used by tx coverage/review surfaces. | tx-contract generator/checks |
| `v15_implementation_gap_register.json` | Current implementation gap register; must not be edited to conceal blockers. | gap-register generator/checks |

## Historical or batch-era evidence

Files with names such as `b499_b503_*`, `b572_b576_*`, or documents with `BATCH` in the title are retained as historical evidence from earlier hardening passes. They are not the preferred starting point for reviewers. Do not delete them unless a separate cleanup proves they are duplicated by a current domain-named artifact and all tests/docs have been updated.

## Deterministic regeneration rule

For every generator change or stale generated file:

```bash
cd Weall-Protocol
PYTHONPATH=src python scripts/<generator>.py
PYTHONPATH=src python scripts/<generator>.py
git diff -- generated/<artifact>.json
```

The second generator run should produce no additional diff. If the artifact depends on environment-specific runtime data, write the runtime output outside `generated/` unless it is explicitly part of the checked-in release evidence contract.

## What must not be generated here

Never commit these into `generated/` or any release/archive path:

- private keys, seed-registry signing keys, node identity private keys, or `.pem`/`.key` files;
- `secrets/` or `.secrets/` contents;
- local SQLite databases, journals, runtime state, media caches, or devnet directories;
- `.pytest_cache`, `__pycache__`, `node_modules`, `.venv`, coverage output, Playwright reports, or frontend build output.
