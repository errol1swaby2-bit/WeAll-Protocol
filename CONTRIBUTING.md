# Contributing to WeAll Protocol

Thanks for taking the time to review or contribute to WeAll.

WeAll is a protocol implementation, not only an application surface. Contributions should preserve deterministic execution, fail-closed validation, and clear separation between product UX and protocol authority.

## Contribution principles

A contribution should be easy to review and safe to replay.

Prefer changes that are:

- deterministic across machines and restarts
- explicit about validation and rejection behavior
- covered by tests
- small enough to audit
- clear about whether they affect consensus, execution, API shape, frontend UX, or local tooling

## Before opening a pull request

Run the relevant checks locally.

Backend:

```bash
cd Weall-Protocol
source .venv/bin/activate
pytest
```

Targeted controlled-devnet proof:

```bash
cd Weall-Protocol
source .venv/bin/activate
PYTHONPATH=src pytest -q tests/test_devnet_email_tier1_harness_batch210.py
WEALL_EMAIL="you@example.com" bash scripts/devnet_full_onboarding_e2e.sh
```

Frontend:

```bash
cd web
npm ci
npm run typecheck
npm run contract-check
npm run build
```

Release hygiene:

```bash
cd Weall-Protocol
./scripts/clean_local_artifacts.sh
```

## Pull request expectations

A useful pull request should include:

- a clear summary of what changed
- why the change is needed
- tests that were run
- any affected transaction types, API routes, or state fields
- any known limitations or follow-up work

For protocol-facing changes, include the expected safety property. Examples:

- replay protection is preserved
- state roots remain deterministic
- helper execution remains serial-equivalent
- admission fails closed
- system-origin transactions remain explicitly gated
- local runtime artifacts are not committed

## Determinism rules

Avoid introducing behavior that depends on:

- wall-clock time in consensus or execution paths
- randomness without deterministic seeding and protocol binding
- unordered dict or set iteration where order affects state
- floating point arithmetic in canonical state transitions
- environment variables that can change consensus-critical behavior after startup

If a value must vary by environment, keep it outside canonical execution or bind it into an explicit startup/runtime profile.

## Security-sensitive changes

Do not include secrets, private keys, personal credentials, local database files, `.env` files, or generated devnet runtime state in commits.

Do not open public issues with exploitable security details. Use `SECURITY.md`.

## License

By contributing, you agree that your contribution is provided under the Mozilla Public License 2.0, the same license that governs this repository.
