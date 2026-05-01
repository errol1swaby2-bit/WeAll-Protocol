# External Tester Release Checklist

Use this checklist before publishing the repository for external testers.

## 0. Fresh clone validation

Before publishing, validate from a clean directory that does not contain founder-local state:

```bash
git clone <repo-url> weall-fresh-test
cd weall-fresh-test
./scripts/quickstart_tester.sh
cd web
cp .env.example .env.local
npm ci
npm run dev -- --host 127.0.0.1 --port 5173
cd ../Weall-Protocol
./scripts/demo_bootstrap_tester.sh
```

Do not treat an in-place founder checkout as sufficient validation.

## 1. Clean founder-local artifacts

Run:

```bash
cd Weall-Protocol
./scripts/clean_local_artifacts.sh
```

Confirm none of these are staged:

- `Weall-Protocol/.env`
- `Weall-Protocol/.venv*`
- `Weall-Protocol/data/`
- `Weall-Protocol/generated/` runtime leftovers
- `Weall-Protocol/secrets/*`
- `web/.env.local`
- `.weall-dev/`
- `Weall-Protocol/.weall-devnet/`

## 2. Verify canonical startup path still works

Preferred full-stack path from the repository root:

```bash
./scripts/dev_boot_full_stack.sh
```

Manual backend path from the repository root:

```bash
./scripts/quickstart_tester.sh
```

Frontend:

```bash
cd web
cp .env.example .env.local
npm ci
npm run typecheck
npm run contract-check
npm run build
npm run dev -- --host 127.0.0.1 --port 5173
```

Demo bootstrap:

```bash
cd Weall-Protocol
./scripts/demo_bootstrap_tester.sh
```

Controlled-devnet non-seeded readiness proof:

```bash
cd Weall-Protocol
source .venv/bin/activate

pytest -q
WEALL_DEVNET_SUITE_RUN_TIER2=1 \
WEALL_DEVNET_SUITE_RUN_LIVE=1 \
bash scripts/devnet_controlled_readiness_suite.sh
```

## 3. Verify browser-visible demo

Confirm all of the following:

- `http://127.0.0.1:8000/v1/readyz` returns success
- `http://127.0.0.1:8000/docs` loads
- `http://127.0.0.1:5173` loads
- the printed demo account exists in the UI
- the printed demo post body is visible in the feed

## 4. Verify documentation matches reality

Check that these files all describe the same startup path and current proof posture:

- `README.md`
- `Weall-Protocol/README.md`
- `Weall-Protocol/docs/testnet_runbook.md`

The root README should only reference files that are actually tracked in this repository.

## 5. Verify environment examples are present

Confirm these files exist and are current:

- `.env.example`
- `Weall-Protocol/.env.example`
- `web/.env.example`

## 6. Verify public trust files are present

Confirm these files exist before broad external review:

- `LICENSE`
- `SECURITY.md`
- `CONTRIBUTING.md`
- `CODE_OF_CONDUCT.md`

## 7. Verify CI coverage

Confirm the repository has active GitHub Actions coverage for:

- backend lint, dependency audit, canon lint, generated-artifact check, tx coverage report, and pytest
- web install, typecheck, contract check, and build
- Native async/live PoH checks, including no required email, SMTP, DNS, Cloudflare, inbox, or external identity provider path

## 8. Known release policy

For external testers, the supported walkthrough is:

- backend via Docker Compose
- frontend via Vite dev server
- demo state via `scripts/demo_bootstrap_tester.sh` or the repository root `scripts/dev_boot_full_stack.sh`

For protocol reviewers, the supported non-seeded readiness proof is:

- `Weall-Protocol/scripts/devnet_controlled_readiness_suite.sh`
- `Weall-Protocol/scripts/devnet_full_onboarding_e2e.sh`

Browser onboarding and PoH verification are Cloudflare-free, email-free, and routed through the active WeAll API plus native async/live PoH surfaces. The controlled-devnet proof remains the protocol-native readiness path, while the default general tester flow may still use deterministic demo bootstrap for speed.

## 9. Current validated checkpoint

The current release checkpoint for this snapshot is:

- full backend suite: rerun locally before release
- tx canon artifacts: `225 tx types, version 1.24.0`
- `scripts/secret_guard.sh`: passed
- `scripts/verify_release_tree.sh`: passed
- Native PoH cleanup: primary path validated without email, SMTP, DNS, Cloudflare, relay-token completion, or external identity-provider env aliases

Before publishing, rerun:

```bash
cd Weall-Protocol
source .venv/bin/activate
pytest
python3 -S scripts/check_tx_canon_artifacts.py
bash scripts/secret_guard.sh
bash scripts/verify_release_tree.sh
```
