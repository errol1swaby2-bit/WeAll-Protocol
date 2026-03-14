# Monday External Tester Release Checklist

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
- `Weall-Protocol/cloudflare/email_oracle/.dev.vars`
- `web/.env.local`

## 2. Verify canonical startup path still works

Backend from the repository root:

```bash
./scripts/quickstart_tester.sh
```

Frontend:

```bash
cd web
cp .env.example .env.local
npm ci
npm run dev -- --host 127.0.0.1 --port 5173
```

Demo bootstrap:

```bash
cd Weall-Protocol
./scripts/demo_bootstrap_tester.sh
```

## 3. Verify browser-visible demo

Confirm all of the following:

- `http://127.0.0.1:8000/v1/readyz` returns success
- `http://127.0.0.1:8000/docs` loads
- `http://127.0.0.1:5173` loads
- the printed demo account exists in the UI
- the printed demo post body is visible in the feed

## 4. Verify documentation matches reality

Check that these files all describe the same startup path:

- `README.md`
- `Weall-Protocol/README.md`
- `Weall-Protocol/docs/testnet_runbook.md`

## 5. Verify environment examples are present

Confirm these files exist and are current:

- `.env.example`
- `Weall-Protocol/.env.example`
- `web/.env.example`

## 6. Known release policy

For Monday, the supported walkthrough is:

- backend via Docker Compose
- frontend via Vite dev server
- demo state via `scripts/demo_bootstrap_tester.sh`

Do not claim that browser email onboarding is part of the required tester flow unless the local email oracle has been included and documented in the same quickstart path.
