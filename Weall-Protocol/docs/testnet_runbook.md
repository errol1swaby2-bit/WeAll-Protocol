# Local Tester Runbook

This runbook is the operator-facing version of the external tester quickstart.

## Canonical path

Use only this sequence for the tester release:

1. from the repository root run `./scripts/quickstart_tester.sh`
2. from `web/` run the Vite frontend
3. from `Weall-Protocol/` run `./scripts/demo_bootstrap_tester.sh`

## Commands

Backend from the repository root:

```bash
./scripts/quickstart_tester.sh
```

Frontend in a second terminal:

```bash
cd web
cp .env.example .env.local
npm ci
npm run dev -- --host 127.0.0.1 --port 5173
```

Demo bootstrap in a third terminal:

```bash
cd Weall-Protocol
./scripts/demo_bootstrap_tester.sh
```

## Verification

Check all of the following:

- `curl http://127.0.0.1:8000/v1/readyz`
- `curl http://127.0.0.1:8000/v1/status`
- open `http://127.0.0.1:8000/docs`
- open `http://127.0.0.1:5173`
- confirm the printed demo post appears in the feed
- confirm the printed demo account appears in the UI

## Notes

- email-oracle onboarding is optional and not part of the required tester path
- `generated/tx_index.json` is created automatically by the backend helper
- founder-local files must be removed before release with `Weall-Protocol/scripts/clean_local_artifacts.sh`
