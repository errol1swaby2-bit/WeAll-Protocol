# Dependency locking

This repository uses committed dependency locks as part of the release posture.

## Runtime/backend locks

Backend release locks live in:

```text
requirements.lock
requirements-dev.lock
```

They are generated from:

```text
requirements.in
requirements-dev.in
```

Generate or refresh them with:

```bash
python -m pip install pip-tools
bash scripts/lock_deps.sh
```

Verify them with:

```bash
bash scripts/verify_lockfiles.sh
```

The verifier requires pinned `name==version` entries and `--hash=sha256:` hashes.

## Frontend lock

Frontend release locking uses:

```text
../web/package-lock.json
```

Generate or refresh it from the repository root frontend directory:

```bash
cd ../web
npm install --package-lock-only
npm ci
```

## Combined release check

From `Weall-Protocol/`:

```bash
bash scripts/verify_release_dependencies.sh
```

This check must pass before public operator packaging.

## Development workflow

For local backend development, use a virtual environment and editable install as needed:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -e '.[test]'
pytest -q
```

Editable installs are for development only. Public release packaging must use the committed lockfiles.
