# Batch 313 — Production Dependency Locking Posture

## Purpose

Batch 313 makes dependency reproducibility an explicit release gate for public operator packaging.

The backend already has lockfile-generation and lockfile-verification scripts. Batch 313 adds a combined verifier and pins frontend dependency declarations to exact versions so the committed `package-lock.json` can be generated and reviewed deterministically.

## Required release artifacts

Before public operator release, the repo must contain:

```text
Weall-Protocol/requirements.lock
Weall-Protocol/requirements-dev.lock
web/package-lock.json
```

## Generate backend lockfiles

From `Weall-Protocol/Weall-Protocol`:

```bash
python -m pip install pip-tools
bash scripts/lock_deps.sh
bash scripts/verify_lockfiles.sh
```

The backend verifier requires pinned `name==version` entries and `--hash=sha256:` hashes.

## Generate frontend lockfile

From `WeAll-Protocol/web`:

```bash
npm install --package-lock-only
npm ci
npm run typecheck
npm run contract-check
npm run build
```

## Combined release verifier

From `Weall-Protocol/Weall-Protocol`:

```bash
bash scripts/verify_release_dependencies.sh
```

The combined verifier checks backend lockfiles and the frontend npm lockfile, but it does not fabricate dependency locks. Real locks must be generated in a networked local/CI environment and committed after review.

## Release posture

Until these files are committed and verified, the protocol may be considered a local/devnet implementation artifact under active hardening, but not fully public-operator-packaged.
