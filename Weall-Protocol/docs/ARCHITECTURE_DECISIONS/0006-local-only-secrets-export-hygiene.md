# ADR 0006: Local-only secrets and release export hygiene

## Context

Node operators and registry signers need private keys and runtime state locally. Those files must never become part of public repository history or release archives.

## Decision

Secrets, private keys, local runtime databases, node state, media caches, build output, dependency directories, and test caches are local-only. Release/export checks must fail when dangerous files are tracked or staged.

## Rationale

Reviewer/operator trust depends on the repository being safe to clone and share. A release archive that includes founder-local keys, runtime state, caches, or generated scratch files would undermine that trust.

## Consequences

- `secrets/`, `.secrets/`, `.weall-dev/`, `.weall-devnet/`, media caches, SQLite files, `node_modules/`, `.venv/`, and cache/build outputs stay ignored.
- `scripts/secret_guard.sh` remains a release gate.
- Clean-clone and clean-export checks are preferred over in-place founder checkout validation.

## Safety implications

This protects operators and reviewers from accidental key disclosure and prevents runtime artifacts from masquerading as source or release evidence.

## Enforcement references

- `.gitignore`
- `Weall-Protocol/scripts/secret_guard.sh`
- `Weall-Protocol/scripts/clean_local_artifacts.sh`
- `scripts/build_clean_release_export.sh`
- `RELEASE_CHECKLIST.md`
