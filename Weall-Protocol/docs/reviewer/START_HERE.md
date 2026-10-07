# Reviewer verification: start here

This page is the canonical front door for external technical review of the WeAll Protocol repository.

The repository contains several useful startup and verification paths. They are **not equivalent evidence**. Choose the path that matches the question you are trying to answer.

## 1. Exact reviewer-readiness verification

**Use when:** you want the closest local reproduction of the repository's Reviewer Readiness and Backend CI evidence for a specific commit.

**Required source form:** a **full-history Git clone** checked out at the exact commit under review. A GitHub source tarball or `git archive` is not equivalent because historical M2/M3 evidence provenance is restored from Git history.

**Identity first:**

```bash
git rev-parse HEAD
git rev-parse HEAD^{tree}
git status --short --branch
```

Then follow the locked install and reviewer gate documented by the repository and compare the resulting commit/tree with the review target.

**What this proves:** current source/install/test/readiness gates plus the repository's history-backed evidence checks for that exact checkout.

**What this does not prove:** mainnet readiness, public-beta readiness, independent cryptographic review, or closure of findings not marked closed in the current audit/claims artifacts.

## 2. Historyless source-archive verification

**Use when:** you received a source tarball or `git archive` with no `.git` directory.

You may run archive-compatible source/generated checks such as the V2 clean-checkout verifier and release-tree checks, but you **cannot reproduce the full history-backed reviewer procedure** from that archive alone.

A passing archive check is therefore not equivalent to the full-history Reviewer Readiness gate.

### Reproducibility levels and non-claims

The repository intentionally separates three reproducibility levels:

1. **Dependency-reproducible application install.** Python runtime/dev application dependencies are installed from hash-locked requirements files, and the frontend uses `npm ci` against its lockfile.
2. **Source-archive derivative reproducibility.** `check_v2_spec_clean_checkout.py` proves that committed V2 derivatives reproduce from a clean `git archive` **under the already-provisioned interpreter/toolchain used to run the checker**.
3. **Full reviewer provenance reproduction.** Reviewer Readiness additionally requires a full-history clone because historical evidence objects are verified by exact Git commit identity.

The repository does **not** claim byte-for-byte clean-machine, container, or complete toolchain hermeticity. Current build/rehearsal inputs still include symbolic external selectors such as the Python base-image tag, Kubo/Alpine image tags, Python/Node version families, and GitHub Action major-version refs. Those inputs are outside the source-archive derivative proof.

Accordingly:

- “clean checkout” means **source archive consistency under an already-provisioned toolchain**;
- it does not mean that the Git tree alone fixes every external tool or container byte;
- a future byte-for-byte reproducible-build claim requires separately pinning the relevant external artifacts and proving independent clean-environment equivalence.

## 3. Fresh-clone smoke

**Use when:** you want to test whether a clean clone can install and execute the advertised smoke path.

Script: `scripts/fresh_clone_smoke.sh`.

For reviewer evidence, the smoke requires `WEALL_FRESH_CLONE_COMMIT` set to the exact 40-hex commit under review and executes both backend and frontend verification. A smoke that follows moving default-branch HEAD or skips frontend verification is convenience evidence only, not exact-commit full-stack proof.

## 4. External observer / onboarding node

**Use when:** you want to run a non-authoritative observer/onboarding node.

Start with:

- `Weall-Protocol/docs/testnet/PUBLIC_OBSERVER_QUICKSTART.md`
- `Weall-Protocol/docs/TESTER_ONE_COMMAND_NODE_BOOT.md`

These paths test node onboarding and observer behavior. They are not substitutes for Reviewer Readiness, consensus-validator qualification, or production/mainnet certification.

## 5. Local developer/demo flows

Developer boot scripts, demo seeding, golden-path scripts, and local web flows are useful for feature testing.

They are **not reviewer-readiness evidence** unless the relevant exact-commit verification gate explicitly consumes them.

## Decision table

| Goal | Required path | Full Git history required? | Exact commit required? | Frontend required? | Equivalent to Reviewer Readiness? |
| --- | --- | ---: | ---: | ---: | ---: |
| Exact technical review | Full-history clone + Reviewer Readiness/Backend gates | Yes | Yes | Yes where the permanent gate requires it | Yes, when all required gates pass |
| Source-archive integrity | Archive-compatible generated/release checks | No | Archive identity must be recorded | No | No |
| Fresh-machine smoke | `scripts/fresh_clone_smoke.sh` with explicit review ref | Clone created by script | Yes for reviewer evidence | Yes for full-stack evidence | No |
| External observer test | Public-observer / tester-node runbook | No special historical requirement | Pin the release/commit being tested | Optional unless the runbook claims web coverage | No |
| Local development | Dev/demo scripts | No | No | Optional | No |

## Current truth sources

For current claims and known limitations, prefer generated/current artifacts and the active audit closure matrix over historical prose:

- `Weall-Protocol/generated/current_verified_claims.json`
- `Weall-Protocol/docs/CURRENT_VERIFIED_CLAIMS.md`
- `audit-metadata/p1-revalidation-after-p0-20261005/MATRIX.json`
- `Weall-Protocol/docs/reviewer/EVIDENCE_INDEX.md`

If two documents appear to conflict, the exact checked-out source tree, generated-current checks, and active finding matrix define the review boundary; historical evidence remains evidence for the historical commit it identifies.
