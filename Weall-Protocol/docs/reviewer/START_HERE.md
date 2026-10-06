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

## 3. Fresh-clone smoke

**Use when:** you want to test whether a clean clone can install and execute the advertised smoke path.

Script: `scripts/fresh_clone_smoke.sh`.

For reviewer evidence, the smoke must be bound to an explicit commit/ref and must execute both backend and frontend verification. A smoke that follows moving default-branch HEAD or skips frontend verification is convenience evidence only, not exact-commit full-stack proof.

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
