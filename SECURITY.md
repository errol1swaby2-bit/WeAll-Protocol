# Security Policy

WeAll is a protocol and node implementation, so security reports may involve consensus safety, deterministic execution, state sync, API exposure, identity gates, or local operator tooling.

## Supported branch

Security review should target the default branch unless a maintainer explicitly asks for a different branch or release snapshot.

## Please report privately

Do not open public GitHub issues containing exploitable security details.

Preferred reporting path:

1. Use GitHub's private vulnerability reporting flow for this repository when available.
2. If private vulnerability reporting is unavailable, open a minimal public issue that says you need a private security contact, without including exploit details.
3. Include enough non-sensitive context for a maintainer to route the report.

## What to include

A useful report includes:

- affected commit or branch
- affected component
- reproduction steps
- expected behavior
- actual behavior
- potential impact
- whether the issue affects consensus, state roots, signature validation, replay protection, PoH gates, state sync, API auth, local secrets, or frontend session handling

## High-priority categories

Please report issues involving:

- consensus divergence
- non-deterministic state roots
- block replay inconsistencies
- invalid transaction admission
- replay protection bypass
- signature verification bypass
- unsafe system-origin transaction acceptance
- state sync anchor bypass
- PoH tier escalation without required proof
- committed secrets or private keys
- remote code execution
- authentication or authorization bypass

## Local devnet artifacts

Controlled-devnet files, generated demo output, local databases, lock files, `.env` files, and runtime secrets should not be committed. If you find one in the tracked tree, report it.

## Disclosure posture

Security issues should be fixed and regression-tested before public disclosure. Public writeups should avoid publishing working exploit details until users and operators have had reasonable time to update.
