# ADR 0004: Observer-to-validator promotion model

## Context

Public operators need a safe way to boot observer nodes, discover the network, and eventually participate in validation. Local node configuration alone must not create validator authority.

## Decision

Observer mode is the safe default for public downloads. Validator/service signing is effective only when protocol state and runtime authority gates agree that the node is authorized. Endpoint advertisements, seed discovery, environment variables, and local config are not validator activation mechanisms by themselves.

## Rationale

Separating connectivity from authority prevents accidental or malicious validator activation. It also lets public observers join safely before they meet protocol-governed eligibility and responsibility requirements.

## Consequences

- Public observers can discover seeds and verified validator endpoints.
- Promotion remains protocol-gated.
- Startup checks must fail closed when raw environment variables request signing without effective authority.

## Safety implications

This protects consensus authority boundaries during public-testnet bootstrapping and external operator onboarding.

## Enforcement references

- `Weall-Protocol/scripts/boot_public_observer_testnet.sh`
- `Weall-Protocol/tests/prod/test_observer_cannot_enable_validator_signing.py`
- `Weall-Protocol/docs/CHOOSE_YOUR_NODE_MODE_QUICKSTART.md`
- `Weall-Protocol/docs/PROMOTED_OBSERVER_TO_VALIDATOR_RUNBOOK.md`
