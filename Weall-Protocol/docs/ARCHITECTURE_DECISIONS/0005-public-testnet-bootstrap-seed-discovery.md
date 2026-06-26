# ADR 0005: Public testnet bootstrap and seed discovery

## Context

New observers need a way to find the genesis node or other safe verified nodes. The repository must avoid treating any hosting provider, DNS name, or CDN as protocol authority.

## Decision

Public-testnet discovery is based on checked-in chain commitments, signed seed registries, pinned registry signer keys, and signed validator endpoint advertisements. Providers publish bytes; signatures and protocol state define trust.

## Rationale

This makes bootstrap reviewable and portable across hosting providers while preserving a concrete operator path for public observers.

## Consequences

- Registry signatures and chain commitments are required for public observer discovery claims.
- Unsigned endpoint hints must not be treated as verified validator authority.
- Runtime launch transcripts should be generated only after real registry/signing material is published.

## Safety implications

Provider independence reduces operational capture risk, but operators still need clear NAT/firewall/TLS recovery guidance and signed-registry hygiene.

## Enforcement references

- `Weall-Protocol/src/weall/api/public_seed_registry.py`
- `Weall-Protocol/src/weall/api/routes_nodes.py`
- `Weall-Protocol/generated/public_discovery_provider_independence_v1_5.json`
- `Weall-Protocol/docs/PUBLIC_OBSERVER_TESTNET_QUICKSTART.md`
- `Weall-Protocol/docs/PUBLIC_REGISTRY_SIGNER_OPERATIONS.md`
