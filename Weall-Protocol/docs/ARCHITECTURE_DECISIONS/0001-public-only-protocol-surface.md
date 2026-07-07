# ADR 0001: Public-only protocol surface

## Context

WeAll includes social, civic, governance, moderation, dispute, group, reputation, validator/operator, and protocol-state activity. These surfaces influence shared civic state and must be inspectable by observers and reviewers.

## Decision

All protocol-native civic/social activity that can affect protocol state is publicly inspectable. The protocol does not provide hidden consensus-affecting social or civic content.

## Rationale

Public inspectability keeps moderation, dispute review, group governance, validator/operator actions, and reputation effects accountable. It also prevents the protocol from becoming a native shelter for opaque social coordination while still allowing sensitive Proof-of-Humanity evidence to be protected by separate evidence-handling boundaries.

## Consequences

- Public-only applies to protocol-native content and civic state, not raw identity documents or recovery secrets.
- Opaque encrypted payloads that affect civic/social outcomes are rejected.
- Reviewers can audit social/civic state without privileged group membership.

## Safety implications

This reduces hidden consensus-affecting activity, but it requires careful redaction of sensitive PoH/session/device/evidence internals at public API boundaries.

## Enforcement references

- `Weall-Protocol/src/weall/runtime/public_protocol_policy.py`
- `Weall-Protocol/tests/test_public_only_protocol_redesign.py`
- `web/scripts/test_public_only_protocol_source.mjs`
- `Weall-Protocol/generated/public_only_protocol_audit_v1_5.json`
