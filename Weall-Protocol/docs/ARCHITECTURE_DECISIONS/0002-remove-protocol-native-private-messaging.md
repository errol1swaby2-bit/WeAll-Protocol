# ADR 0002: Remove protocol-native private messaging

## Context

Earlier prototype surfaces included private/direct messaging concepts. Those surfaces create ambiguity for public civic review and could imply protocol-native encrypted communication support.

## Decision

WeAll does not support protocol-native encrypted direct messages, private message threads, inbox/outbox semantics, or private social chat as protocol features. Compatibility requests to removed communication routes must fail deterministically rather than partially work.

## Rationale

A public civic protocol should not mix state-affecting social governance with hidden native communication channels. Removing these surfaces simplifies reviewer expectations and aligns the UI/API with the public-only rule.

## Consequences

- No `/messages` UI route or messaging rail is exposed.
- The frontend activity surface explains public notices instead of private communication.
- Removed transaction names are not canonical and are rejected as unknown/invalid.

## Safety implications

This does not prohibit users from communicating outside the protocol. It only prevents the protocol from providing native private messaging or treating encrypted social payloads as consensus-affecting civic content.

## Enforcement references

- `Weall-Protocol/tests/test_public_only_protocol_redesign.py`
- `web/scripts/test_public_only_protocol_source.mjs`
- `web/src/pages/Activity.tsx`
- `Weall-Protocol/generated/api_contract_map_v1_5.json`
