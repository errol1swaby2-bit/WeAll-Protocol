# ADR 0003: Public group visibility with member-gated participation

## Context

Groups are civic subspaces. They need participation boundaries, but protocol-native group content must remain inspectable.

## Decision

Protocol-native group content is publicly readable. Group membership may gate participation rights such as posting, commenting, voting, moderation, invitation, and administration. Membership must not gate read visibility of protocol-native group posts or civic actions.

## Rationale

This preserves open review of civic/group state while still allowing groups to manage who participates in their internal governance and moderation flows.

## Consequences

- Non-public group creation and member-only read visibility are rejected.
- Group posts are stored with public read posture.
- Non-members can read group content but cannot necessarily comment or vote.

## Safety implications

This keeps public civic visibility intact while avoiding accidental exposure of raw PoH evidence, recovery secrets, or local node secrets.

## Enforcement references

- `Weall-Protocol/src/weall/runtime/apply/groups.py`
- `Weall-Protocol/src/weall/runtime/apply/content.py`
- `Weall-Protocol/tests/test_public_only_protocol_redesign.py`
- `Weall-Protocol/docs/PUBLIC_ONLY_PROTOCOL.md`
