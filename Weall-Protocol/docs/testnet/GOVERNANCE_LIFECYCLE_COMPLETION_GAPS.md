# Governance lifecycle completion — bounded user journey, October 23, 2026

This is a dependent UX correction against PR #56, not a replacement for scope-authority and zero-ballot safety changes. The purpose is to make ordinary users understand the exact difference between **recorded decisions** and **authorized executable changes** and to stop showing client actions that the canonical runtime forbids.

## Implemented in this change

- The guided creator now defaults to **draft** (not unexplained immediate polling), with clear distinctions among deliberation, polling and final voting. The selection never promises that a browser can advance protocol time.
- Creation shows **record-only** status when it does not declare actions. Executable governance is a separate, bounded advanced protocol action, never a universal real-world or legal command. Title and description are required by the guided user interface.
- Proposal author edit controls appear only during **draft/revision**, not poll, validation, or frozen voting. Withdrawal remains available through open voting, but not after close/tally.
- Strict first-admitted ballots do not expose a valid revoke action. Preliminary polling does not count as having voted in a later final ballot; identity-choice associations may be redacted from strict public results.
- The decision detail explains the recorded tally, missing/no-decision state, and the distinction between a protocol execution and a mere vote/record; canonical Transactions and state remain authoritative.
- Public discovery now supports **Explore**, **Protocol-wide**, and **My groups in the visible public directory**, ranked using active public memberships. A group's name or location label grants zero territorial or other external authority.

## Known constraints and explicit nonclaims

1. **Pagination**: proposal and group lists are limited to 200; the visible-directory membership subset may omit valid groups. Neither “My groups” nor ranking confers actual voter or author privileges. Never report “not a member” based on absence from that subset.
2. **Permissions**: frontend controls only reflect common stage restrictions and cached account state. Canonical group membership, role status, ballot eligibility, scope and action allowlists are checked during signed backend apply. The frontend cannot promise acceptance.
3. **Ballot disclosure**: strict aggregate ballot mode intentionally redacts per-identity vote choices. Confirm inclusion and finality from authenticated transaction lifecycle evidence, not an optimistic submit or empty identity map.
4. **Non-passing tally closure**: inspect the non-approved tally path and ensure a canonical final terminal disposition instead of indefinitely displaying `tallied` without executable actions. This implementation makes the UI honest; it does not alter consensus stages.
5. **Ordinary executable proposals**: no guided workflow yet for crafting safe whitelisted action payloads, their scoped authorization, review and approval. General real-world execution, emissary external authority, software upgrades, migrations and economics activation are *not* implied.
6. **Proof**: mocked browser tests and green CI are not equivalent to two independently cloned nodes with independently signed create, comment, revise, vote, tally, approved/denied execute, receipts, crash/restart and deterministic state-root convergence.

## Further acceptance criteria

Demonstrate with distinct signer accounts and two independent nodes that a group member can create, comment and revise while an outsider cannot, that votes are frozen at the right stage with group electorate pinned, that a non-passing proposal terminates without execution, that an approved **whitelisted** effect is identical on both nodes, and that all public status, evidence, receipt and state roots survive restart. Validate errors in the web UI as well as canonical backend tests. Only then mark the ordinary user journey complete.
