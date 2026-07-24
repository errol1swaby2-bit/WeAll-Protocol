# ADR: Institutional identity is outside the Milestone 2 closure boundary

- **Status:** Accepted for the Milestone 2 implementation freeze
- **Decision date:** 2026-07-23
- **Scope owner:** WeAll protocol maintainer

## Context

The v2 product specification describes both human accounts and institutional accounts with authorized human representatives. Milestone 2 is the account-custody and Proof-of-Humanity milestone. The security model completed here is specifically for a natural person controlling an ML-DSA account, an independent offline recovery authority, an ML-KEM evidence-encryption authority, and Tier 1/Tier 2 human-verification status.

Institutional identity introduces a different authority model: entity formation evidence, representative appointment and removal, representative quorum, succession, entity disputes, and an explicit rule for which actions belong to the entity rather than the representative. Treating that model as a small extension of a human account would create an unsafe authority shortcut.

## Decision

Institutional identity and institutional authorized-representative transactions are formally removed from Milestone 2. They will be implemented in a separately activated milestone after the human account, recovery, and PoH lifecycle is frozen and externally rehearsed.

Milestone 2 therefore closes only these identity subjects:

1. Human account creation and browser custody.
2. Independent account recovery and reversal.
3. Tier 1 async human verification.
4. Tier 2 live human verification, renewal, and expiry.
5. Restricted encrypted evidence handling.
6. Reviewer onboarding and externally reproducible testnet journeys.

No Milestone 2 artifact may claim that institutional accounts are production-ready.

## Consequences

- `account_type=human` is the only newly admitted identity type covered by the M2 closure claim.
- Any legacy or placeholder institutional state remains non-authoritative until a later activation explicitly defines its transaction family and migration rules.
- Institutional proposal, treasury, and representation authority cannot be inferred from a human account's Tier 2 status.
- The later institutional milestone must provide its own threat model, canon entries, migration, replay tests, representative conflict rules, and end-to-end evidence.

## Reversal condition

This ADR may be superseded only by a later specification activation that implements and tests institutional formation, representation, removal, recovery, and dispute semantics. Documentation alone is not sufficient to bring institutional identity back into the M2 claim.
