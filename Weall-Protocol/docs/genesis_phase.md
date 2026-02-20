# WeAll Genesis Constitutional Phase (Non-Economic Launch)

WeAll launches as a **production protocol** with the full identity, governance, and social stack enabled,
but with **economics disabled**.

This is a deliberate “constitutional” phase to stabilize consensus, onboard humans (PoH), and form
governance *before* introducing incentives and monetary transfer metering.

---

## Core principle

At launch:

- **No transaction fees**
- **No rewards**
- **No treasury payouts/spending**
- Full identity, PoH, governance, and social functionality is live

Economics is enabled later via in-protocol governance after a mandatory time lock.

---

## Genesis Constitutional Phase

### Duration (time-based)
- `economic_unlock_time = genesis_time + 90 days`

This is time-based, not block-based, to avoid block-time drift games and to keep the rule simple.

### Lock rules (hard protocol constraints)
If `now < economic_unlock_time`, the protocol MUST reject any governance proposal that attempts to:

- enable any fees
- enable any rewards
- enable treasury payouts/spending
- modify any economic parameter (fees/rewards/treasury/economic settings)

During this lock, governance may still coordinate civic actions, identity growth, moderation, and non-economic
protocol formation — but cannot turn on or tune economics.

---

## Fee philosophy

### Civic actions: permanently fee-free
The following categories must remain fee-free forever:

- identity creation / recovery
- PoH upgrades and attestations
- governance proposals, voting, and related governance operations
- disputes / juror flows / moderation
- posting content, commenting, reactions, follows
- group participation / civic coordination

These actions must not be payable-gated.

### Economic transfers: optionally metered after unlock
Only **economic transfers** (value movement from one user to another) may have fees, and only after unlock.

- Fee structure is integer-based (e.g., flat units) to keep governance control simple and deterministic.
- Fees can be governance-controlled *after* unlock, but must never apply to civic actions.

---

## Economics activation

Economics transitions from disabled → enabled via governance using:

- `ECONOMICS_ACTIVATION` proposal

Constraints:

- Must be submitted and accepted **after** `economic_unlock_time`
- Must not allow bypassing the lock
- Must not retroactively fee civic actions

---

## Anti-spam stance

Anti-spam is enforced via:

- Proof-of-Humanity tier gating (PoH tiers)
- rate limits / moderation / dispute mechanisms

Anti-spam is **not** enforced via fees during the Genesis phase.

---

## Operator note

This doc describes protocol-level intent. The runtime must implement enforcement so that:
- mempool/block rules cannot be overridden by API flags in production mode
- governance proposals that violate the lock are rejected deterministically
