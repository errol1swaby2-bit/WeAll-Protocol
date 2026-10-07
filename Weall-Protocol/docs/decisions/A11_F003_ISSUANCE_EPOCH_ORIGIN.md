# A11-F003 Issuance Epoch Origin Decision Record

Status: **AWAITING PROTOCOL AUTHORITY**

Audit finding: A11-F003 — halving clock advances while issuance is locked, creating an unresolved delayed-activation monetary-policy interpretation.

This record is deliberately non-normative until the protocol authority selects one of the two rules below. It must not be cited as changing WeAll monetary policy.

## Current executable behavior

The current v1.5 implementation derives the issuance epoch from absolute chain height:

- one issuance epoch every 30 blocks;
- `issuance_epoch_for_due_height(h) = (h // 30) - 1`;
- one halving every 105,120 issuance epochs;
- subsidy is derived from that absolute epoch index;
- economics-disabled/locked epochs emit nothing;
- skipped epochs are not accumulated for later minting.

Consequently, chain age continues to advance the halving schedule while economics is disabled. If economics first activates after the first halving boundary, the first live subsidy is already halved.

This behavior is deterministic and does not create inflation above the cap. The unresolved issue is whether it matches the intended monetary policy.

## Decision A — Genesis-relative emission schedule

Normative rule:

> An issuance epoch is every canonical 30-block interval since Genesis, whether or not economics is enabled. Economics-disabled epochs are permanently skipped. The subsidy/halving clock is a property of chain age, not cumulative minted epochs.

Consequences:

- preserves the current implementation;
- delayed launch can permanently reduce obtainable lifetime emission below the nominal schedule;
- activation after a halving boundary begins at the then-current reduced subsidy;
- governance cannot recover skipped issuance without a separate explicit monetary-policy change;
- no new issuance-era origin state is required.

If selected, the implementation work is primarily normative documentation plus delayed-activation regression evidence.

## Decision B — Activation-relative issuance era

Normative rule:

> Issuance epoch zero begins only when economics/issuance is activated under protocol authority. The subsidy/halving clock advances with active issuance epochs rather than pre-activation chain age.

Consequences:

- changes the current executable rule;
- requires a consensus-committed issuance-era origin (for example an activation height/epoch);
- first active issuance begins at the initial 100 WCN subsidy even after a long pre-activation chain lifetime;
- restart, state sync, replay, migration, and upgrade paths must preserve the same issuance-era origin;
- activation and any future pause/resume semantics must explicitly define whether the issuance clock pauses or continues;
- cap enforcement remains authoritative.

This option requires protocol/runtime implementation changes before activation.

## Required closure evidence after either decision

A11-F003 is not closed merely by selecting a paragraph. The selected rule must be bound to executable evidence covering:

1. normative statement defining issuance epoch origin;
2. activation before the first halving boundary;
3. activation exactly at the first halving boundary;
4. activation after one or more halving boundaries;
5. economics-locked boundaries emit no reward;
6. deterministic restart preserving the selected epoch origin;
7. fresh-node/state-sync preservation of the same origin;
8. deterministic two-node replay;
9. exact cap behavior under the selected rule;
10. full backend and reviewer-readiness CI.

## Decision field

Protocol authority selection: **UNSET**

Allowed values:

- `GENESIS_RELATIVE`
- `ACTIVATION_RELATIVE`

Until this field is normatively selected and the corresponding implementation/tests are merged, A11-F003 remains a design blocker and no stronger monetary-policy claim should be made.
