# PoH Privacy Requirements

WeAll uses chain-verified eligibility, not surveillance identity.

## Hard requirements

- No raw private PoH evidence on-chain.
- No raw private PoH evidence in receipts.
- No raw private PoH evidence in public snapshots.
- No plaintext native PoH review in chain state.
- No authority signer private key in logs.
- No mailbox data in protocol state.

## Commitment model

Native PoH verification may compute private off-chain review artifacts, but public
chain state must contain only protocol-required commitments, case identifiers,
juror decisions, and deterministic status fields. Raw identity-provider data is
not part of the protocol.
