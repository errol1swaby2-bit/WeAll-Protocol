# Direct-message transaction quarantine

Status: **public-testnet claim excludes direct/private messaging**.

WeAll is a pre-public-testnet protocol implementation under active hardening. The NLnet/public-testnet reviewer claim is public-only civic protocol infrastructure, not private messaging, encrypted messaging, inbox/outbox chat, or private group read visibility.

## Current canon result

The generated public-testnet transaction index does **not** include active direct-message transaction types:

- `DIRECT_MESSAGE_SEND` is absent.
- `DIRECT_MESSAGE_REDACT` is absent.
- No tx name containing `DIRECT_MESSAGE`, `PRIVATE_MESSAGE`, or `P2P_CHAT` is present in `generated/tx_index.json`.

If any historical document mentions direct messages, private messages, chat, inbox/outbox, encrypted payloads, or member-only readable groups, that wording is legacy/out-of-scope unless the surrounding text explicitly says it is unsupported, removed, disabled, or forbidden for the NLnet/public-testnet claim.

## Public-only boundary

Protocol-native social, civic, governance, moderation, dispute, group, reputation, and node/operator activity is intended to be publicly inspectable. Group membership may gate posting, commenting, voting, moderation, invitation, or administration. Group membership must not gate read visibility for protocol-native group content.

Private/direct/encrypted messaging is not part of the NLnet/public-testnet claim and must not be presented in reviewer-visible UI or public-testnet documentation as an active feature.

## Verification commands

```bash
cd Weall-Protocol
PYTHONPATH=src python scripts/gen_tx_index.py --check
PYTHONPATH=src python -m pytest -q tests/test_direct_message_transaction_quarantine.py tests/test_public_only_protocol_redesign.py
cd ../web
node scripts/test_public_only_protocol_source.mjs
node scripts/test_reviewer_critical_flows_source.mjs
```

## Reviewer interpretation

This quarantine closes a wording/claim-risk class only when the tests above pass against the exact commit under review. It does not prove public beta readiness, public mainnet readiness, public BFT readiness, live economics, or first external observer readiness.
