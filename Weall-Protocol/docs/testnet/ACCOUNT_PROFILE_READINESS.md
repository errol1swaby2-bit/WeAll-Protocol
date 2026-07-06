# Account and public profile readiness

This guide defines what a normal tester should understand on the **Account** page during the bounded public observer / controlled testnet.

The goal is account/profile clarity, not public beta, mainnet, legal identity, public validator, live economics, automatic upgrade, production helper, or public storage-market readiness.

## What the Account page must make clear

A tester should be able to see:

- the canonical account id used for signed transactions;
- the available public-key summary for this account or the local browser signer;
- PoH/Tier status as a protocol eligibility signal;
- reputation and public trust dimensions from deterministic read models;
- public profile fields such as display name, bio, avatar CID, website, location, and tags;
- whether the view is owner-authenticated or public-only;
- a transaction status path after profile edits.

## Protocol-state versus local state

Local UI preferences, draft profile fields, browser session state, and saved signer presence are not protocol authority.

A profile edit follows this path:

```text
local form draft → PROFILE_UPDATE skeleton → local signature → /v1/tx/submit → /v1/tx/status/{tx_id} → committed public profile read model
```

The Account page may help the user prepare and sign the action, but the page must not say the profile is updated merely because the user clicked submit, because the backend accepted a request, or because the browser has a local key.

## Public profile state

Public profile metadata is protocol-native public state after commit. This can include display name, bio, avatar reference, website, location label, and tags.

The profile surface must not request or expose raw PoH evidence, government ID material, recovery secrets, device secrets, private notes, or private identity evidence. PoH evidence belongs to the protected verification/review flow, not the public profile contract.

## PoH/Tier language

PoH/Tier status is protocol eligibility. It may unlock participation, posting, review eligibility, or service responsibilities under protocol rules.

It must not be described as legal identity proof, permanent real-world certainty, or complete anti-Sybil/collusion protection.

## Receipt/status visibility

After a profile edit, the tester should be directed to transaction status evidence. The status template is:

```text
/v1/tx/status/{tx_id}
```

The stronger user-facing path is the **Transactions** page, because it distinguishes submitted, locally accepted, pending, included, finalized, rejected, and unknown/unavailable propagation states.

## Stop conditions

File a bug if the Account page:

- says a profile is confirmed before transaction status or the read model confirms it;
- treats a local draft as protocol state;
- treats a local browser signer as protocol authority;
- describes PoH/Tier as legal identity certainty;
- exposes raw PoH evidence, recovery material, private identity evidence, or device secrets in public profile fields;
- hides receipt/status linkage after profile mutation;
- implies public beta, mainnet, public BFT, live economics, automatic upgrade, production helper, legal approval, or public storage-market readiness.

## Allowed readiness statement

If the account/profile flow works locally but external transcripts are still missing, the strongest allowed claim remains:

```text
Pre-public-testnet protocol implementation under active hardening, with local/devnet/public-observer-oriented evidence present and public beta readiness still blocked by explicit external evidence gates.
```
