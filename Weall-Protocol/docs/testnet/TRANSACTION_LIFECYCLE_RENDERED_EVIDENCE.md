# Transaction lifecycle rendered evidence

This checklist is for bounded public observer / controlled testnet testers who submit a signed action and then inspect **Transactions**.

The goal is not to prove public beta, mainnet, public multi-validator BFT, live economics, automatic upgrades, production helper execution, legal approval, public validator safety, or public storage-market readiness. The goal is to prove that the rendered UI does not collapse different transaction lifecycle states into a false confirmation claim.

## Required rendered states

A tester should be able to distinguish these states in the browser:

| State | What it means | What it must not claim |
| --- | --- | --- |
| Submitted | The browser attempted to send a signed envelope. | Not proof of mempool admission, gossip, inclusion, or finality. |
| Locally accepted | The local backend returned a tx id or accepted/already-known response. | Not final confirmation. |
| Queued / pending | The tx is in a local mempool, durable observer tx queue, or visible pending state. | Not block inclusion. |
| Forwarded / gossiped | The node reports gossip or upstream forwarding evidence. | Not finality; propagation may still be unknown or unavailable. |
| Included in block | The backend tx status reports a block height/block id or local inclusion evidence. | Not automatic public beta or public BFT proof. |
| Finalized / confirmed | The local observer has synced the confirming state or the backend reports a terminal confirmed status that is safe for this node. | Not mainnet readiness or legal/economics readiness. |
| Rejected | Backend or local validation failed the signed action. | Not safe to retry blindly if a tx id or duplicate/nonce detail is present. |
| Removed from mempool | The tx is no longer merely pending because confirmed state or explicit removal evidence superseded mempool residency. | Must not be inferred from local acceptance alone. |
| Unknown / unavailable | The local node cannot currently prove propagation or finality. | Must remain non-final and should direct the tester to refresh/status evidence. |

## What the Transactions page should show

Open **Transactions** after any signed action. Expected behavior:

- local browser history is labeled separately from canonical backend status;
- live toast queue entries are described as browser runtime state, not chain history;
- `/v1/tx/status/{tx_id}` is the read-only status source for pending tx ids;
- the page explains that mempool acceptance is not confirmation;
- the lifecycle timeline contains submitted, locally accepted, queued/pending, forwarded/gossiped, included in block, finalized/confirmed, rejected, removed from mempool, and unknown/unavailable evidence states;
- unknown propagation remains visibly non-final;
- rejected/error states say whether retry is safe instead of hiding the tx id;
- clearing local history is labeled as clearing browser history only, not deleting protocol records.

## Observer-edge boundary

A public observer may accept a tx locally, queue it for upstream forwarding, or show upstream propagation details. That still does not grant validator authority. In observer-edge flows:

- upstream accepted means an upstream endpoint accepted the tx envelope;
- upstream confirmed means the upstream status surface reports inclusion;
- local observer state is not synced until local status/read models show the confirming state;
- `local_state_synced=false` must not be rendered as final local confirmation.

## Evidence to capture

For an external observer transcript, capture:

1. screenshot of the live transaction toast immediately after submission;
2. screenshot of **Transactions** showing local history and lifecycle timeline;
3. `/v1/tx/status/{tx_id}` response for the same tx id when available;
4. any upstream propagation object if running observer-edge forwarding;
5. the affected read model after refresh or honest fail-closed result;
6. a note when propagation/finality is unknown instead of claiming success.

## Stop conditions

Stop and file a bug if the UI:

- says a tx is final because the button was clicked;
- treats local acceptance, mempool acceptance, queueing, or gossip as final proof;
- hides rejected tx ids or nonce/duplicate details;
- treats unknown/unavailable propagation as success;
- treats browser history clearing as protocol deletion;
- claims public beta, mainnet, public BFT, live economics, automatic upgrades, production helpers, legal approval, or public storage readiness.

## Allowed readiness statement after this check

```text
Transaction lifecycle rendering is clearer for bounded controlled/public-observer rehearsal. Public beta readiness remains blocked by explicit external evidence gates.
```
