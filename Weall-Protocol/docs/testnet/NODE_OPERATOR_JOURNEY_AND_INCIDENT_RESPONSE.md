# Node/operator journey and incident response readiness

This checklist is for a bounded public observer / controlled testnet operator. It explains what the **Personal Node** dashboard should show, what a tester may safely do next, and what must remain unclaimed until external evidence exists.

This is not a public beta, mainnet, public multi-validator BFT, live economics, automatic upgrade, production helper, legal/compliance, or public storage-market readiness claim.

## 1. Mode and authority matrix

The dashboard must make the current mode readable before any command is copied:

| Mode | What the surface may show | What it must not imply |
| --- | --- | --- |
| Observer | chain identity, sync height, seed/peer status, tx forwarding diagnostics, read-only routes | observer mode can never sign blocks or grant validator authority |
| Node operator | account-linked operator readiness, local storage/helper/validator opt-in state, safe commands | local setup and copied commands do not create protocol authority |
| Validator-candidate | readiness receipt path, validator blockers, activation prerequisites | candidate state is not effective validator authority |
| Validator | backend/protocol state says validator authority is effective | frontend state alone must never enable signing |

The phrase "current mode" should be backend/account-derived. Browser navigation, environment flags, seed registry hints, local storage preferences, and copied commands are not protocol authority.

## 2. Expected dashboard evidence

A tester should capture the following from **Personal Node**:

- current backend URL;
- `chain_id`, genesis hash, tx index hash, protocol profile hash, state root, and height;
- finalized height if the node exposes it;
- `/readyz` health;
- mempool backlog and observer tx queue counts;
- seed registry source, signature status, seed node count, and direct P2P URI count;
- active validator count, verified endpoint count, fresh endpoint count, and missing-fresh warnings;
- NAT/firewall posture and recovery guidance;
- storage/IPFS read model counts and local storage preference boundary;
- helper, economics, protocol-upgrade, and public beta blocker state;
- safe command wizard output;
- incident timeline output.

## 3. Safe command rule

Run read-only diagnostics first:

```bash
curl -fsS http://127.0.0.1:8000/v1/status | python -m json.tool
curl -fsS http://127.0.0.1:8000/readyz | python -m json.tool
curl -fsS http://127.0.0.1:8000/v1/chain/head | python -m json.tool
curl -fsS http://127.0.0.1:8000/v1/status/mempool | python -m json.tool
curl -fsS http://127.0.0.1:8000/v1/nodes/seeds | python -m json.tool
curl -fsS http://127.0.0.1:8000/v1/nodes/validators | python -m json.tool
curl -fsS http://127.0.0.1:8000/v1/status/operator | python -m json.tool
```

Only after those outputs are saved should a tester run a documented recovery or rehearsal command. A command marked diagnostic-only, local-only, observer-only, evidence capture, or requires-protocol-state must remain inside that scope.

## 4. Chain mismatch response

Treat these as incidents, not normal fallbacks:

- incompatible `chain_id`;
- genesis hash mismatch;
- tx index hash mismatch;
- protocol profile hash mismatch;
- state root divergence across replay surfaces;
- validator endpoint freshness mismatch.

The browser may switch only to healthy compatible nodes. It must not use a stale or incompatible node to keep the demo moving.

## 5. Mempool/backlog response

If the dashboard shows mempool pressure or observer queue items:

1. capture `/v1/status/mempool`;
2. capture `/v1/observer/edge/status` if observer-edge mode is active;
3. open **Transactions** and verify local acceptance, queueing, forwarding, inclusion, finalization, rejection, removed, and unknown states remain distinct;
4. do not call mempool acceptance "confirmed";
5. file a bug if the queue hides stale or rejected state.

## 6. Validator and BFT boundary

Validator-candidate warnings are not permission to enable signing. Before any controlled validator rehearsal, the transcript must show:

- fresh clone or clean operator setup;
- synced observer state;
- account/Tier eligibility if required;
- node-operator readiness;
- explicit validator responsibility opt-in;
- readiness receipt;
- activation visible in protocol state;
- restart remains fail-closed unless chain state permits signing.

Public multi-validator BFT remains unclaimed until independent public validator/operator evidence exists.

## 7. Storage, helper, economics, and upgrade boundary

The dashboard may show read-only storage/IPFS, helper, economics, and protocol-upgrade status, but must keep these boundaries visible:

- storage market/public durability needs real storage/IPFS operator transcript evidence;
- production helper execution remains disabled and future-gated;
- economics remain locked unless governance and launch policy explicitly activate them in a later scope;
- protocol/constitution upgrade records are record-only in this testnet path and must not auto-fetch artifacts, execute migrations, restart nodes, or change economics.

## 8. Incident packet

For each issue, attach:

```text
machine / OS:
branch:
commit:
node base URL:
observed mode:
chain_id:
height / finalized height:
status output:
readyz output:
chain head output:
mempool output:
seed/peer output:
validator endpoint output:
operator status output:
screenshots:
what action was attempted:
what happened:
why it is safe / unsafe to continue:
```

See `docs/operators/INCIDENT_RESPONSE.md` for the operator-facing runbook.

## 9. Allowed statement after this pass

```text
The node/operator journey is clearer for controlled internal/public-observer rehearsal. Public beta readiness remains blocked by explicit external evidence and mainnet-hardening gates.
```
