# Production Relay Network Runbook

This runbook describes the production-safe outbound relay path for WeAll nodes that cannot accept inbound TCP/TLS connections because they are behind NAT, CGNAT, firewalls, mobile hotspots, or residential routers.

The relay path is a **transport mailbox only**. It is not consensus authority, not identity authority, not PoH authority, not validator authority, and not a substitute for tx/BFT admission.

## Safety model

Every relay envelope is:

- bound to `chain_id`
- bound to `schema_version`
- bound to `tx_index_hash`
- bound to sender peer id
- bound to recipient peer id
- bound to canonical payload hash
- signed by the sender's node key
- expiration bounded
- replay/dedupe safe at the receiver

The relay server stores and returns signed envelopes. It cannot safely mutate payloads because mutation breaks the payload hash and ML-DSA signature.

Relayed messages still pass the normal receiving path:

- `TX_ENVELOPE` goes through normal peer/gossip tx admission, signature checks, nonce checks, gates, and mempool admission.
- BFT messages go through existing BFT prefilters and executor validation.
- Utility messages remain node-local networking metadata.

## Relay server configuration

On the public bootstrap/genesis node or any dedicated relay node:

```bash
export WEALL_NET_RELAY_ENABLED=1
export WEALL_NET_RELAY_DB=/var/lib/weall/net_relay.sqlite
export WEALL_NET_RELAY_MAX_PAYLOAD_BYTES=524288
export WEALL_NET_RELAY_MAX_TTL_MS=600000
export WEALL_NET_RELAY_FETCH_LIMIT=100
```

Endpoints mounted under `/v1`:

- `GET /v1/net/relay/status`
- `POST /v1/net/relay/submit`
- `POST /v1/net/relay/fetch` with a signed recipient access request
- `POST /v1/net/relay/ack` with a signed recipient access request

`GET /v1/net/relay/fetch?recipient_peer_id=<peer>&limit=<n>` is legacy non-production compatibility only. Production fetch is signed and recipient-key bound.

Recommended reverse-proxy controls:

- HTTPS only
- request size cap matching `WEALL_NET_RELAY_HTTP_MAX_BYTES`
- rate limit by IP and peer id
- logs for relay submit/fetch/ack status

## Outbound-only observer client configuration

On an observer/onboarding node behind NAT:

```bash
export WEALL_NET_NAT_MODE=relay_only
export WEALL_NET_RELAY_CLIENT_ENABLED=1
export WEALL_NET_RELAY_URLS=https://<bootstrap-or-relay-host>
export WEALL_NET_RELAY_RECIPIENTS=<genesis-peer-id-or-validator-peer-id>
export WEALL_NET_RELAY_RECIPIENT_PUBKEYS='{"genesis":"<64_HEX_GENESIS_NODE_PUBLIC_KEY>"}'
export WEALL_NET_RELAY_POLL_MS=1000
export WEALL_NODE_PUBKEY=<observer-node-public-key>
export WEALL_NODE_PRIVKEY=<observer-node-private-key>
```

After boot, verify the observer reports relay-only posture:

```bash
curl -sS http://127.0.0.1:8000/v1/net/self | python -m json.tool
```

Expected values:

- `nat.recommended_profile` is `relay_only` or `outbound_relay_only`
- `nat.relay.client_ready=true`
- `nat.relay.authority=transport_only`
- no `inbound_required_without_public_advertise_uri` warning unless this node is trying to operate as a seed/validator

Observer safety flags remain mandatory:

```bash
export WEALL_OBSERVER_MODE=1
export WEALL_VALIDATOR_SIGNING_ENABLED=0
export WEALL_BFT_ENABLED=0
export WEALL_HELPER_MODE_ENABLED=0
export WEALL_BLOCK_LOOP_AUTOSTART=0
```

## Relay envelope flow

### Observer submits tx through relay

1. Observer builds a normal signed WeAll tx.
2. Observer wraps the corresponding `TX_ENVELOPE` in a signed relay envelope.
3. Observer posts it to `/v1/net/relay/submit`.
4. Genesis/bootstrap node polls `POST /v1/net/relay/fetch` with a signed recipient access request.
5. The relay returns only signed tx envelopes bound to the genesis relay identity.
6. Genesis verifies the relay envelope.
7. Genesis decodes the wire envelope.
8. Genesis runs normal tx admission.
9. If valid, tx enters mempool and can be included in a block.
10. Genesis acks the relay envelope with a signed recipient access request.

### Relay mutation attempt

If a relay mutates any payload field, the receiver rejects the envelope because either:

- `payload_hash` no longer matches the payload, or
- the ML-DSA signature no longer verifies, or
- the recomputed `relay_id` no longer matches.

### Wrong-chain relay attempt

If a relay forwards an envelope from another chain/profile, the receiver rejects it because:

- envelope `chain_id` mismatches, or
- envelope `schema_version` mismatches, or
- envelope `tx_index_hash` mismatches, or
- nested wire message header mismatches.

## Operational notes

- Relay delivery is at-least-once.
- Receivers ack after processing.
- Receivers must dedupe by relay id and by the native tx/BFT identity.
- Relay queues are durable SQLite mailboxes.
- Expired envelopes are pruned.
- Relay operation may degrade liveness but cannot create valid consensus authority.

## External observer rehearsal checklist

Before inviting an external observer tester, run this sequence internally on a second machine:

1. Boot genesis/bootstrap node with real non-placeholder production manifest values.
2. Enable relay server on the bootstrap node.
3. Build/export public observer onboarding bundle.
4. Copy bundle to observer machine. The bundle must include `observer.relay_recipient_pubkeys` when relay URLs are present.
5. Run `scripts/external_observer_onboarding_smoke.sh` with `WEALL_NET_RELAY_URLS` and `WEALL_NET_RELAY_RECIPIENT_PUBKEYS` set or emitted by the bundle verifier.
6. Boot observer in observer mode.
7. Submit `ACCOUNT_REGISTER` from observer.
8. Verify genesis receives the relayed tx and includes it.
9. Verify observer reads committed receipt/state from genesis.
10. Verify observer cannot sign/propose/enable BFT.

Passing this checklist is the minimum gate before inviting one trusted external observer-node tester.
