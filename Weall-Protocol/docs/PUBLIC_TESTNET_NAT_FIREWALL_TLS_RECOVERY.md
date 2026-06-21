# Public Testnet NAT, Firewall, and TLS Recovery

Public observer access is open, but public validator connectivity and seed reliability require normal internet-facing operations hygiene.

## Required ports

- API: usually `8000` locally; public seed APIs should be HTTPS behind a reverse proxy.
- P2P: default `30303` unless configured otherwise.
- Frontend dev: usually `5173`; hosted web builds should use normal HTTPS.

## Seed unreachable

Check:

```bash
curl -sS <seed-api>/v1/chain/identity
curl -sS <seed-api>/v1/nodes/seeds
```

If the seed is unreachable, verify DNS, HTTPS certificate, reverse proxy, firewall allow rules, and that the seed process is running.

## Incompatible chain or genesis

If the frontend reports `incompatible:chain_id_mismatch`, `incompatible:genesis_hash_mismatch`, `incompatible:tx_index_hash_mismatch`, or `incompatible:protocol_profile_hash_mismatch`, do not continue onboarding. Confirm the public seed registry, frontend pinned env values, and `/v1/chain/identity` all match.

## No validator endpoints

`/v1/nodes/validators` distinguishes protocol membership from endpoint hints. Active validators without verified endpoints are active in state but not safe public connection targets. Publish signed or verified endpoint records before relying on public validator connectivity.

## Tx local-only / mempool not propagating

In public observer mode, observer tx forwarding must use explicit upstreams or verified seed/validator upstreams. Missing upstreams should return `PUBLIC_TESTNET_NO_VERIFIED_TX_UPSTREAM`. Treat any local-only mempool acceptance as dev-only unless a verified upstream accepted the tx.

## Sync stuck

Check chain identity and height on both observer and seed:

```bash
curl -s http://127.0.0.1:8000/v1/chain/identity | python -m json.tool
curl -s <seed-api>/v1/chain/identity | python -m json.tool
```

If chain commitments match but height does not advance, inspect local logs, peer counts, seed reachability, and P2P port exposure.

## CORS/TLS browser failures

The frontend connection manager probes API nodes from the browser. Public API nodes need HTTPS and browser-compatible CORS policy for the hosted frontend origin. Browser API access-node switching does not change the local node's P2P mesh peers or signing authority.

## NAT traversal posture

WeAll does not treat NAT traversal, relay delivery, peer address gossip, or frontend node selection as consensus authority. NAT mechanics are transport-only.

A public testnet node should fall into one of these profiles:

1. **Public inbound seed/validator** — the node accepts inbound P2P and publishes a dialable `tcp://` or `tls://` URI.
2. **Outbound-only observer** — the node is behind NAT/CGNAT/firewall and uses verified seeds plus the signed relay mailbox path.
3. **Local/LAN-only development node** — useful for rehearsal, not enough for public observer launch evidence.

Check your local posture with:

```bash
curl -sS http://127.0.0.1:8000/v1/net/self | python -m json.tool
```

The response includes `nat.recommended_profile`, `nat.advertise`, `nat.relay`, `nat.warnings`, and `nat.recovery_actions`. This endpoint never returns private keys and reports `authority: network_transport_only`.

## Inbound-capable seed or validator

Seeds and active validators must not publish loopback, private, or unspecified addresses as public P2P endpoints.

```bash
export WEALL_NET_BIND_HOST=0.0.0.0
export WEALL_NET_BIND_PORT=30303
export WEALL_NET_ADVERTISE_URI=tls://<public-dns-name>:30303
export WEALL_NET_INBOUND_REQUIRED=1
```

Then verify:

```bash
curl -sS http://127.0.0.1:8000/v1/net/self | python -m json.tool
```

Expected posture:

- `nat.inbound_reachable_claim=true`
- `nat.recommended_profile=public_inbound`
- no `inbound_required_without_public_advertise_uri` warning

A DNS advertise URI is an operator claim, not a proof. Launch evidence still requires real peer/session counts and external connectivity transcripts.

## Outbound-only observer behind NAT/CGNAT

Observers behind residential routers, mobile hotspots, or shelter/shared networks should not claim public inbound reachability. Use relay-only posture instead:

```bash
export WEALL_NET_NAT_MODE=relay_only
export WEALL_NET_RELAY_CLIENT_ENABLED=1
export WEALL_NET_RELAY_URLS=https://<bootstrap-or-relay-host>
export WEALL_NET_RELAY_RECIPIENTS=<genesis-peer-id-or-validator-peer-id>
export WEALL_NET_RELAY_RECIPIENT_PUBKEYS='{"genesis":"<64_HEX_GENESIS_NODE_PUBLIC_KEY>"}'
export WEALL_NODE_PUBKEY=<observer-node-public-key>
export WEALL_NODE_PRIVKEY=<observer-node-private-key>
```

Expected posture:

- `nat.recommended_profile=relay_only` or `outbound_relay_only`
- `nat.relay.client_ready=true`
- `nat.relay.authority=transport_only`

Relay delivery can improve liveness for firewalled observers, but relayed messages still go through normal tx/BFT admission and do not grant validator, role, PoH, storage, juror, or governance authority.

## Discovery refresh and stale peer recovery

Public observers refresh seed discovery periodically by default. Configure the interval with:

```bash
export WEALL_SEED_DISCOVERY_REFRESH_MS=60000
```

Set it to `0` to preserve one-shot discovery in controlled local rehearsals. The local `/v1/net/self` response exposes `net.seed_discovery` with the configured interval, last refresh time, last learned peer count, and last error. This is operator telemetry only and does not affect deterministic state.
