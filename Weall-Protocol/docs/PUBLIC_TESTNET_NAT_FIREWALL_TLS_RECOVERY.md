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
