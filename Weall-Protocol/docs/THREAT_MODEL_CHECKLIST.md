# WeAll Node Threat-Model Checklist (MVP)

This document is an operator-facing checklist for deploying a WeAll node safely.

The current backend build targets an **open mesh** posture: nodes can continue to gossip/sync over the protocol-native TCP mesh even if the public HTTP path is disrupted.

## 0) Deployment goals (what this checklist assumes)

- You want the node to be **fail-closed by default**.
- You want **peer identity = account key** (Proof-of-Humanity account), to reduce Sybil leverage.
- You accept that the current TCP mesh is **not encrypted** (no TLS/Noise yet); confidentiality is not guaranteed.

## 1) Identity + "one node per user"

**Goal:** A single PoH-verified user should operate *one* node identity on the mesh.

Current enforcement (this build):
- The TCP mesh can require that peers prove control of the same Ed25519 key registered on-chain.
- The node process enforces **only one live, identity-verified session per account** (duplicate nodes for the same account are rejected at the network edge).

Environment toggles:
- `WEALL_NET_REQUIRE_PEER_IDENTITY=1` (default: `1`)
- `WEALL_NODE_PUBKEY=<account active pubkey>`
- `WEALL_NODE_PRIVKEY=<matching Ed25519 seed>`

Operational notes:
- Do **not** reuse the same account key across multiple machines if you expect them to be concurrently online.
- Keep `WEALL_NODE_PRIVKEY` out of logs and process listings; prefer env injection via a secrets manager.

## 2) Genesis economics lock

**Goal:** During the first 90 days from genesis, economics (fees/rewards/treasury spending) must remain disabled and non-bypassable.

This build enforces:
- Time lock: `economic_unlock_time = genesis_time + 90 days`
- Even after unlock, economics stay disabled until `ECONOMICS_ACTIVATION`.

No operator toggle should bypass this in production.

## 3) HTTP API surface hardening

Environment toggles:
- `WEALL_CORS_ALLOW_ORIGINS="https://example.com,https://app.example.com"` (default: deny)

Built-in protections:
- Request size limiting (fail fast)
- Rate limiting

Checklist:
- Place the HTTP API behind a reverse proxy/WAF.
- Consider restricting API exposure to trusted networks if you are running a private validator set.

## 4) TCP mesh hardening

Environment toggles:
- `WEALL_NET_ENABLED=1` (default: `1`)
- `WEALL_NET_BIND_HOST=0.0.0.0`
- `WEALL_NET_BIND_PORT=30303`
- `WEALL_NET_MAX_STRIKES=10`
- `WEALL_NET_BAN_COOLDOWN_MS=60000`

Built-in protections:
- Length-prefixed framing with **max frame bytes** and **max buffer bytes**.
- Oversized/invalid frames trigger strike escalation and banning.

Checklist:
- Use firewall rules to limit inbound mesh connections to expected ranges (when possible).
- Monitor for repeated connect/ban churn.

## 5) Key operational hygiene

- Ensure `generated/tx_index.json` is present in the deployment package.
- Run nodes with least privilege (non-root user).
- Store ledger/mempool/attestation files on durable storage.
- Back up the `./data/` directory regularly.
