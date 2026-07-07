# WeAll Node Threat-Model Checklist (MVP)

This document is an operator-facing checklist for deploying a WeAll node safely.

The current backend build targets an **open mesh** posture: nodes can continue to gossip/sync over the protocol-native TCP mesh even if the public HTTP path is disrupted.

## 0) Deployment goals (what this checklist assumes)

- You want the node to be **fail-closed by default**.
- You want **peer identity = registered node key bound to a verified account**, to reduce Sybil leverage while keeping the account recovery key out of node runtime.
- You accept that the current TCP mesh is **not encrypted** (no TLS/Noise yet); confidentiality is not guaranteed.

## 1) Identity + "one node per user"

**Goal:** A single PoH-verified user should operate a bounded number of registered node identities on the mesh, using node keys that are separate from the account recovery key.

Current enforcement (this build):
- The TCP mesh can require that peers prove control of a registered node key bound on-chain to a verified account.
- The node process enforces the configured node/account uniqueness policy at the network edge.

Environment toggles:
- `WEALL_NET_REQUIRE_PEER_IDENTITY=1` (default: `1`)
- `WEALL_NODE_PUBKEY=<registered node public key>`
- `WEALL_NODE_PRIVKEY_FILE=/secure/path/weall-node.key`

Operational notes:
- Do **not** use the account recovery key as the node key.
- Generate a separate node key, register its public key, and store the private key outside the repository.
- Prefer `WEALL_NODE_PRIVKEY_FILE` over raw private-key environment variables so node secrets do not appear in shell history, process listings, or logs.

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
- Consider restricting API exposure to trusted networks if you are running a controlled validator set.

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
