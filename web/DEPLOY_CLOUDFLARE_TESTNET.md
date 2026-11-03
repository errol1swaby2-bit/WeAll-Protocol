# Optional Cloudflare Pages access to the WeAll public testnet

This is **only** a static, optional convenience frontend. Cloudflare does not
operate a WeAll node, process transactions, proxy `/v1` traffic, verify PoH,
own accounts, select validators, or provide consensus/discovery authority.

This deployment reads the existing public-testnet identity commitments and
candidate HTTPS API endpoints. The browser probes the nodes, selects a healthy
compatible one before first API use, and continues using the existing
`NodeConnectionPanel` for explicit switching. Users remain free to use a
locally hosted frontend or any other compatible frontend distributor.

## Preconditions — do not skip

1. A real public observer testnet must be operating. Use the canonical
   `Weall-Protocol/docs/testnet/PUBLIC_OBSERVER_QUICKSTART.md` and registry
   signer operations runbook; this frontend does not establish network launch.
2. The operator **must** cryptographically verify the ML-DSA signed registry
   using the existing Python signing/check process and pinned trust roots.
   The frontend build checks for nonempty signature and matching chain
   commitments but **does not cryptographically verify the registry**.
3. Clear `seed_registry_rotation_required` and
   `pq_resign_required_before_public_testnet` only after the operator has
   actually re-signed the current registry. This build fails closed otherwise.
4. All advertised public **API** nodes must support browser HTTPS. P2P
   `tls://` endpoints are not browser API addresses. Each node must expose
   `/v1/status`, `/v1/readyz`, `/v1/status/consensus` where available,
   and `/v1/nodes/seeds`. Cross-node discovery remains on the backend.
5. Node API origins must explicitly permit the deployed Cloudflare frontend:
   `WEALL_CORS_ORIGINS=https://<your-testnet-domain>`. Include the exact
   preview origin separately when testing previews. No production `*` CORS.
6. Test live PoH browser camera/microphone permissions and, if enabled, set
   `VITE_WEALL_LIVE_ROOM_BASE_URL` to the actual self-hosted HTTPS room
   transport. WebRTC ICE/TURN and live room reachability are separate tests.

The checked-in `web/public/seeds.json` is **only** a local-development fixture.
Never upload it unchanged as the public testnet registry.

## Cloudflare Pages configuration

Create a Cloudflare Pages project linked to this repository. Configure:

| Setting | Value |
| --- | --- |
| Root directory | `web` |
| Framework | React / Vite |
| Production branch | the chosen release branch after review |
| Build command | `node scripts/buildCloudflareTestnet.mjs` |
| Output directory | `dist` |
| Node.js | 22 (supported by `web/package.json`) |

The build script reads:

- `Weall-Protocol/configs/public_testnet_chain_commitments.json`
- `Weall-Protocol/configs/public_testnet_trust_roots.json`
- `Weall-Protocol/configs/public_testnet_seed_registry.json`

It refuses unsigned, still-rotating, unpinned, or non-HTTPS testnet settings;
runs the normal web build with public testnet identity explicitly pinned;
then **replaces only `dist/seeds.json`** with a manifest constructed from
the published registry's browser-accessible HTTPS seed API endpoints.
The tracked local-development fixture is not modified.

Cloudflare serves the resulting static assets, including `_headers`.
There is deliberately **no** Pages Function, Worker gateway, `/v1` proxy,
or reliance on any specific Cloudflare API at runtime.

Set a custom domain under the DNS zone you own only after the preview
deployment and node access checks succeed. Cloudflare's Pages Git integration
can deploy subsequent reviewed commits.

## User flow

1. Visitor loads the static website over HTTPS.
2. Before initial API calls, the browser fetches `/seeds.json` and queries
   seed candidates, combining the build default, known current API and the
   backend's `/v1/nodes/seeds` response when reachable.
3. Node probes verify readiness and the pinned
   chain/genesis/tx-index/protocol-profile commitments.
4. Existing healthy user-selected nodes remain selected. Otherwise the
   browser selects a healthy compatible node; if there is none, it does not
   silently pick an incompatible node.
5. Normal API requests go **directly** to the chosen node origin. The
   connection panel remains available for manual inspection and switching.

## Validation before inviting testers

- Check the release registry with the real signing workflow.
- Run `cd web && npm ci && node scripts/buildCloudflareTestnet.mjs`.
  A pending unsigned registry **must fail**, not produce a fake public build.
- Run `npm run typecheck`, `npm run test:node-manager`, and existing web CI.
- Inspect generated `dist/seeds.json`; no loopback address or placeholder.
- From two independent browsers/devices, verify first-visit node discovery,
  node switching, incompatible-node rejection, and app login.
- Simulate an unavailable selected node and verify failover to another
  compatible reachable API node.
- Verify camera/microphone permissions and remote PoH against actual node
  endpoints, with no privileged identity or role bypass.
- Confirm no browser request to the Cloudflare origin is used as a `/v1`
  transaction proxy; check that testnet API requests reach the selected node.
- Check security response headers and backend CORS under the exact production
  and preview origins.

**Launch status:** A successful static build, or a passing CI suite, is not
proof that public testnet nodes are live, that the registry is signed, or that
two-node browser and live PoH rehearsal has passed. Record that evidence
separately.
