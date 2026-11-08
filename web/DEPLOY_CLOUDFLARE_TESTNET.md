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

## Operator HTTPS API packaging (pre-publication only)

A static HTTPS website **does not** make a local node accessible from the
Internet. Each advertised public API endpoint needs its own public hostname,
certificate, reachable transport, explicitly constrained backend CORS, and
independently approved network/registry metadata.

The repository also ships `web/deploy/Caddyfile.public-api.example` as an
**unactivated example** for a single node operator. Caddy manages a publicly
trusted TLS certificate when DNS and ports 80/443 are correctly configured;
the upstream WeAll API stays bound to a private interface. This is an optional
TLS terminator, **not** a consensus relay or central gateway.

After an operator has independently authorized an external-facing test node:

1. Run the WeAll API under an approved **non-demo** profile; validate the
   explicit `WEALL_CORS_ORIGINS` value for the exact Pages origin. Disable
   local/demo secret and mutation helpers and verify those routes reject
   Internet-origin requests. Keep the raw API port inaccessible from outside
   the host/network.
2. Set `WEALL_API_HOST` to the actual DNS hostname and
   `WEALL_NODE_API_UPSTREAM` to the private `host:port` of that API.
   Review the example's forbidden-route list; it is defense in depth,
   **not** a substitute for production backend route authorization.
3. Validate the template with `caddy adapt --config
   web/deploy/Caddyfile.public-api.example --validate` and launch Caddy
   under the operator's normal service manager. Public certificate issuance
   depends on DNS and reachability; do not treat a locally validated config
   as a working TLS deployment.
4. Use the read-only `check_https_node_api.mjs` command below, against the
   **actual** node API hostname and **actual** Pages origin, before adding
   the node to the signed registry. Verify that forbidden routes return no
   private keys or demo credentials. Check the same-origin and cross-origin
   browser flows from an independent network.
5. Only after the legitimate registry signer re-signs current chain
   commitments and independent launch approvals exist should the signed
   public-testnet registry be distributed and the Pages public build enabled.

### If the public deployment gate is still blocked

That is the current repo state: the checked-in registry has an empty
`seed_registry_signature`, with rotation and re-signing flags still true.
**Do not** clear flags by hand, use a test signing key, replace the registry
with an unsigned `seeds.json`, fall back to plaintext HTTP, or direct
ordinary users to the seeded demo account.

Instead run the browser and node in a clearly labeled **controlled-devnet
rehearsal** behind local-only access or a deliberately restricted private
test environment. A tester may create/restore their own local key and rehearse
account registration against that network, but those records are not
production membership and are not guaranteed to survive a fresh genesis.
Record failed connection attempts as unavailable without duplicate signed
registration dispatch. Operator-led HTTPS TLS/CORS smoke testing may proceed
on a separately authorized isolated test endpoint, without publishing it
as the real public WeAll network.

Remote browser access is distinct from running a full node. HTTPS makes
account/transaction *access* possible over the Internet once the receiving
node is live and authorized; it does not provision a local node, make
validators independent, prove PoH video, or remove network/firewall constraints
for people who choose to operate their own node.

## Cloudflare Pages configuration

Create a Cloudflare Pages project linked to this repository. Configure:

| Setting | Value |
| --- | --- |
| Root directory | `web` |
| Framework | React / Vite |
| Production branch | the chosen release branch after review |
| Build command | `node scripts/buildCloudflareTestnet.mjs` |
| Output directory | `dist` |
| Node.js | 22; set Cloudflare Pages build environment variable `NODE_VERSION=22` |

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
   chain/genesis/tx-index/protocol-profile commitments. In a public build,
   only HTTPS APIs from the shipped static seed manifest are eligible for
   automatic switching; independent compatible HTTPS nodes require explicit
   informed manual approval.
4. A listed healthy existing node is retained. If there is a saved session,
   the target must recognize it before selection. Otherwise the browser
   chooses a listed healthy compatible node; unavailable sessions or chain
   mismatches fail closed.
5. Normal API requests go **directly** to the chosen node origin. The
   connection panel remains available for manual inspection and switching.

## Authenticated browser sessions and HTTPS node changes

The browser stores account/public signer metadata and its selected API origin
in `localStorage`, while the active session bearer and ML-DSA-65 signing seed
are held in `sessionStorage`. These are scoped to the frontend's website
origin; a new browser profile, device or custom domain does **not** inherit
the existing session or signing seed automatically. Multiple tabs in a
single profile may share public metadata, and `sessionStorage` can be
initially copied in some opener-created tabs. For independent-account PoH,
use separate browser profiles/contexts, not merely two tabs.

For public-testnet builds, **automatic failover** uses only **HTTPS APIs
included in the published static seed manifest**. Backend entries from
`/v1/nodes/seeds` remain discovery hints rather than credential trust roots.

To preserve user choice and the ability to reach independently operated
nodes, the connection panel and Settings also offer **explicitly manual**
HTTPS selection outside that manifest. The browser first checks pinned chain
compatibility **without a bearer**, clearly warns that the unlisted operator
may see the user's session bearer and API traffic, and requires an affirmative
operator-trust confirmation. If an active bearer exists, the destination
must independently recognize that session before switching. Consent is kept
in **tab-scoped sessionStorage** and is never inferred from backend gossip
or propagated to every browser profile. A compatible current custom node
may be retained across reloads only with that prior tab approval.
A declined or failed session check preserves the existing node.

When an active session bearer is present, the browser requests the
destination's read-only `GET /v1/session/me` using the existing
`X-WeAll-Account` and `X-WeAll-Session-Key` headers, and requires
`authenticated=true`, the same account, and an active unexpired session.
This happens **after** chain-compatibility validation and **before** committing
an API-base switch. If a compatible node is behind on session records,
the browser keeps the current base, reports `node_unverified` in the
session-health UI, and withholds protected auth headers. It never creates
a new session automatically on that node or treats missing records as
proof of successful login. A user can retry from the connection panel
once the destination catches up, or perform normal account session
recovery. The session check does not prove cross-node synchronization
or on-chain transaction finality.

This is deliberately a conservative **startup/manual** selection policy,
not continuous in-flight transaction failover. On a new hostname, do not
copy bearer/session storage from another domain.

## Read-only node HTTPS and CORS preflight

Once a real public API HTTPS hostname is configured, run from the `web`
directory:

```bash
node scripts/check_https_node_api.mjs \
  --api-base https://YOUR-NODE-API-HOST \
  --frontend-origin https://YOUR-CLOUDFLARE-FRONTEND-HOST \
  --commitments ../Weall-Protocol/configs/public_testnet_chain_commitments.json
```

The checker uses Node's normal TLS certificate validation, rejects
HTTP/placeholder URLs, requires healthy status/readiness/chain identity
matching local pinned commitments, and tests cross-origin GET plus
`OPTIONS` preflight for both session headers and signed-transaction
submission. It sends **no real bearer, key, transaction or PoH media**.
A passing check only establishes endpoint reachability, TLS and CORS
configuration at that moment; it does not verify ML-DSA signatures,
two physical machines, real PoH, P2P ports or live economics.

Run the same check with the real production hostname and every preview
origin you intend to allow. Never set wildcard production CORS simply to
make the preflight pass. Node HTTPS and CORS configuration remain the
node operator's responsibility, not Cloudflare Pages' responsibility.

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
