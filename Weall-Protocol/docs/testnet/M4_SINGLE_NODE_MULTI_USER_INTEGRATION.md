# M4 — Single-node, multi-user integration rehearsal

**Status:** IN PROGRESS — controlled integration only; **Genesis NO-GO** and **public beta NO-GO**.

## Objective and evidence boundary

The next implementation milestone prioritizes one WeAll node on an operator-controlled PC
(WSL2/Linux), accessed by independent browser profiles and then independent remote human
users through a Cloudflare-hosted **static frontend** and an HTTPS **node API endpoint**.
No second physical PC is required to begin validating account, social, civic, governance,
and honest failed-authorization journeys.

This is **not** an exemption from the independent validator, authenticated historical BFT
finality, cryptographic review, PoH uniqueness, external observer/replay, legal, storage,
helper-topology, or V2 semantic-review acceptance gates. A single operator may produce
bounded local test receipts and application state, but cannot claim an independent BFT
quorum or constitutionally independent adjudication. Never manufacture receipts or
temporarily disable validation to make a journey appear successful.

**Network participation by other nodes is out of scope for M4**, not declared completed.

## Architecture and trust boundary

1. Participants load the static `web/dist` build from Cloudflare Pages.
2. The browser obtains candidate HTTPS API origins from the published `/seeds.json`.
   The published manifest is a *discovery list*, not a cryptographic or constitutional
   authority source.
3. The build-pinned expected chain ID, genesis hash, transaction-index hash, and protocol
   profile hash are the browser's expected compatibility identity. A remote backend
   MUST NOT fill missing pins from its own `/v1/nodes/seeds` response.
4. Before selecting an API, the browser tests readiness, chain compatibility, and
   public HTTPS origin rules. An active session must be recognized on that target
   before a bearer is sent for protected requests. Unlisted targets need informed,
   tab-scoped consent; unreachable or incompatible targets remain unavailable.
5. The node's public application API is exposed through an HTTPS edge/tunnel with
   restricted routes and method controls. **Do not expose the entire localhost API,
   operator/health diagnostics, IPFS admin API, developer bootstrap assets, the WSL
   filesystem, peer management, validator keys, or live developer tooling.**
   The existing operator runbook lists `/health`, `/healthz`, `/readyz`,
   `/v1/health`, `/v1/healthz`, and `/v1/readyz` as private by default.
   The browser currently probes `/v1/readyz`, so its deliberate, narrow
   deployment-specific exposure (if any) requires an authenticated/allowlisted
   edge design and reviewer agreement rather than exposing everything.
6. WeAll backend transactions, deterministic receipts, durable state and consensus
   remain authoritative. Browser buttons and local caches never grant roles,
   verification, finality, sanctions, economics or governance power.

Cloudflare Pages is the **frontend host**, not a WeAll validator, consensus engine,
or trusted identity oracle. A remote browser sees its own `localhost`, not the
operator laptop. Therefore a hosted UI cannot point to `127.0.0.1:8000` to reach
the operator's node. A production HTTPS node API and explicit CORS must be
configured and preflighted separately. Never publish secrets through `VITE_*` variables.

## Entry prerequisites — before inviting remote testers

- [ ] Pin an exact source commit, build SHA, and the immutable chain commitments.
- [ ] Review the production readiness blockers and obtain the authorizations needed
      for this *bounded* test; do not call the result a released public beta.
- [ ] Prepare a resettable, isolated test ledger, encrypted backups and recovery plan.
      No real-value funds or live economics.
- [ ] Complete the seed-registry rotation and **real operator-held ML-DSA signing
      and verification**, not a fabricated signature. The checked-in registry
      intentionally fails the public frontend build while rotation is pending.
- [ ] Configure an HTTPS node API, strict CORS scoped to the exact frontend origin,
      response-size limits, rate limits, and a narrow route allowlist.
- [ ] Verify that each public API route's authorization and rejection rules are
      enforced at the backend, not only in the browser.
- [ ] Verify browser camera/microphone permissions, media limits and explicit
      evidence retention; do not expose any private PoH footage by URL.
- [ ] Check account-key creation, export/recovery and per-tab session recognition
      across independent browsers before inviting outside participants.
- [ ] Run the source, unit, rendered-browser and backend regression gates on the
      **exact** candidate commit and preserve failures as open blockers.

## Execution increments

| Increment | Real user journey | Acceptance evidence | Current limit |
| --- | --- | --- | --- |
| M4.0 — endpoint and identity | Cloudflare UI chooses the expected HTTPS node and rejects spoofed/unready nodes | Pinned-build identity, CORS preflight, independent browser source tests, failing negative controls | Public registry still requires genuine rotation/signature |
| M4.1 — account custody | Two distinct browsers create, sign into, exit and restore distinct accounts | Canonical registration receipts; different local signing keys; no cross-user bearer leakage; restart recovery | Production PoH authority gate stays closed |
| M4.2 — public social | Users read public feed/groups and submit allowed posts, comments, reactions, flags | Signed tx ID, pending/rejected/apply receipt, persisted visible state and remote-user replay | Roles/reputation restrictions continue to apply |
| M4.3 — civic and governance | Group creation/membership, proposals, ballots and election read model | Exact identity/eligibility, inclusion, turnout and canonical outcome; negative unauthorized cases | Independent governance and validator authority cannot be faked |
| M4.4 — reviews/disputes/PoH | Real applicant and reviewer sessions, submitted evidence, assignments, disputes and appeals | Device permissions, receipts, reviewer eligibility, privacy/appeal/ban hold, cross-browser isolation | No synthetic independent jury, PoH uniqueness or sanctions authority |
| M4.5 — durability and recovery | One physical node restarts while several browsers reconnect | Identical state root/receipts before and after restart; unconfirmed vs terminal UI; operator incident log | No cross-physical-host quorum or network-join proof |

Each journey is recorded as **permitted / explicitly rejected / blocked by
constitutional prerequisite / not yet implemented**. These states are not
interchangeable with "passed". A successful HTTP 200, UI toast, mempool acceptance,
or locally included block is not automatically an authoritative finalized success.

## Existing checked-in commands (verification, not launch approval)

From `web/`, after dependency installation and source review:

```bash
npm run typecheck
node scripts/test_cloudflare_testnet_access_source.mjs
node scripts/test_cloudflare_testnet_behavior.mjs
node scripts/test_https_node_api_preflight.mjs
npm run production-safety-check
```

The Cloudflare static release generator (`node scripts/buildCloudflareTestnet.mjs`)
intentionally refuses unsigned, stale, or unrotated seed registries and emits
`dist/seeds.json` only after its structural checks pass. It **does not itself
cryptographically verify** the registry signature.

Once an authorized HTTPS API and hosted origin exist, run the bounded live
operator check (no credentials in flags):

```bash
node scripts/check_https_node_api.mjs \
  --api-base https://YOUR-APPROVED-NODE-API.example \
  --frontend-origin https://YOUR-APPROVED-FRONTEND.example \
  --commitments ../Weall-Protocol/configs/public_testnet_chain_commitments.json
```

This only checks TLS URL form, three read endpoints, pinned public identity, and
browser CORS preflights. **It does not assert public-testnet ready.** Running it
does not establish that the frontends are deployed, that external participants
have completed a flow, or that constitutional authorization exists.

## M4 evidence ledger format

For each real run store: source commit, frontend build hash, API origin (redacted
if needed), node executable/hash and node mode, chain identity commitment,
UTC timestamp, separate browser profile/device IDs (without personal identifiers),
journey/actor/tx type, signed tx ID, backend response, observed block height,
apply receipt, finalized-status classification, persisted result, negative case,
server/restart log hash, independent witness if any, and **scope of proof**.

Exclude secret keys, session bearers, private media, account recovery data,
and protected IPFS material from CI artifacts and public evidence.

## Rollout decision

**M4 GO (bounded local integration)** requires green focused regression gates
and actual, source-bound local journeys with honest blocked states.

**Remote invited-user rehearsal** requires a separate explicit security and
release-scope review; until then Cloudflare static deployment is only a
development objective, not an instruction to expose the laptop immediately.

**Public beta, independent validators, Genesis, sanction activation and
public release remain NO-GO** until their separate approval gates close.
