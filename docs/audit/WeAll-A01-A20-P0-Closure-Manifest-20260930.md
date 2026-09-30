# WeAll A01–A20 Finding Inventory and P0 Closure Manifest

Date: 2026-09-30
Audited base commit: `cd7f10a8b62e9f5a3711f4263d04e3fd62f0d351`
Audited Git tree: `36a5868c72022f11a61bca8f48816852acccb1c9`

## Inventory summary

- Total unique findings: **77**
- HIGH: **27**
- MEDIUM: **34**
- LOW: **16**
- CRITICAL: **0**

For this closure program, **P0 is derived as every HIGH finding** in the A01–A20 audit set. Assurance and claim-truth HIGHs are not discarded; they are mapped to the runtime root cause they must prove or reflect.

## P0 closure tracks

### P0-01 — Canonical transaction identity and cross-block replay

Findings: `A02-F001`, `A16-F002`

Closure condition: Make committed transaction identity one-shot across restart/replay, preserve immutable first inclusion, and prove failed-inclusion resubmission rejection.

### P0-02 — Equal-root deterministic execution and PoH SYSTEM scheduling

Findings: `A04-F001`, `A16-F003`, `A18-F001`

Closure condition: Canonicalize every scheduler-visible collection/order so equal state roots imply identical SYSTEM scheduling, receipts, and next-block expectations; regenerate public claims only after proof.

### P0-03 — HotStuff parent selection and validator-set transition certificates

Findings: `A05-F001`, `A05-F002`, `A16-F004`

Closure condition: Require leader proposals to extend the certified highQC branch and add an authenticated certificate bridge across BFT activation / validator-set generations with restart and adversarial transition coverage.

### P0-04 — Follower receipt canonicality and durable block representation

Findings: `A06-F001`, `A16-F002`

Closure condition: Persist only execution-derived canonical receipts after follower replay; reject or replace contradictory received receipt bodies and prove restart consistency.

### P0-05 — P2P peer authentication and protocol-valid frame sizing

Findings: `A07-F001`, `A07-F002`

Closure condition: Use session-bound mutual peer authentication with anti-replay challenge material; make transport limits admit every protocol-valid BFT/state-sync message while remaining finite.

### P0-06 — Human uniqueness and reviewer-selection anti-grinding

Findings: `A08-F001`, `A20-F001`

Closure condition: Define/enforce a protocol-level uniqueness authority and remove applicant-controlled entropy from reviewer selection (commit/reveal or protocol-assigned unpredictable selection input), with Sybil/collusion/grinding tests.

### P0-07 — Governance electorate, proposal immutability, and constitutional authority

Findings: `A09-F001`, `A09-F002`, `A09-F003`, `A09-F004`, `A16-F005`

Closure condition: Recognize production chain policy fail-closed, bind executable governance to the verified-human electorate, bind votes to an immutable proposal/action version, and enforce a constitutional/high-impact class with explicit rights-floor rules.

### P0-08 — Economics activation and treasury governance binding

Findings: `A10-F001`, `A10-F002`, `A10-F005`

Closure condition: Never enqueue economic SYSTEM work while economics is locked, make production activation preconditions mandatory, and require a governance approval commitment before treasury signer threshold can execute value movement.

### P0-09 — PoH API authorization/privacy contract

Findings: `A12-F001`, `A18-F002`

Closure condition: Bind viewer/reviewer-scoped PoH reads to the authenticated account session, use explicit public projections, and execute generated auth/privacy vectors against runtime before claiming API contract validity.

### P0-10 — Bounded production state and state-sync work

Findings: `A15-F001`, `A15-F002`, `A15-F003`

Closure condition: Remove unbounded block ancestry from live root-visible state, place finite authenticated work/response envelopes around native state sync, and enforce permanent-state scarcity/onboarding limits against fresh-key account bloat.

### P0-11 — P0 assurance and mutation/property gate

Findings: `A16-F001`

Closure condition: Install a locked property-based/mutation-testing gate covering the P0 surfaces; survivor output must be an artifact and non-equivalent P0 survivors must block closure.

### P0-12 — Evidence/claims truth binding

Findings: `A18-F001`, `A18-F002`

Closure condition: Make claim generation consume current open audit findings so same-tree HIGH findings automatically downgrade/block broader capability claims; regenerate exact-commit reviewer evidence after runtime closure.

## P0 finding inventory

- **A02-F001 — Failed included user transactions are replayable across blocks under the same transaction identity** — HIGH
- **A04-F001 — Equal state roots can drive different PoH SYSTEM scheduling and valid-block expectations** — HIGH
- **A05-F001 — Production leader construction does not extend the certified highQC branch** — HIGH
- **A05-F002 — No production certificate bridge exists for BFT activation or validator-set generation change** — HIGH
- **A06-F001 — Follower acceptance can persist an unverified receipt body and contradictory durable block representation** — HIGH
- **A07-F001 — Peer authentication is not mutual and the signed hello proof is replayable across sessions** — HIGH
- **A07-F002 — Network ingress size limits reject protocol-valid BFT and state-sync messages** — HIGH
- **A08-F001 — No protocol-enforced global human uniqueness / complete Sybil-resistance primitive** — HIGH
- **A09-F001 — Checked-in production governance fails open to legacy ballot mode because ballot policy does not recognize production chain_id** — HIGH
- **A09-F002 — Executable production governance currently assigns political authority to validators rather than the verified-human electorate** — HIGH
- **A09-F003 — Proposal actions/rules/title can be edited during active voting without invalidating existing votes** — HIGH
- **A09-F004 — Constitutional/high-impact governance lacks a mechanically enforced constitutional amendment class and rights-floor validation** — HIGH
- **A10-F001 — Locked/disabled economics can receive a threshold-triggered group-treasury SYSTEM execution that is guaranteed to fail** — HIGH
- **A10-F002 — Economic activation readiness gates are optional and the production timestamp unlock has already expired** — HIGH
- **A10-F005 — Group treasury signatures can directly cause value execution without a governance approval commitment** — HIGH
- **A12-F001 — PoH viewer/reviewer scoped API reads are not bound to an authenticated session** — HIGH
- **A15-F001 — Root-visible block ancestry grows forever and makes mandatory per-block work scale with total chain age** — HIGH
- **A15-F002 — Tiny P2P state-sync requests can trigger synchronous full-state work and unbounded snapshot responses on the consensus network loop** — HIGH
- **A15-F003 — Fresh-key account registration has no scarcity or global count bound, enabling permanent consensus-state bloat** — HIGH
- **A16-F001 — No systematic property-based or mutation-testing gate exists** — HIGH
- **A16-F002 — Cross-lifecycle mutants empirically survive because tests stop at local subsystem boundaries** — HIGH
- **A16-F003 — Determinism tests do not systematically vary representation/order, allowing equal-root execution divergence** — HIGH
- **A16-F004 — BFT tests kill local threshold mutants but do not kill production chained-state-machine mutations** — HIGH
- **A16-F005 — Governance tests do not enforce vote-to-executable-proposal version binding** — HIGH
- **A18-F001 — Positive replay/determinism headline is contradicted by a confirmed equal-root execution divergence** — HIGH
- **A18-F002 — Structurally “valid/current” API contract evidence does not establish runtime authorization truth** — HIGH
- **A20-F001 — Applicant-controlled async PoH case IDs permit deterministic reviewer-panel grinding** — HIGH

## Full A01–A20 inventory

- **A01-F001** — MEDIUM — Authoritative main branch does not enforce the validation gates
- **A01-F002** — MEDIUM — "Clean checkout" proof is not a clean-machine/hermetic reproducibility proof
- **A01-F003** — MEDIUM — Generated V2 route inventory includes four unmounted duplicate endpoint implementations
- **A01-F004** — LOW — V2 source_tree_digest is a partial protocol-source digest, not a full release-tree behavior digest
- **A01-F005** — LOW — Exact reviewer procedure is Git-history-dependent and not reproducible from a plain HEAD source archive
- **A02-F001** — HIGH — Failed included user transactions are replayable across blocks under the same transaction identity
- **A02-F002** — MEDIUM — Schema accepts "false" while social execution applies it as True
- **A02-F003** — LOW — All-canon coverage gates do not prove an executable lifecycle for every canonical type
- **A03-F001** — MEDIUM — Nonzero stale ledger snapshot can pass startup while newer persisted blocks already exist
- **A03-F002** — MEDIUM — Observer durable_tx_queue acknowledgement is not backed by an explicit filesystem durability barrier
- **A04-F001** — HIGH — Equal state roots can drive different PoH SYSTEM scheduling and valid-block expectations
- **A04-F002** — LOW — Determinism validation remains incomplete across machines and protocol breadth
- **A05-F001** — HIGH — Production leader construction does not extend the certified highQC branch
- **A05-F002** — HIGH — No production certificate bridge exists for BFT activation or validator-set generation change
- **A05-F003** — MEDIUM — Timeout certificates do not actually identify the highest referenced QC
- **A05-F004** — LOW — Existing “production BFT” rehearsal does not exercise production BFT consensus validity
- **A06-F001** — HIGH — Follower acceptance can persist an unverified receipt body and contradictory durable block representation
- **A06-F002** — MEDIUM — Future constitutional-slot blocks are rejected by honest construction but accepted by follower/BFT admission before the slot
- **A07-F001** — HIGH — Peer authentication is not mutual and the signed hello proof is replayable across sessions
- **A07-F002** — HIGH — Network ingress size limits reject protocol-valid BFT and state-sync messages
- **A07-F003** — MEDIUM — Production TLS peer connections can silently disable certificate verification
- **A08-F001** — HIGH — No protocol-enforced global human uniqueness / complete Sybil-resistance primitive
- **A08-F002** — MEDIUM — Fresh async PoH can progress using commitment-only evidence with no cryptographically bound reviewable ciphertext
- **A08-F003** — MEDIUM — Anti-Sybil/collusion scoring exists as rehearsal/library logic but is not automatically enforced by the canonical PoH lifecycle
- **A09-F001** — HIGH — Checked-in production governance fails open to legacy ballot mode because ballot policy does not recognize production chain_id
- **A09-F002** — HIGH — Executable production governance currently assigns political authority to validators rather than the verified-human electorate
- **A09-F003** — HIGH — Proposal actions/rules/title can be edited during active voting without invalidating existing votes
- **A09-F004** — HIGH — Constitutional/high-impact governance lacks a mechanically enforced constitutional amendment class and rights-floor validation
- **A10-F001** — HIGH — Locked/disabled economics can receive a threshold-triggered group-treasury SYSTEM execution that is guaranteed to fail
- **A10-F002** — HIGH — Economic activation readiness gates are optional and the production timestamp unlock has already expired
- **A10-F003** — MEDIUM — Reward scheduler reallocates empty-bucket and split remainder value to the protocol treasury
- **A10-F004** — MEDIUM — Generic treasury cancellation is authorized by a global emissary role rather than treasury-scoped cancellation authority
- **A10-F005** — HIGH — Group treasury signatures can directly cause value execution without a governance approval commitment
- **A11-F001** — MEDIUM — Positive FEE_PAY can remove balance value without a destination or explicit burn accounting
- **A11-F002** — MEDIUM — Positive transfer fee policy is currently unenforceable
- **A11-F003** — LOW — Halving clock advances while issuance is locked, creating an unresolved delayed-activation monetary-policy interpretation
- **A12-F001** — HIGH — PoH viewer/reviewer scoped API reads are not bound to an authenticated session
- **A12-F002** — MEDIUM — Anonymous mempool status returns complete pending transaction envelopes despite a redacted-public contract
- **A12-F003** — MEDIUM — Observer-edge operator authorization trusts loopback peers by default
- **A12-F004** — LOW — Consensus forensics exposes operator/BFT internals anonymously in production
- **A13-F001** — MEDIUM — Alternate encodings of the same ML-DSA key are treated as different protocol authorities
- **A13-F002** — MEDIUM — Signature-profile mode policy and explicit allowlist can fail open to ML-DSA
- **A13-F003** — LOW — “Explicit signature profile required” is not consistently enforced outside transaction signing
- **A13-F004** — LOW — Mainline helper-certificate signatures omit the explicit certificate domain used by the newer hardening path
- **A14-F001** — MEDIUM — An older persisted read can overwrite a newer committed in-memory canonical state
- **A14-F002** — LOW — Timed block-loop shutdown can hand ownership to a new generation while the old worker is still alive
- **A14-F003** — LOW — The WebRTC “durable” signal queue can lose updates because its lock is not a single inter-process RMW lock
- **A14-F004** — LOW — Transaction status can transiently report unknown while a transaction atomically moves from mempool to confirmed index
- **A15-F001** — HIGH — Root-visible block ancestry grows forever and makes mandatory per-block work scale with total chain age
- **A15-F002** — HIGH — Tiny P2P state-sync requests can trigger synchronous full-state work and unbounded snapshot responses on the consensus network loop
- **A15-F003** — HIGH — Fresh-key account registration has no scarcity or global count bound, enabling permanent consensus-state bloat
- **A15-F004** — MEDIUM — Health/readiness endpoints are rate-limit-exempt but load and parse the entire ledger snapshot
- **A15-F005** — MEDIUM — Public state snapshot has unbounded response/work size and recursively copies/redacts the whole state
- **A15-F006** — MEDIUM — A02’s apply-failed replay defect is an indefinitely reusable block-capacity exhaustion primitive
- **A16-F001** — HIGH — No systematic property-based or mutation-testing gate exists
- **A16-F002** — HIGH — Cross-lifecycle mutants empirically survive because tests stop at local subsystem boundaries
- **A16-F003** — HIGH — Determinism tests do not systematically vary representation/order, allowing equal-root execution divergence
- **A16-F004** — HIGH — BFT tests kill local threshold mutants but do not kill production chained-state-machine mutations
- **A16-F005** — HIGH — Governance tests do not enforce vote-to-executable-proposal version binding
- **A16-F006** — MEDIUM — Transaction “coverage” is structural; no all-236 semantic property/mutation matrix exists
- **A17-F001** — MEDIUM — Full reviewer-readiness reproduction depends on Git history, not only the current source archive
- **A17-F002** — MEDIUM — Application lockfiles do not make the full clean-machine build hermetic
- **A17-F003** — MEDIUM — Current clean CI proves source/install/test health but not complete node restart/replay reproducibility
- **A17-F004** — LOW — Primary “fresh checkout” verification instructions assume an already-created virtual environment
- **A18-F001** — HIGH — Positive replay/determinism headline is contradicted by a confirmed equal-root execution divergence
- **A18-F002** — HIGH — Structurally “valid/current” API contract evidence does not establish runtime authorization truth
- **A18-F003** — MEDIUM — Current verified-claims registry cannot invalidate itself from same-tree adversarial findings
- **A18-F004** — MEDIUM — “Verified human” tier wording omits the critical uniqueness/Sybil limitation at the point of claim
- **A18-F005** — LOW — Frontend repositorySnapshot is a historical V2 specification snapshot, not the current implementation commit
- **A19-F001** — MEDIUM — Public repository description overstates exact canon conformance
- **A19-F002** — MEDIUM — Advertised “one-command” tester node is not a self-contained clean-clone bootstrap
- **A19-F003** — MEDIUM — fresh_clone_smoke.sh can pass without exact-commit binding or frontend verification
- **A19-F004** — MEDIUM — Reviewer verification paths are fragmented and non-equivalent without a front-door decision tree
- **A19-F005** — LOW — Current whole-system architecture and source-authority map is not obvious from the repository front door
- **A20-F001** — HIGH — Applicant-controlled async PoH case IDs permit deterministic reviewer-panel grinding
- **A20-F002** — MEDIUM — Raw API session bearer key is persisted in browser localStorage
- **A20-F003** — LOW — Documented production static deployment does not mechanically deliver the repository’s CSP posture

## Closure rules

- A finding is not marked closed merely because a defensive feature is disabled; closure requires the report's required regression evidence or an explicit, reviewed scope decision that removes the unsafe capability from the production contract.
- Every consensus/state-transition repair must prove proposer/follower/replay equivalence and restart persistence where applicable.
- Every authorization/privacy repair must include anonymous, wrong-principal, and right-principal negative/positive tests.
- Every P0 production change must pass the full backend suite plus the existing generated/canon/reviewer-readiness gates.
- Closure evidence must be exact-commit bound. The PR description and final evidence manifest must record the final head commit and Git tree.
- A16 property/mutation evidence and A18 claim-truth regeneration are closure gates, not substitutes for runtime repairs.
