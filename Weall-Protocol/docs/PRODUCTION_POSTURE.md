# WeAll Protocol — Production Posture Specification

Version: 1.1  
Applies to: WeAll Genesis Node (HotStuff BFT runtime)  
Status: REQUIRED for public-validator and production deployment

Reviewer current-state boundary after Passes 10–27:

> WeAll is a pre-public-testnet protocol implementation under active hardening, with local/devnet/public-observer-oriented evidence present and public beta readiness still blocked by explicit external observer, replay, validator/operator, storage, legal, upgrade-execution, and helper-topology gates.

This document is a production posture specification and truth boundary. It is not a claim that the repository is public beta ready, public mainnet ready, public validator safe, public multi-validator BFT ready, live-economics ready, automatic-upgrade ready, production-helper ready, legal approval granted, or public storage-market ready.

Current tx canon checkpoint: **236 tx types, version 1.25.0**. Proof-of-Humanity checkpoint: **Tier 0 = account only**, **Tier 1 = native async verified human**, and **Tier 2 = native live verified human**. There is no required user-facing Tier 3. There is no required email, no required SMTP, no required DNS, and no required named hosting provider as PoH authority.

## 0. Current Reviewer Go / No-Go Boundary

| Claim area | Status | Production-posture meaning |
|---|---:|---|
| Controlled internal/public-observer rehearsal candidate | GO | Local/generated evidence supports the next bounded rehearsal candidate only. |
| Public beta readiness | NO-GO | `public_beta_ready=false` remains the public-readiness truth boundary. |
| Public mainnet readiness | NO-GO | Mainnet hardening remains future work. |
| Public validator/BFT readiness | NO-GO | Independent operator and public multi-validator evidence remains required. |
| Live economics | NO-GO | Fees, transfers, rewards, treasury spend, and slashing are locked or not live launch claims. |
| Automatic protocol upgrades | NO-GO | Upgrade records are deterministic metadata; automatic software apply is disabled. |
| Executable migrations/rollbacks | NO-GO | Migration and rollback execution are not enabled. |
| Production helper execution | NO-GO | Helper topology remains a future hardening gate. |
| Legal/compliance approval | NO-GO | Counsel/control attestation remains required. |
| Public storage-market readiness | NO-GO | Storage/IPFS evidence is not yet a public storage-provider market claim. |

Reviewer verification path for this posture:

```bash
cd ~/WeAll-Protocol/Weall-Protocol
source .venv/bin/activate

PYTHONPATH=src:scripts python scripts/gen_public_beta_blocker_report_v1_5.py --check
PYTHONPATH=src python scripts/gen_release_evidence_manifest_v1_5.py --check
PYTHONPATH=src python scripts/check_v15_public_readiness_artifacts.py
PYTHONPATH=src python scripts/check_reviewer_truth_boundaries.py
PYTHONPATH=src python scripts/check_release_hygiene_v1_5.py
```

## 1. Purpose

This document defines the strict production posture for the WeAll Protocol.

Production posture means:

- deterministic behavior across all honest nodes
- fail-closed startup and runtime
- no dev/test fallbacks reachable in production execution paths
- no implicit configuration
- no unsafe defaults
- no hidden bootstrap shortcuts

All production nodes, clients, and operator tooling MUST comply with this specification.

## 2. Core Principles

### 2.1 Fail-Closed by Default

If required configuration, secrets, or invariants are missing:

- the node MUST NOT start
- the client MUST NOT proceed
- the system MUST NOT degrade to a weaker mode

### 2.2 Determinism Over Convenience

No production code path may depend on:

- local timing differences
- thread scheduling
- unordered iteration
- implicit defaults
- environment drift

### 2.3 Explicit Configuration Only

All production configuration MUST be:

- explicitly declared
- validated at startup
- immutable during runtime

### 2.4 Separation of Concerns

Code must be separated into:

| Category | Allowed in Production |
|---|---|
| Runtime core | YES |
| Operator tools | YES |
| Dev/test tools | NO |
| Bootstrap/genesis shortcuts | NO |
| Debug UI paths | NO |

## 3. Production Runtime Contract

### 3.1 Required Mode

Production nodes MUST run with:

`WEALL_MODE=prod`

No implicit default is allowed. Controlled genesis bootstrap mode is documented separately and must not be confused with public validator production-service mode.

### 3.2 Required Startup Conditions

Node startup MUST FAIL if any of the following are missing:

- node identity (public + private key) when network/BFT/signing are enabled
- chain_id
- trusted anchor configuration when production profile requires it
- validator account when validator/BFT mode is enabled

### 3.3 Forbidden Runtime Flags in Production

The following MUST NOT be allowed in production:

- `WEALL_GENESIS_MODE=1`
- `WEALL_BLOCK_LOOP_ENABLED=1`
- `WEALL_PRODUCE_EMPTY_BLOCKS=1`
- `WEALL_BLOCK_INTERVAL_MS=*`
- `WEALL_SIGVERIFY=0`
- `WEALL_AUTOVOTE=1`
- `WEALL_AUTOTIMEOUT=1`
- `WEALL_BFT_ALLOW_QC_LESS_BLOCKS=1`
- `WEALL_BFT_ALLOW_UNSIGNED_TIMEOUTS=1`
- `WEALL_UNSAFE_DEV=1`
- any implicit localhost CORS fallback

If present, startup MUST FAIL.


### 3.4 Public Validator BFT Posture

Production observer nodes may run without validator signing, but any node that presents
itself as a production validator service or enables validator signing MUST run with
HotStuff/BFT enabled. The following mixed posture is forbidden:

- `WEALL_OBSERVER_MODE=1` together with `WEALL_VALIDATOR_SIGNING_ENABLED=1`
- `WEALL_VALIDATOR_SIGNING_ENABLED=1` without `WEALL_BFT_ENABLED=1`
- `WEALL_NODE_LIFECYCLE_STATE=production_service` with `validator` in `WEALL_SERVICE_ROLES` without `WEALL_BFT_ENABLED=1`

### 3.5 v1.5 Block Timing and Economics Configuration

Production and public-testnet chain configuration MUST use the v1.5 block cadence and locked-economics posture:

- `block_interval_ms: 20000`
- `block_reward: 0`

`block_interval_ms` is block-production cadence only. WeCoin issuance is not configured as a per-block reward; it is scheduled by the v1.5 issuance-epoch constants and remains locked unless the existing governance activation path proves activation.

### 3.6 Production Consensus Profile Pinning

Consensus-affecting limits MUST be profile-pinned and included in the production
profile hash. In production, local `WEALL_MAX_TX_PAYLOAD_*` overrides are not
local policy; they are consensus-critical profile values and must match the
pinned production consensus profile. A mismatch MUST fail closed before a node
participates in validation.

Current pinned tx payload limits:

| Field | Value |
|---|---:|
| `max_tx_payload_bytes` | 65536 |
| `max_tx_payload_depth` | 20 |
| `max_tx_payload_list_len` | 2000 |
| `max_tx_payload_dict_keys` | 2000 |
| `max_tx_payload_str_len` | 65536 |
| `max_tx_payload_nodes` | 50000 |

### 3.7 SYSTEM Transaction Replay Binding

Mutating SYSTEM transactions are protocol authority actions, not proposer discretion.
A received block MUST reject a SYSTEM tx before domain apply unless the tx is bound
to locally recomputed deterministic scheduler output.

Follower-side replay MUST validate at least:

- `_system_queue_id`
- `_due_height`
- queue item existence
- tx type
- queue phase
- signer
- parent reference, when present
- canonical payload hash
- once/emitted-height status

This rule applies to received blocks as well as locally built block candidates.

## 4. Secrets and Configuration

### 4.1 Secret Sources

Secrets MUST come from:

- secure environment injection
- file-based secret mounts

Not allowed:

- hardcoded values
- frontend exposure
- fallback demo values

### 4.2 Required Secret Inventory

- node private key
- authority signer keys
- ingress/tunnel credentials where applicable

### 4.3 Secret Validation

Startup MUST:

- verify presence
- verify format
- never print secret values

## 5. Frontend Production Contract

Production frontend MUST:

- use a single pinned API base
- not allow runtime editing of API base
- not allow localhost fallback

## 6. Bootstrap and Genesis Policy

Bootstrap/genesis logic MUST exist only in:

- dedicated bootstrap scripts
- operator tooling
- test environments

It MUST NOT exist in the normal production runtime or normal user-facing UI.

## 7. Helper Execution Policy

Helpers remain subordinate to HotStuff and MUST remain fail-closed behind explicit production gates until serial equivalence, deterministic restart behavior, replay-safe receipts, fallback behavior, and adversarial testing are proven.

When helper execution metadata is present in a block, it MUST be committed through `helper_execution_root` in the block header. A node MUST reject helper metadata/root mismatches, missing metadata for a committed root, or unexpected helper metadata without the required commitment in helper-enabled production contexts.

## 8. Operator Bundle Requirements

Production deployment MUST NOT rely on dev tooling.

Required:

- `python3 -S scripts/check_tx_canon_artifacts.py` passes
- `bash scripts/secret_guard.sh` passes
- `bash scripts/verify_release_tree.sh` passes
- `bash scripts/verify_release_dependencies.sh` passes
- release tree contains no local runtime DBs, devnet state, demo secrets, or generated bootstrap secret/result artifacts
- backend `requirements.lock` and `requirements-dev.lock` are committed, pinned, and hashed
- frontend `web/package-lock.json` is committed and used with `npm ci`
- dedicated production start script
- dedicated stop script
- structured logging
- health checks
- restart procedures

## 9. Launch Gate Checklist

Production launch requires:

- full test suite passing
- tx canon, secret guard, release tree, and dependency-lock verification passing
- clean production startup in a fresh environment
- restart equivalence verified
- onboarding flow verified
- posting/media flows verified
- secrets validated
- no dev fallbacks reachable
- public snapshots and unauthenticated account reads redact sensitive session/device/evidence internals
- helper mode either disabled or fully proven

## 10. Enforcement

Violations of this production posture MUST result in:

- startup failure
- build failure
- deployment rejection

<!-- WEALL_RELEASE_TRUTH_CHECKPOINT_START -->
## Release truth checkpoint

- Current transaction canon checkpoint: **236 transaction types**, canon version **1.25.0**.
- Latest full backend test checkpoint: **3636 passed, 3 warnings**.
- Proof-of-Humanity model: **Tier 0 = account only**, **Tier 1 = native async verified human**, **Tier 2 = native live verified human**.
- Live PoH uses adaptive integer quorum with up to **10 jurors**, up to **3 active reviewers**, and up to **7 watchers**.
- There is no required user-facing Tier 3.
- No required email, no required SMTP, no required DNS, and no required named hosting provider are part of PoH authority.
- Production validator posture must **fail closed** unless BFT is enabled and effective for validator/service signing.
- SYSTEM txs received in blocks must be scheduler-bound before apply.
- Helper execution metadata is committed by `helper_execution_root` when present.
- Production tx payload limits are **profile-pinned** and local payload env overrides must not change consensus validity.
- Public API redaction is required for public snapshots and unauthenticated account reads.
- Release safety requires tx canon artifact verification, secret guard, release tree verification, and dependency-lock verification.
<!-- WEALL_RELEASE_TRUTH_CHECKPOINT_END -->

Current tx canon checkpoint: 236 tx types, version 1.25.0.
