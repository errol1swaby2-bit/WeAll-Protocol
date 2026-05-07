# WeAll Protocol — Production Posture Specification

Version: 1.0  
Applies to: WeAll Genesis Node (HotStuff BFT runtime)  
Status: REQUIRED for public-validator and production deployment

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

No implicit default is allowed.

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

### 3.5 Production Consensus Profile Pinning

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

## 8. Operator Bundle Requirements

Production deployment MUST NOT rely on dev tooling.

Required:

- `python3 -S scripts/check_tx_canon_artifacts.py` passes
- `bash scripts/secret_guard.sh` passes
- `bash scripts/verify_release_tree.sh` passes
- release tree contains no local runtime DBs, devnet state, demo secrets, or generated bootstrap secret/result artifacts
- dedicated production start script
- dedicated stop script
- structured logging
- health checks
- restart procedures

## 9. Launch Gate Checklist

Production launch requires:

- full test suite passing
- clean production startup in a fresh environment
- restart equivalence verified
- onboarding flow verified
- posting/media flows verified
- secrets validated
- no dev fallbacks reachable
- public snapshots and unauthenticated account reads redact private/session/device/evidence internals
- helper mode either disabled or fully proven

## 10. Enforcement

Violations of this production posture MUST result in:

- startup failure
- build failure
- deployment rejection

<!-- WEALL_RELEASE_TRUTH_CHECKPOINT_START -->
## Release truth checkpoint

- Current transaction canon checkpoint: **230 transaction types**, canon version **1.25.0**.
- Proof-of-Humanity model: **Tier 0 = account only**, **Tier 1 = native async verified human**, **Tier 2 = native live verified human**.
- There is no required user-facing Tier 3.
- No required email, no required Cloudflare, no required SMTP, and no required DNS are part of PoH authority.
- Production validator posture must **fail closed** unless BFT is enabled and effective for validator/service signing.
- Production tx payload limits are **profile-pinned** and local payload env overrides must not change consensus validity.
- Public API redaction is required for public snapshots and unauthenticated account reads.
- Release safety requires tx canon artifact verification, secret guard, and release tree verification.
<!-- WEALL_RELEASE_TRUTH_CHECKPOINT_END -->

