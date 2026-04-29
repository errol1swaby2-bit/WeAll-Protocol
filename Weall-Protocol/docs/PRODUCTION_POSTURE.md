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
- PoH email secret when PoH email flow is enabled
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
- PoH email secret
- oracle authority keys
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
- helper mode either disabled or fully proven

## 10. Enforcement

Violations of this production posture MUST result in:

- startup failure
- build failure
- deployment rejection
