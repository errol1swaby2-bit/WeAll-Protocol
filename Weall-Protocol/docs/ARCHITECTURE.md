# Current Architecture and Authority Map

Status: current reviewer map for the checked-out implementation. This document describes repository authority and runtime flow; it is not a claim of public-beta or mainnet readiness and it does not promote the V2 target specification above the current executable implementation.

## Authority hierarchy

Use these layers in order when reviewing the current node:

1. **Exact Git commit and tree** identify the implementation under review. Reviewer evidence is only exact-subject evidence when it records both.
2. **Current executable source and configuration** live primarily under `src/weall/`, the active transaction canon/configuration inputs, and checked-in launch/runtime configuration.
3. **Generated current artifacts** under `generated/` and `web/src/generated/` are deterministic derivatives and evidence. They must be fresh, but they do not replace runtime source authority.
4. **Reviewer evidence** under `docs/reviewer/`, `docs/audit/`, `audit-metadata/`, and `artifacts/` describes proof scope. Historical transcripts prove only their recorded subject.
5. **V2 target specification material** under `specs/v2/source/` and `generated/v2/target_*` describes the target/specification program. It does not silently override current compatibility/runtime behavior.

For mutable transaction counts and versions, read `generated/tx_index.json` rather than copying numbers from prose.

## Runtime component map

```text
client / reviewer / frontend
        |
        v
FastAPI routes (src/weall/api/)
        |
        +--> authentication / signature / request policy
        |
        v
transaction admission and mempool
        |
        v
block construction / BFT proposal and admission
        |
        v
canonical transaction application
        |
        v
atomic block commit + SQLite/durable state
        |
        +--> receipts / tx status / diagnostics
        +--> replay / restart / observer catch-up

P2P transport <----> BFT / block admission
                       |
                       +--> validator-set / QC / timeout state

helper planning/execution --> signed helper receipts/certificates --> deterministic merge
        (production helper execution remains launch-gated)

PoH APIs / review state --> canonical PoH transactions/state
        (fresh positive production human-authority progression remains scope-closed)

governance / treasury / economics transactions --> canonical state transition handlers
        (live economics remains disabled/unclaimed)
```

## Transaction lifecycle

The reviewer should trace ordinary user transactions through these boundaries:

1. HTTP/API transaction entry under `src/weall/api/`.
2. Canon/schema and authentication/signature checks.
3. Admission into the mempool.
4. Deterministic block selection and proposal construction.
5. Follower/BFT block admission.
6. Canonical apply/state-transition logic.
7. Atomic block, transaction-index, receipt, and state persistence.
8. Status/replay/restart paths that must reproduce the same canonical result.

The generated all-canon and semantic-assurance artifacts are evidence about this flow; they are not themselves the executor.

## Consensus and block authority

Current consensus-related implementation is concentrated in runtime modules such as:

- `src/weall/runtime/bft_hotstuff.py`
- `src/weall/runtime/block_admission.py`
- `src/weall/runtime/block_commit.py`
- validator-set, QC, timeout, and replay helpers referenced by those modules.

Public multi-validator production readiness remains separately gated. Local or controlled rehearsal success is not equivalent to independent public-validator evidence.

## Persistence and restart boundary

Durable authority is backed by the repository's SQLite/state persistence path, including `src/weall/runtime/sqlite_db.py` and the block/state persistence code used by the executor. Review restart safety by comparing the persisted block/tip/state/transaction identity with the in-memory publication path; an in-memory object is not independently authoritative after restart.

## PoH boundary

PoH HTTP surfaces are under `src/weall/api/routes_public_parts/poh.py` with canonical state changes flowing through protocol transaction/runtime paths. Tier labels are compatibility/rehearsal states and are not proof of global one-human uniqueness. The production profile keeps fresh positive human-authority progression fail-closed pending uniqueness/entropy closure.

## Governance, treasury, and economics

Governance, dispute, group, treasury, transfer, fee, reward, and related mutations are protocol transactions and must be reviewed through the same admission/apply/commit/replay lifecycle. Live economics is currently disabled/unclaimed; locked economics code is still security-relevant before activation.

## Helper execution boundary

Helper code includes runtime surfaces such as:

- `src/weall/runtime/parallel_execution.py`
- `src/weall/runtime/helper_receipts.py`
- `src/weall/runtime/helper_certificates.py`
- `src/weall/runtime/helper_merge_admission.py`

Helpers may accelerate execution but do not replace consensus. Production helper execution remains gated until the helper safety requirements, including deterministic/serial equivalence, context-bound signatures, Byzantine rejection, restart safety, and multi-node non-divergence evidence, are satisfied.

## P2P and trust boundaries

Network peers, peer identity, state sync, raw state/block reads, observer forwarding, and BFT messages are separate trust surfaces. Public chain-visible status is not the same thing as operator incident forensics. Operator/state-sync/raw-read credentials are local operational authority and do not grant protocol governance or validator authority.

## API and frontend authority boundary

The frontend is a consumer of backend/public protocol state and generated status metadata. Browser state is not protocol authority. Generated frontend status in `web/src/generated/protocolStatus.ts` is a compiled truth/provenance surface; fields describing V2 specification provenance must not be interpreted as the current build commit unless explicitly named as such.

## Current versus target specification hierarchy

- **Current implementation:** checked-out source/configuration plus its current compatibility canon and runtime behavior.
- **Generated current evidence:** deterministic outputs proving bounded repository consistency.
- **V2 specification source:** `specs/v2/source/`, which drives generated V2 registers and target contracts.
- **V2 target outputs:** future/target contracts and mechanism descriptions; they are not automatic runtime authority.
- **Historical audit/evidence:** immutable evidence for the exact subject recorded, not current behavior unless revalidated.

## Disabled or launch-gated surfaces

The current reviewer boundary keeps the following stronger claims disabled or explicitly gated:

- public beta and mainnet readiness;
- independent public multi-validator/validator readiness;
- live economics;
- automatic upgrade/migration execution;
- production helper execution;
- fresh positive production PoH human-authority progression pending uniqueness/entropy closure;
- completed production cryptographic review and legal/compliance approval.

Read `docs/reviewer/START_HERE.md`, `docs/CURRENT_VERIFIED_CLAIMS.md`, and the generated blocker/release manifests for the exact current claim boundary.

## Legacy and shadow material

Historical milestone documents, old evidence transcripts, compatibility paths, and target-spec derivatives can be valuable context but must not be mistaken for current runtime authority. When a generated/static inventory disagrees with the mounted/runtime path, the discrepancy is an audit finding until the authority relationship is explicitly resolved.

## Reviewer entry points

- `docs/reviewer/START_HERE.md` — choose the correct verification path and evidence strength.
- `docs/reviewer/README_TO_IMPLEMENTATION_TRACEABILITY.md` — claim/source traceability.
- `docs/reviewer/EVIDENCE_INDEX.md` — evidence classes and blocker meaning.
- `docs/V2_SPEC_COMPILER.md` — V2 source/derivative assurance boundary.
- `docs/audit/` and `audit-metadata/` — active audit/closure records.
