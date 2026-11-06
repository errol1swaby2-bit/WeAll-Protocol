# First canonical solo-bootstrap finality — F1b design review

**Status:** Open design decision, NON-NORMATIVE. No production consensus change is authorized by this document.  
**Scope:** Draft PR #82, issue #87. Do not treat this note as launch acceptance or an independent security review.  
**Source baseline:** `18f0352ef9a289c70ef4a9a109f59cdd7d79f453` and its subsequent F1b genesis/attestation test commits. Review exact-head CI separately.

## Observed production contracts

1. `scripts/build_production_genesis_manifest.py` produces the height-zero genesis record with one active validator/operator in `roles` and matching validator key registries. It does not predeclare a BFT-active `consensus.validator_set`. The current `configs/genesis.ledger.prod.json` has `height=0`, `finalized=false`, and one genesis role validator. In contrast, the earlier signed-governance F1b fixture starts with an **empty** authoritative consensus active set and cannot establish genesis solo liveness.
2. `runtime/apply/consensus.py::_apply_block_attest` records an attestation against an already-known block/height. `BLOCK_ATTEST` is a validator-origin user transaction. Public ingress and canonical block admission must authenticate its ML-DSA account signature; a direct domain-apply fixture is not signature proof.
3. `runtime/apply/consensus.py::_apply_block_finalize` requires a SYSTEM envelope and a parent. Outside its BFT receipt-driven path, production-default `enforce_finality_attestations` requires more than two-thirds of the active validator set to have a yes attestation. It then updates the canonical finalized record. When it finalizes **height 1**, it enqueues `EPOCH_OPEN(1)` only if epoch 1 is not already established.
4. `runtime/bft_finality_bridge.py::schedule_bft_finality_receipt` currently derives deterministic canonical `BLOCK_FINALIZE` work from an admitted three-chain HotStuff justify-QC, which is available only after BFT activation. The shared normal leader/replay scheduler does not currently derive the **first** solo-bootstrap finalization from an admitted one-validator attestation.
5. `BLOCK_FINALIZE` is a SYSTEM, receipt-only transaction with canonical `parent_tx_type=BLOCK_ATTEST`; `EPOCH_OPEN` is likewise SYSTEM/receipt-only with canonical `parent_tx_type=BLOCK_FINALIZE`. `runtime/system_tx_engine.py` and block build/replay enforce deterministic queue IDs, emission, and same-block `EPOCH_OPEN` lineage witnesses. The initial-finality producer **cannot** simply push a synthetic SYSTEM receipt into a test fixture and call it authorized consensus.

## Existing positive and negative evidence

- `tests/test_f1b_governance_execute_canonical_two_block.py` covers actual signed proposal/votes, canonical `GOV_EXECUTE -> VALIDATOR_SET_UPDATE`, replayable **pending** four-validator membership, and a noncommitted epoch-activation projection; it also proves another committed block cannot silently activate the pending set.
- `tests/test_p0_03_production_composition.py` covers real four-executor signed HotStuff QC chains, rejected transaction receipt, `BLOCK_FINALIZE`, and restart, but starts from a different fixture-seeded **already active** validator set and transition bridge.
- The new genesis-bootstrap attestation test in the F1b governance test file is intended to prove that the **real genesis builder** can seed a solo validator whose genuine signed `BLOCK_ATTEST` is accepted, canonically committed, follower-replayed, and durable. It explicitly does **not** assert a canonical `BLOCK_FINALIZE` when none is scheduled, and it is not an end-to-end handoff proof. Confirm this claim only after exact-head CI.

## Candidate to review, NOT an implemented rule

A plausible minimal transition is a **state-derived solo-bootstrap finality scheduler** that uses the existing canonical attestation state and existing SYSTEM queue/emitter; it must not introduce a new HotStuff engine, new operator override, or synthetic QC.

The candidate would require **all** of:

- A uniquely authenticated, canonical active singleton validator and explicit solo-bootstrap phase, rather than just a process-local operator setting, untrusted pending set, or bare key registry entry.
- A canonical block at height 1 and a validly ML-DSA-signed `BLOCK_ATTEST` for that exact block/height by that active validator, included in a **previously committed** block and verifiable through independently replayed ancestry. No same-block uncommitted vote may finalize history.
- A deterministic, replay-identical finalizer selection at the first eligible height, monotonic non-conflicting finalized ancestry, strict exact parent/proof binding, and a single `BLOCK_FINALIZE` in the mandatory SYSTEM pre-phase. No direct user/SYSTEM submission substitutes for scheduler provenance.
- Existing `BLOCK_FINALIZE -> EPOCH_OPEN(1)` same-block witness and queue rules; atomic state/root agreement in an independent follower and persistence across restart.
- The resulting validator activation may use only the **already signed and governance-approved** pending four-validator set. It must preserve the exact validator identities, epoch, set hash, transition bridge, and block ancestry that the HotStuff stage later signs.
- Clear exit/fail-closed semantics at the initial finalized epoch boundary; the solo lane must never sign or assert a HotStuff QC and must never be reenabled by environment variables, an operator command, or replay.

## Decisions required before production implementation

1. **Authority and constitutional sufficiency:** Is one verified, signed solo-validator `BLOCK_ATTEST` enough for the first canonical finality, or is a separately committed genesis-witness certificate required? A genesis witness attestation is not automatically the same thing as a validator BLOCK_ATTEST. Reconcile with BSTR-032.
2. **Parent proof format:** Specify how the finalized target and authenticated attesting transaction are bound to `BLOCK_FINALIZE` (canonical committed attestation transaction ID, signed certificate, or another exact deterministic witness) without inventing a privileged SYSTEM parent.
3. **Epoch timing:** When signed governance completes after some solo blocks, can a delayed first-height finalizer safely activate the pending set at epoch 1, or must governance select a future epoch? Preserve the sequential `EPOCH_OPEN` and no-skipped-epoch rules.
4. **Genesis metadata:** Normalize or explicitly version the difference between the production genesis `finalized=false` placeholder and runtime `finalized={height,block_id}` representation; do not rewrite historical state silently.
5. **Security/Byzantine matrix:** Require failed/forged/nonmember/duplicate/equivocating/stale-key attestation refusal; incorrect signer/chain/block-height/parent/proof refusal; restart, cross-process follower replay, missing-attestation liveness behavior, then actual four-process partitions (3+1, 2+2), conflicting QCs and recovery.
6. **Release gates:** GEN-002 and BSTR-023 in the attached candidate v2.0 specification permit labeled single-validator genesis with **no BFT/decentralization claim**. GEN-007 ends exceptional genesis authority after height zero. These are draft *normative targets*, not already-verified production consensus rules. No post-genesis founder shortcut may be presumed.

## Acceptance rule

Do not close issue #87 or merge PR #82 on test-only projection, synthetic QC, direct ledger edits, quorum bypass, or copied `bft_active` state. The positive gate must prove *one uninterrupted canonical chain* from genesis authority and signed governance to witnessed epoch activation, real signed four-validator 3-chain QCs, canonical rejected receipt/finality, and durable independent-process Byzantine/restart convergence.

**Until the missing finality authority/proof contract is decided, retain DRAFT / NO-GO.**
