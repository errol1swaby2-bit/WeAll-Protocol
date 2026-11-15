# PR #93 — reputation penalty provenance: local root and signed-QC review

**Status: DRAFT / GENESIS NO-GO / NO REPUTATION OR BAN AUTHORIZATION.**

This docket distinguishes three different claims that must never be conflated.

1. **Local canonical-history consistency:** durable blocks rebind to canonical header,
   body, and receipt commitments; consecutive hashes link; local snapshot
   `compute_state_root` matches the stored tip header's committed post-apply
   `state_root`. This is local evidence only. A copied or fabricated SQLite
   database can remain perfectly self-consistent.
2. **Caller-supplied signed BFT evidence:** three consecutive durable blocks each
   have a full QC whose ML-DSA vote signatures verify against an explicit,
   caller-supplied same-epoch validator-key registry. Each QC binds the exact
   chain, view, block ID, block hash, parent, validator epoch and set hash.
   Views must increase; three certified blocks must link. This is a conservative
   *review profile*, not an alteration of production HotStuff's three-chain
   receipt semantics.
3. **Independently authorized constitutional enforcement:** remains **unproven**.
   A caller can generate its own valid keypairs, signatures and internally
   consistent certificates. Neither module establishes that signers were
   independently governed active validators at the relevant historical epoch,
   that those QC artifacts were observed in the authorized network, that replay
   establishes the consensus finalized decision, or that a juror/appeal process
   constitutionally authorized the parent dispute and resulting penalty.

## Source-bound evidence surfaces

- `scripts/reputation_delta_origin_review.py` reads production executor
  `read_state` and `get_block_by_height`, checks bounded canonical history,
  exact queue and claimed parent, and now compares recomputed persisted snapshot
  root against the canonical tip header state root.
- `scripts/reputation_parent_finality_review.py` performs a **separate** bounded
  three-block read and verifies a strictly explicit signed QC triplet against
  caller-supplied validator keys. No node-local `state["finalized"]` claim or
  QC supplied by that same node is independently authoritative.
- `src/weall/runtime/bft_hotstuff.py::verify_qc` checks signed votes against
  registered keys and the quorum threshold; the review requires exact vote
  metadata rather than relying on permissive legacy inheritance.
- `src/weall/runtime/bft_finality_bridge.py::finalized_target_from_justify_qc`
  is deliberately **structural**; cryptographic proof and admission have to be
  established separately before its three-chain projection can be treated as
  production evidence. The strict three-QC review triplet is not substituted
  into that production path.
- `tests/test_pr93_persisted_reputation_root_review.py` uses real local SQLite
  block commits and a tampered snapshot reader.
- `tests/test_pr93_reputation_parent_qc_three_chain_review.py` uses real local
  block commits and real ML-DSA signatures, including adversarial QC and
  block-history substitutions.
- Dedicated PR93 exact-head workflows provide scoped, non-authoritative test
  evidence. They do **not** waive failed semantic review gates.

## Known unclosed trust boundaries

| Boundary | Required closure |
| --- | --- |
| Validator registry | Independently pin and authenticate signer keys, roles, epoch and authority transitions at each historical height |
| BFT transcript | Retain and verify the actual production vote/QC artifacts and admissible HotStuff finalization chain, including restart/replay and epoch rotation |
| Source history | Bind the authorized dispute opening, resolution parent transaction, successful committed receipt, deterministic child queue and post-apply reputation state |
| Constitutional procedure | Validate real juror assignment, votes, conflicts, severity, reasoned decision, automatic severe appeal, timing, waiver and reinstatement |
| V2 source semantics | Resolve and sign off outstanding semantic-review digests; no self-approval by regenerating evidence hashes |
| Release | Exact-final-head Backend, Web, reviewer and constitutional gates, independent operator witnesses and replay |

A complete synthetic three-QC triplet may legitimately return
`cryptographic_three_chain_candidate=true` while
`independent_bft_finality_verified=false` and
`constitutional_authorization=NOT_ESTABLISHED`.

**Never infer `may_enqueue_reputation_delta=true` or
`may_ban_account=true` from either review. No production consensus or state
applier has been changed by these review-only increments. PR #93 stays draft.**
