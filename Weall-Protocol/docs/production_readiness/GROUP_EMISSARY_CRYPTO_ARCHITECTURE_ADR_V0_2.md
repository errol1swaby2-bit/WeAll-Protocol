# ADR GEB-0001 — Confidential group emissary ballots: research-track selection

**Date:** 2026-11-10  
**Status:** RESEARCH TRACK SELECTED; NO PRODUCTION CRYPTOGRAPHIC SUITE SELECTED; NO ACTIVATION  
**Applies to:** WeAll group emissary elections and any later constitutionally approved confidential ranked-ballot transport.  
**Inputs:** `GROUP_EMISSARY_CONFIDENTIAL_BALLOT_DESIGN_V0_1.md`, current runtime and transaction schema, independent public cryptographic references.  
**Machine-readable disposition:** `../../specs/research/group_emissary_ballot_architecture_v0_1.json`.

## Decision and scope

**Select a classical verifiable shuffle / threshold-decryption model as a *feasibility reference*, not as a deployable security solution.** The preferred *architectural shape* is:

1. freeze and commit the eligible electorate plus canonical candidate order and all election/version/height parameters;
2. anonymously prove membership and create an election-bound one-use nullifier without exposing a link to the public human roster;
3. encrypt a complete ranked choice, verify the proof and ciphertext/election binding before canonical admission, and retain an unlinkable inclusion/receipt trail;
4. after the election closes and sufficient independent trustees cooperate, publicly verify shuffle and decryption of the now-unlinked complete rankings;
5. feed the deterministically encoded, decrypted rankings to the existing STV tally, independently reproduce all transfers/ties/exhaustion, then publish an auditable transcript and only then grant any elected emissary or signer authority.

This is **a research hypothesis**. Neither its cryptographic privacy nor its compatibility with a post-quantum threat model has been proved. The default release decision remains **NO-GO**. No code in this increment signs, submits, admits, verifies, counts, decrypts or authorizes a confidential ballot. **No new consensus transaction type, cryptographic primitive, or ballot authority is introduced or authorized by this ADR.**

### Existing implementation constraint

The current `GROUP_EMISSARY_BALLOT_CAST` schema has `signer` alongside plaintext `ranking`. Strict ballot mode aggregates vote choices in apply state and stores a nullifier, **but the transmitted transaction remains attributable**. The existing `_apply_group_emissary_election_finalize` reconstructs whole rankings, uses `_stv_winners`, and updates `group.emissaries`, `group.signers` and group treasury signers/threshold after a nonempty result. Those authority effects are forbidden until a new scheme proves its tally. Historical plain-text transaction semantics must not be rewritten in place.

## Candidate comparison

| Candidate | What it could prove | Main blocker | Decision |
|---|---|---|---|
| A. Classical verifiable shuffle + threshold decryption | Whole rankings can be shuffled, decrypted and fed to existing deterministic STV; classical literature/tooling exists | Conventional public-key shuffle/decrypt primitives are not quantum-resistant; anonymous eligibility remains separate | **Research baseline only** |
| B. PQ anonymous membership + encrypted ranks + publicly verifiable shuffle/decryption | Plausible long-term direction for confidentiality and ranked STV | No selected reviewed end-to-end membership, PQ encryption, threshold protocol and proof verifier; interoperability/performance unknown | **Research candidate, no implementation authorization** |
| C. Zero-knowledge proof of private STV tally | Potential to verify winners without disclosing every individual decrypted ranking | Transfer-heavy full STV circuit and soundness, proof sizes, trust setup and quantum-resistance need independent validation | **Research candidate** |
| D. Homomorphic addition of first-choice totals | Efficient additive tally for non-ranked contests | Does not prove transfers, eliminations, exhausted partial ballots or full STV results | **Reject as drop-in STV** |
| E. ML-KEM as “the voting encryption scheme” | Standardized PQ key establishment component | A KEM alone does not give anonymous eligibility, verifiable mixing, trustee key sharing, threshold election or STV proof | **Reject as complete protocol** |

**External evidence, not repo results:** NIST FIPS 203 specifies **ML-KEM**, a key-encapsulation mechanism, and FIPS 204 specifies **ML-DSA**, a signature scheme. Neither standard defines a full end-to-end anonymous ranked election. ElectionGuard's glossary says its current protocol does not support ranked-choice voting, so it cannot be treated as a proven drop-in STV engine. Verificatum documents classical verifiable mix-net tooling, including grouped ciphertext processing for ranked elections, but does **not** establish WeAll-grade PQ end-to-end security or integration. Sources are listed below.

## Intended ranked-redistribution semantics (clarified 2026-11-10)

WeAll's protocol architect clarified that **after a candidate fills a seat, all votes assigned to that candidate move at full weight to the voter's next still-eligible preferred candidate**. That redistribution repeats for subsequent seats. Thus the earlier T0 description of this transfer as a retained-quota *defect* was incorrect and is withdrawn. The existing helper implements the intended full-weight transfer, although it should not be represented as conventional surplus-retaining Droop STV. The proposed private tally, shuffle/decryption reference and public verifiability work must reproduce **WeAll's intended sequential redistribution**, not silently substitute conventional STV. Other tally policy choices (tie handling, candidate fill, quorum, exhaustion) remain reviewable independently.

## Security requirements that rule out a short-cut

- **No attributed envelope:** the public ballot transaction, mempool and block history cannot include both a registered-account signer and a ballot ciphertext/choice that can be linked by deterministic identity, timing, plaintext or proof witness. A new proof-bearing admission mechanism needs its own versioned schema; do not bypass SYSTEM restrictions or reuse `GROUP_EMISSARY_BALLOT_CAST`.
- **No enumerated nullifier:** a hash of a known account and election ID is guessable by anyone with the public roster. The nullifier must have a nonpublic witness and a public, independently verifiable proof of correct eligibility and one-time use.
- **No unverifiable STV:** the canonical tally transcript must bind every admitted ballot commitment through accepted shuffle/decryption proofs to the same complete ranked-choice multiset and the current deterministic STV implementation. If only aggregate first-choice counts are available, no winner/signer/treasury update is permissible.
- **No trustee capture:** choose threshold assumptions and public roster/attestation rules; test malicious trustees, absent shares, premature decryption, Byzantine and censored relays. Independent trustee selection is a governance/security problem, not merely threshold algebra.
- **No “PQC by signature”:** ML-DSA signatures can authenticate registered identity but do not make the ballot anonymous. ML-KEM is not itself a threshold verifiable mix-net; a post-quantum claim requires the *whole* membership, encryption, shuffle/tally proof, hash/commitment and ceremony suite to be reviewed.
- **No validator randomness for consensus:** cryptographic proof generation can be randomized off-chain, but verification, proof decoding, state transitions and winner derivation must be deterministic and bounded on each validator.
- **No public production beta by assertion:** reviewer agreement, a passing focused test, or a controlled-testnet ballot profile do not establish constitutional approval or release readiness.

## Research experiment ladder (no consensus or production deployment)

1. **T0 — Golden election and STV vectors.** Extract canonical `_stv_winners` cases: five-seat minimum, candidate normalization/ties, partial rankings, abstentions/no-decision, duplicate ballots, and rank exhaustion. Bind all vectors to checked-in tests and independent reimplementation. No crypto assumed.
2. **T1 — Classical reference model in an isolated research harness.** Prove by deterministic checks that a shuffled/decrypted multiset of complete rankings, irrespective of mixing order, gives exactly the same STV result. Evaluate malicious shuffle, invalid ciphertext proof, duplicate nullifier, wrong snapshot or election, missing trustee and premature decryption. A classical demonstration is **not PQ release proof**.
3. **T2 — Feasibility matrix.** Compare candidate B and C against T1 with independent academic/security review. Document exact primitives, formal security models, parameter sizes, libraries, licenses, implementation maturity and the surviving quantum attacks. If no end-to-end sound scheme exists, return **NO IMPLEMENTATION** rather than combine incompatible libraries.
4. **T3 — Hardware/resource measurements.** On a baseline **4 GB RAM laptop** and a mainstream laptop and validator reference, benchmark 10/100/1,000/10,000 voters × 5/20/100 candidates. Record per-voter proof time, median/p95 verification, peak RSS, ciphertext and proof bytes, cumulative chain size, shuffle/proof creation and verification, trustee dropout recovery, deterministic STV replay, restart and observer catch-up. These are proposed experimental fixtures **not performance claims or accepted resource ceilings**. Review and set caps before any versioned tx.
5. **T4 — Security and governance gating.** Independent cryptanalysis, adversarial browser/node/replay proof, archive/observer privacy scan, explicit versioned activation from canonical constitutional authority, non-skippable release gates. Only then authorize a new tx schema and testnet implementation.

### Artifacts and provenance for research completion

Every experiment must record exact source commit, dependency lock/hash, primitive versions, election fixture digest, canonical election and candidate roots, test vectors, node hardware/OS, wall-time/cpu/peak-RSS/proof bytes and seed/reproducibility rules. Verifier failures must fail closed. Include a **negative evidence** section for claims not demonstrated; no invented benchmark, proof size, signature throughput, collusion threshold or cryptographic safety classification.

## Residual risk and unknowns

We have **not** selected: a membership proof, PQ-compatible commitments, anonymous credential issuance/recovery, election key-generation ceremony, threshold PQ decryption, shuffle proof system, trusted setup, proof verification implementation, privacy-preserving network relay, metadata protection, or liability/governance rules for a missing trustee. A mixed classical/PQ construction cannot claim end-to-end quantum resistance merely because one component is ML-KEM. Revealed anonymous rankings may still enable vote inference when the electorate is tiny or choices are distinctive; coercion resistance is not established even if voter-to-ballot linkage is cryptographically removed.

## Sources reviewed and limits

- [NIST FIPS 203 — ML-KEM](https://csrc.nist.gov/pubs/fips/203/final) (standardizes KEM; does not specify voting).
- [NIST FIPS 204 — ML-DSA](https://csrc.nist.gov/pubs/fips/204/final) (standardizes signatures; does not specify anonymous ballots).
- [ElectionGuard glossary](https://electionguard.vote/overview/Glossary/) (states ranked-choice voting not currently supported as presented by the project; this is not a test of WeAll).
- [Verificatum mix-net documentation](https://www.verificatum.org/html/product_vmn.html) (vendor-documented classical mix-net capabilities; independent evaluation of use in WeAll and PQ suitability outstanding).

These references support the **comparison**, not a claim that any candidate is production secure for WeAll.

## Binding stop rules

The companion machine-readable review manifest must always report:
`document_status=RESEARCH_ONLY_NO_ACTIVATION`, `release_decision=NO_GO`,
`selected_production_primitive_suite=null`, `claimed_post_quantum_security=false`,
`enabled_ballot_submission=false`, and `authorized_new_consensus_tx_types=[]`.
These are **research-artifact** checks, not substitutes for production consensus admission rules.

PR #88 and PR #81 remain **DRAFT / NO-GO**. A later change to those dispositions requires independent review and a separate explicit authorization process.
