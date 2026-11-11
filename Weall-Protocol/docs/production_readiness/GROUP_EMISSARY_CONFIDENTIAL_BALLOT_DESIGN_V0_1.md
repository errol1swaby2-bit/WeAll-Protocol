# Group emissary confidential ranked ballots — threat model and design review v0.1

Status: **DESIGN INPUT ONLY / NOT IMPLEMENTED / NOT APPROVED**  
Applies to: WeAll Protocol group emissary elections.  
Decision authority: independent cryptographic review, constitutional governance, and explicit versioned launch activation.  
Reviewed implementation: PR #88 draft as of 2026-11-10. The reviewed code provides a **read-only** election projection and non-submitting, browser-memory-only preference rehearsal.

This document is deliberately not a consensus specification or approval to add a new cryptosystem.

## 1. Concrete blocker in today's code

The canonical `GROUP_EMISSARY_BALLOT_CAST` schema has `election_id` and a **plaintext** `ranking: list[str]` (`src/weall/runtime/tx_schema.py`). The ordinary transaction envelope also carries a stable `signer` and a signature. The browser signer (`web/src/auth/session.ts`) places the plaintext payload inside that signed envelope. The public `/v1/tx/submit` route (`src/weall/api/routes_public_parts/tx.py`) makes an immutable copy for forwarding; mempool propagation, archival block history, transaction indexes and inspection can retain that association.

`_apply_group_emissary_ballot_cast` (`src/weall/runtime/apply/groups.py`) checks election status, the ballot profile, height window, voter snapshot and candidate membership. Under the strict ballot profile, it aggregates identical rankings and stores election-bound voter nullifiers instead of retaining a voter-to-ranking map in the **apply-state ballot box**. That is an integrity/storage property, not transport confidentiality or unlinkability. The legacy ballot profile stores attributable ranking records. In neither profile does the current signed-envelope format hide the individual voter-to-choice link.

Additional leak surface: the apply metadata contains `voter`, and a transaction's signature and sender remain identifiable even if later public reads omit that field. Masking a frontend field or redacting an API projection cannot undo earlier exposure.

The read API correctly says `ballot_transport_privacy_verified=false`, `secret_ballot_supported=false` and `ballot_submission_authorized=false`. The frontend must keep real ballot submission disabled. A public signed ranking could be used only if a **separately specified, reviewed, explicitly consented public-ballot policy** authorized that disclosure; it must never be presented as anonymous or secret by default. That policy is not approved by this design.

## 2. Required privacy and integrity properties

1. **Eligibility without public identity-to-choice linkage.** One eligible human in the frozen election snapshot can cast at most one final accepted ballot, regardless of device, node, relay, or key rotations. Validation cannot depend on a publicly visible registered-account signer attached to the encrypted choice.
2. **Eligibility soundness.** Each accepted ballot proves snapshot membership and unique eligibility for the exact chain, group, election version and electorate root. Multiple human identities or duplicate credentials remain a separate PoH/Sybil resistance question; cryptographic voting cannot repair a false electorate.
3. **Choice confidentiality.** Observers of tx ingestion, gossip, mempool, block data, read APIs, proposer/juror tooling, and archived history must not see a voter's ranking. If any coalition of trustees/decrypters can reveal ballots, its honest-threshold assumption must be explicit. Network metadata/IP correlation also needs a separate threat model and mitigation.
4. **Unlinkability.** Ballot admission, replay protection and tally input must not reveal which voter cast which ranking. Hashing the existing voter ID into a deterministic nullifier without a zero-knowledge membership proof does **not** create anonymity; a public roster permits enumeration.
5. **No replay or substitution.** Domain-separated nullifiers, ciphertext/proof bindings and election-specific commitments must reject double votes, cross-election replay, re-ordering as a replacement, malformed rankings, stale-election proofs and late/early ballots deterministically.
6. **Verifiable deterministic STV.** Everyone must be able to recompute or cryptographically verify the accepted ciphertext set, shuffle/decryption proofs and complete ranked preferences used by the deterministic STV rules, including ties, exhaustion, rounding, vacancies and no-decision. If only opaque aggregate totals are revealed, the current STV contract cannot be verified from them.
7. **No premature reveal.** Decryption material must not be available before canonical close/finality. Threshold reveal, proof generation, trustee availability, transcript publication and recovery from missing shares require exact rules.
8. **Safe lifecycle and finality.** Admission is not canonical execution; only a persisted successful apply receipt counts. Validator replay, restart, reorg handling, independent-process two-node equality, observer catch-up and bounded resources must be shown. A failed apply must never consume eligibility, nullifier or nonce silently.
9. **Accessibility and censorship resistance.** Ordinary user hardware must remain viable. Multiple independent relays and inclusion evidence should resist single-operator veto. The design cannot assume each voter runs a heavy prover without measuring CPU, RAM, latency, memory growth and proof sizes.
10. **Post-quantum claim discipline.** WeAll's ML-DSA user signatures do not automatically make a mixnet, membership proof, encryption scheme or threshold decryption quantum-resistant. Any chosen primitive must have an independently evaluated security argument and migration story.

## 3. Candidate architecture — exploration, not a selected scheme

A plausible research route is **anonymous snapshot-membership credentials + per-election one-use nullifiers + threshold-encrypted ranked ballots + publicly verifiable mixing and decryption**. The components are not currently selected, implemented or proven compatible:

- Freeze an election snapshot commitment/root from canonical chain state; version and bind it to `chain_id`, `group_id`, `election_id`, start/end heights, roster and deterministic candidate ordering. Define whether per-group participant identity is unique and how key recovery/revocation affects eligibility.
- A voting proof would attest valid *membership* and a correct election-bound nullifier without revealing the member. Use a vetted, explicit credential/commitment and proof protocol; do not simply sign with the visible account or transmit a hashed account.
- Canonical admission would validate the proof, unique nullifier, statement/ciphertext binding, candidate domain, proof versions, payload limits, replay domain, and election-height gate. Relaying must not require exposing the originating account in the public transaction or receipt. Do not synthesize a fake `SYSTEM` signer or bypass existing canonical authorization.
- Encrypt a complete ranked ballot to an election-specific threshold public key. Set up independently controlled trustee shares through a public, auditable ceremony. Define collusion thresholds, missing trustee recovery, and who can decrypt when.
- At canonical close, use a *publicly verifiable mix/shuffle* to break ciphertext/inclusion linkage and verifiable threshold decryption of the shuffled ballots, then run the existing deterministic STV function over a canonical encoding. The proof verifier and accepted transcript must be deterministic across independent nodes.
- Publish the eligible snapshot commitment, accepted nullifier set or commitment, ciphertext commitments, shuffle/decryption proofs, STV input commitment, deterministic tally transcript, final winners/no-decision receipts and finalized heights. Publish no voter-to-choice link or identifying proof witness.
- Explicitly evaluate a cryptographic alternative such as a verifiable encrypted tally without shuffle; **do not assume** that simple homomorphic vote-counting handles full ranked STV. Document how every transfer and elimination is proved.

**Unresolved research choices:** primitive suite (including quantum resistance), credential issuance and revocation, zero-knowledge proof system, setup trust, threshold trustees and governance, metadata resistance, blinding/mix proof verifier, proof size/cost, censorship and denial-of-service, backup/recovery, data availability, challenge windows and liveness if trustees disappear. No cryptographic security or coercion resistance is claimed here.

## 4. Deterministic, versioned acceptance boundary (proposal)

Before any new ballot-bearing transaction type can be accepted:

- **Separate versioned transaction schema.** Never repurpose the historical `GROUP_EMISSARY_BALLOT_CAST` payload in place. Specify canonical bytes, commitments, proof formats, domain separation, weight limits, receipt codes, status behavior, activation height and migration. Preserve deterministic historical replay for old elections.
- **Independent security review.** Attackers include a public observer, colluding validators, compromised relays, duplicate credential issuers, compromised trustees, colluding voters and offline/replaying nodes. Require independent cryptographic analysis and reproducible test vectors before identifying any primitive suite as secure.
- **Admission and apply proof.** Invalid membership proof, nullifier reuse, unsupported version, wrong election/group/chain, stale snapshot, altered candidate list, malformed rank/ciphertext, premature/late submit, missing cryptographic key and proof sizes must fail closed. Rejected canonical receipts do not consume a final vote.
- **Tally proof.** Known STV vectors (ties, partial rankings, vacancies, no ballots), adversarial proofs, trustee dropout and recovery, deterministic re-execution, and independent proof verification across nodes. No unverified winner can seat emissaries or change a treasury signer set.
- **End-to-end privacy test.** A scan of **all** tx fields, admission logs, gossip messages, block bodies, receipts, read APIs and exported evidence cannot identify a vote from a voter account. Document limitations against device/IP or coerced screen observation rather than claiming complete coercion resistance.
- **Performance and availability proof.** Bound verifier cost, mempool admission cost, light-client cost, chain growth, proof/ballot bytes and optional prover work on ordinary consumer hardware.
- **Constitutional/release process.** Consensus authority remains in the protocol and governance process; reviewer evidence, independent implementation and exact-head green gates are necessary but not individually sufficient. The present PR #88 and base PR #81 remain **DRAFT / NO-GO**.

## 5. Acceptance matrix

| Claim | Present implementation | Required evidence before claim |
|---|---|---|
| Ranking order validated | Implemented in current apply path | Existing window/STV tests plus exact-head chain execution |
| Unique current signer voting | Strict-profile state nullifier checked | Historical replay and race/negative receipts; not equivalent to anonymity |
| Voter-choice confidentiality | **NO**: signer + plaintext ranking in signed envelope | Reviewed encrypted + unlinkable transport, archive/observer scan |
| Secret ballot | **NO** | Cryptographic unlinkability/confidentiality proof and adversarial test suite |
| Coercion resistance | **NOT ESTABLISHED** | Separate coercion threat model and appropriate protocol primitives |
| Verifiable private STV | **NO** | Verified mix/decrypt + canonical STV transcript and proof verifier |
| PQ cryptographic coverage | **NOT ESTABLISHED** | Independently reviewed end-to-end crypto assumptions |
| Production ballot activation | **NO** | Versioned activation and independent constitutional release gates |
| Frontend ballot action | **DISABLED** | All preceding gates plus multi-account acceptance and exact-head green CI |

## 6. Current engineering guardrail

`tests/test_group_emissary_ballot_transport_boundary.py` verifies the present signed-envelope exposure and read-model's false privacy/authorization flags, then labels the resulting evidence **current-risk characterization**, not a cryptographic security test. That test should be updated only as part of a reviewed, versioned replacement. It must never be made green by rewriting the public flags to true without independently verified proof.

No new consensus tx, encryption, credential, key material or ballot submission should be introduced under this document alone.
