# Account Registration Scarcity Invariant (A15-F003)

## Status and scope

This document records the bounded remediation for A15-F003. It closes the **free fresh-key permanent-state creation** primitive. It does **not** claim that WeAll has solved global one-human uniqueness (A08), and it does not claim a hard lifetime maximum on all legitimate human accounts.

## Consensus invariant

When `params.account_registration_work_required` is true, an `ACCOUNT_REGISTER` transaction MUST carry a supported registration-work version and a work nonce whose SHA-256 digest has at least `params.account_registration_work_difficulty_bits` leading zero bits.

The work preimage is domain-separated and commits to:

- the registration-work domain and version;
- transaction `chain_id`;
- signer / new account ID;
- transaction nonce;
- transaction signature profile;
- parent;
- the entire canonical registration payload excluding only `registration_work_version` and `registration_work_nonce`;
- the work nonce.

The registration-work fields remain inside the transaction payload and are therefore covered by the normal transaction signature.

Production and public-testnet genesis identities require registration work with a finite nonzero difficulty. Historical/ad-hoc states that do not enable the consensus parameter remain replay-compatible.

## Fail-closed rules

A required policy fails closed when its enable flag or difficulty is malformed, when difficulty is outside the supported range, when the proof version is absent/unsupported, when the work nonce is outside the JavaScript-safe integer range, or when the digest does not meet the required difficulty.

Public admission performs this cheap SHA-256 check before ML-DSA signature verification. Block admission repeats it, and `_apply_account_register` verifies it again as defense in depth before materializing the permanent Tier-0 account subtree.

## Accessibility boundary

Registration work is not a protocol fee, deposit, rent, stake, or purchase. It imposes a deterministic one-time computation on permanent account creation while retaining fee-free identity onboarding. The browser solves the proof locally before signing; public nodes expose only the consensus work policy and do not act as proof-solving oracles.

## Security boundary

This mechanism establishes **marginal computational scarcity** for each independently bound permanent registration. A proof solved for one signer, nonce, chain, or registration payload cannot be reused for another. It does not equate an account with a unique physical human, and high-resource attackers can still spend proportionally greater computation to create more accounts. Human uniqueness remains separately owned by A08.

## Closure evidence

Required focused evidence includes:

- production/testnet genesis policy is explicitly enabled and nonzero;
- malformed required policy fails closed;
- work is bound to signer, nonce, and registration payload;
- one account's proof does not bypass many-signer admission;
- strict payload schema carries the signed work fields;
- normal browser onboarding obtains policy, solves work locally, then signs/submits;
- 100k and 1M synthetic Tier-0-shaped state cardinality benchmarks are available through `scripts/bench_a15_f003_account_cardinality.py`;
- full backend, web, canon/current-generated, production-readiness, and exact-head CI remain green.

The cardinality benchmark is scaling evidence, not a production performance certification.
