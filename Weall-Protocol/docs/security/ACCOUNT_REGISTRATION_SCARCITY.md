# Account Registration Scarcity Invariant (A15-F003)

## Status and scope

This document records the bounded remediation for A15-F003. It closes the **free, unbounded fresh-key permanent-state creation** primitive for the current production/public-testnet protocol version. It does **not** claim that WeAll has solved global one-human uniqueness (A08). The current ceiling is a resource-safety bound on root-visible account records, not a statement that one account equals one human or that a separately reviewed future protocol version can never raise or replace the ceiling.

## Consensus invariant

Production and the pinned public testnet enforce two independent account-creation scarcity controls:

1. Every `ACCOUNT_REGISTER` must carry identity/payload-bound registration proof-of-work meeting a reviewed **16-bit minimum**.
2. The current protocol version permits at most **10,000 root-visible account records** on production/public-testnet chain IDs. This ceiling includes bootstrap/system account records. A configured `account_registration_max_accounts` value may lower the ceiling but may not raise it above 10,000; omitting the selector on those chain IDs resolves to the reviewed 10,000-record ceiling rather than to unlimited state.

For non-production compatibility/replay states, absent scarcity selectors retain the historical unbounded policy unless the state explicitly enables registration work or a local account limit.

When registration work is required, the work preimage is domain-separated and commits to:

- the registration-work domain and version;
- transaction `chain_id`;
- signer / new account ID;
- transaction nonce;
- transaction signature profile;
- parent;
- the entire canonical registration payload excluding only `registration_work_version` and `registration_work_nonce`;
- the work nonce.

The registration-work fields remain inside the transaction payload and are therefore covered by the normal transaction signature.

## Fail-closed rules

Production/public-testnet policy fails closed if registration work is disabled, if its enable flag or difficulty is malformed, if difficulty is below 16 or outside the supported range, if a configured account ceiling is zero/negative or above 10,000, if the proof version is absent/unsupported, if the work nonce is outside the JavaScript-safe integer range, or if the digest does not meet the required difficulty.

Once the root-visible account registry reaches the effective ceiling, a fresh `ACCOUNT_REGISTER` fails with `account_registration_capacity_exhausted` before proof/signature work can authorize another permanent account. Existing accounts are not deleted or made inaccessible by reaching the ceiling.

Public admission performs the scarcity check before ML-DSA signature verification. Block admission repeats it, and `_apply_account_register` verifies the same function again as defense in depth before materializing the permanent Tier-0 account subtree.

## Accessibility boundary

Registration work is not a protocol fee, deposit, rent, stake, or purchase. It imposes a deterministic one-time computation on permanent account creation while retaining fee-free identity onboarding below the current safety ceiling. The browser solves the proof locally before signing; public nodes expose only the consensus work policy and do not act as proof-solving oracles.

The 10,000-record ceiling is deliberately conservative because the current implementation still commits root-visible account state into the canonical state representation. Raising or replacing the ceiling is future protocol work that requires a separately reviewed state-scaling design, realistic account-shape benchmarks, generated-evidence refresh, and exact-head consensus/restart/state-sync validation.

## Security boundary

The work mechanism establishes **marginal computational scarcity** for each independently bound permanent registration. A proof solved for one signer, nonce, chain, or registration payload cannot be reused for another. High-resource attackers can spend proportionally greater computation, so proof-of-work alone is not represented as a lifetime state bound.

The independent 10,000-record ceiling supplies that current-version global cardinality bound: a distributed attacker can consume capacity but cannot create an infinite number of permanent orphan Tier-0 records. This does not equate an account with a unique physical human. Human uniqueness remains separately owned by A08, and positive production human authority remains scope-closed until that distinct protocol problem is solved.

## Closure evidence

Required focused evidence includes:

- production/testnet chain policy requires registration work and cannot weaken the reviewed 16-bit floor;
- production/testnet policy cannot disable work or raise the reviewed 10,000-record account ceiling;
- admission rejects a fresh account when the effective global ceiling is reached;
- malformed required policy fails closed;
- work is bound to signer, nonce, chain, and registration payload;
- one account's proof does not bypass many-signer admission;
- strict payload schema carries the signed work fields;
- normal browser onboarding obtains policy, solves work locally, then signs/submits;
- 10k / 100k / 1M synthetic Tier-0-shaped state cardinality evidence is retained for scaling analysis, while 10,000 is the current production/public-testnet root-visible account ceiling;
- distributed-signer production-difficulty rehearsal uses independently solved work, valid ML-DSA signatures, canonical block admission, and production-required recovery/evidence-key material;
- signed submit → block build → commit → restart regression proves successfully admitted accounts persist deterministically;
- the P0 mutation gate kills independent mutants for work identity binding, complete work bypass, production-floor weakening, and account-cardinality-bound bypass;
- full backend, web, canon/current-generated, production-readiness, and exact-head CI remain green.

The cardinality benchmarks are scaling evidence, not production throughput certification. The 10,000-record ceiling is the current safety invariant; higher cardinalities are retained as counterfactual scaling evidence for future protocol work.
