# Crypto Agility and Quantum-Resistance Posture

WeAll is a pre-public-testnet protocol implementation under active hardening.

This document records the Pass 34 transition from a classical-only Ed25519 signing assumption toward real, profile-aware ML-DSA protocol signing. It is a truth-boundary document, not a cryptographic audit. WeAll does not claim public mainnet readiness, live economics, public multi-validator BFT readiness, production constitutional governance readiness, public beta readiness, production-grade PQ security, unbreakable quantum-security language, or completed production cryptographic review.

Because WeAll is public-only, the critical quantum-resistance surface is protocol signing and authority. This pass does not reintroduce private messaging, private groups, private E2EE product claims, or confidential protocol content.

## Profile registry

| Profile | Purpose | Status | Post-quantum | Current admission posture |
| --- | --- | --- | --- | --- |
| `legacy-ed25519-v1` | legacy transaction/account/operator/registry signatures | legacy/transitional | no | dev/local and explicit migration tests only in strict testnet mode |
| `pq-mldsa-v1` | controlled-testnet target signing profile | active target | yes | backed by pyca/cryptography ML-DSA-65 in this tree; external review still required before durable public network claims |
| `pq-slhdsa-v1` | optional future backup signature profile | reserved | yes | not accepted by runtime admission |
| `pq-mlkem-v1` | transport/key-establishment only | reserved | yes | not accepted for transaction, block, registry, BFT, or evidence signing |

ML-DSA is the NIST FIPS 204 digital signature family. ML-KEM is a NIST key-establishment/encryption family and must not be used as a transaction signature profile. SLH-DSA is reserved as an optional backup signature family and is not active in this repository state.

## Dependency decision record

The repository now pins and requires `cryptography>=48.0.0,<49` for the controlled-testnet PQ signing path. `pq-mldsa-v1` uses pyca/cryptography's ML-DSA hazmat API with the ML-DSA-65 parameter set and a WeAll domain/context string. The adapter fails closed if the ML-DSA backend is unavailable.

This pass does not silently emulate ML-DSA and does not add toy signatures. Pure-Python educational packages were not integrated as production protocol signing. liboqs-style bindings remain future candidates for independent comparison, but they introduce system-library and reproducible-build requirements that must be pinned and rehearsed before being added to the default path.

## Inventory by surface

| Surface | Current algorithm in this tree | Target profile | Consensus-critical | Account custody | Observer trust | Transport/local only | Before closed testnet | Before public testnet | Before mainnet |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Transaction signatures | profile-aware `pq-mldsa-v1` signing/verifying through ML-DSA-65; Ed25519 dev/migration-only when explicitly allowed | `pq-mldsa-v1` | yes | yes | yes | no | implemented for controlled rehearsal, rerun evidence required | fresh evidence required | external crypto review required |
| Account keys | registration/key-add/recovery helpers create profile-aware ML-DSA key records | `pq-mldsa-v1` key records | yes | yes | yes | no | implemented for controlled rehearsal, rerun evidence required | fresh evidence required | external crypto review required |
| Account recovery keys | recovery key records are profile-aware and default to `pq-mldsa-v1` in strict modes | `pq-mldsa-v1` | yes | yes | yes | no | implemented for controlled rehearsal, rerun evidence required | fresh evidence required | external crypto review required |
| Validator/operator signatures | validator/operator records and HotStuff vote/timeout/proposal signing are profile-aware and ML-DSA-backed | `pq-mldsa-v1` | yes | no | yes | no | implemented for controlled rehearsal, rerun evidence required | fresh evidence required | external crypto review required |
| Block signatures | block signature profile admission requires verifier availability and rejects unknown/disallowed profiles | `pq-mldsa-v1` | yes | no | yes | no | implemented gate, rerun evidence required | fresh evidence required | external crypto review required |
| BFT/QC signatures | HotStuff vote, timeout, proposal, and QC verification paths are profile-aware and ML-DSA-tested | `pq-mldsa-v1` or audited aggregate/threshold profile | yes | no | yes | no | implemented test path; public BFT remains unclaimed | external multi-operator evidence required | external crypto review required |
| Seed registry signatures | checked-in public testnet seed registry is `pq-mldsa-v1`/ML-DSA-65 signed and pinned to PQ trust roots | `pq-mldsa-v1` | no, but bootstrap-critical | no | yes | no | implemented, rerun observer evidence required | fresh evidence required | external crypto review required |
| Public testnet trust roots | trust roots allow `pq-mldsa-v1`; legacy Ed25519 remains transitional/dev-only | `pq-mldsa-v1` | no | no | yes | no | implemented, rerun evidence required | fresh evidence required | external crypto review required |
| Validator endpoint advertisements | registry signing script signs validator endpoint advertisements as `pq-mldsa-v1` by default | `pq-mldsa-v1` | no, but observer safety-critical | no | yes | no | implemented path, rerun evidence required | fresh evidence required | external crypto review required |
| Peer identity signatures | PEER_HELLO identity proofs are profile-aware and support `pq-mldsa-v1`; legacy V1/V2 Ed25519 remains migration fallback | `pq-mldsa-v1` | no/transport-adjacent | no | yes | mixed | implemented path, rerun evidence required | fresh evidence required | external crypto review required |
| Gossip signatures | signed peer address gossip records are profile-aware and support `pq-mldsa-v1` | `pq-mldsa-v1` | can affect propagation trust | no | yes | no | implemented path, rerun evidence required | fresh evidence required | external crypto review required |
| Relay signatures | relay access requests and relay envelopes are profile-aware and support `pq-mldsa-v1` | `pq-mldsa-v1` | no unless relay evidence becomes authority | no | yes | mixed | implemented path, rerun evidence required | fresh evidence required | external crypto review required |
| Observer onboarding signatures | observer bootstrap verifies a PQ-signed seed registry before trusting endpoints; local observer evidence needs rerun | `pq-mldsa-v1` | no, but observer evidence-critical | no | yes | no | implemented registry verification, rerun evidence required | fresh evidence required | external crypto review required |
| Evidence bundle signatures/digests | SHA-256 digests remain for evidence integrity; durable signed evidence bundle policy still needs PQ signing standardization | `pq-mldsa-v1` signatures plus SHA-256/SHA-3 digest policy | no, but reviewer-critical | no | yes | no | acceptable for internal evidence with not-run boundary | required for public proof packages | external crypto review required |
| Frontend signing assumptions | observer UI exposes active `pq-mldsa-v1`; browser-local Ed25519 helper is explicitly legacy/dev-only pending browser ML-DSA support | `pq-mldsa-v1` or controlled backend/operator signer | no | yes if local wallet signs | yes | no | controlled/backend signer path only | real client or controlled signer required | external crypto review required |
| Helper receipts/certificates | helper execution remains disabled for production; receipt/certificate signing has legacy Ed25519/HMAC compatibility and must not be used as public authority | `pq-mldsa-v1` helper receipt profile before production helper enablement | yes if helpers become production consensus execution | no | yes | no | not closed-testnet blocker while helpers are disabled | blocker before production helper/public authority claims | external crypto review required |
| Local wallet/key storage encryption | symmetric/local storage implementation varies and is documented separately from PQ signing migration | AES-256-equivalent plus PQ-aware key backup plan | no | yes | no | local only | document | document and test | external crypto review required |
| Transport/TLS assumptions | conventional TLS stack; `pq-mlkem-v1` remains a documented future key-establishment target | TLS plus future `pq-mlkem-v1`/hybrid support where available | no | no | yes | transport only | document | document/gate | external crypto review required |

## Canonical signing context

Protocol-critical signed payloads carry or derive the following context before strict closed/public testnet use:

- `chain_id`;
- `network_id` where relevant;
- domain separator;
- object kind such as `tx`, `block`, `seed_registry`, `validator_record`, `observer_evidence`, peer identity, gossip record, or relay envelope;
- transaction or action type where relevant;
- signer/account id where relevant;
- nonce or anti-replay field where relevant;
- `sig_profile`;
- activation height or epoch where relevant.

Ambiguous algorithm-free signatures, silent Ed25519 fallback in strict modes, unknown profile acceptance, profile downgrade, and missing `chain_id` in strict testnet modes are rejected or treated as blockers.

## ML-KEM transport note

`pq-mlkem-v1` is for future key establishment and encrypted transport use cases only. It may become relevant for node transport, authenticated registry fetch channels, local wallet backup wrapping, or future confidential operator channels. It is not a WeAll private messaging feature. Public chain content remains public.

Local key storage may still use symmetric encryption such as AES-256-equivalent mechanisms. The quantum-risk posture for local encryption is separate from protocol-signature authority and must be documented before public launch.

## Remaining blockers

1. Rerun fresh closed-testnet observer, registry, tx, block, validator/operator, gossip, relay, and BFT evidence after the ML-DSA transition.
2. Implement or gate browser-local ML-DSA signing. Until then, browser Ed25519 signing is legacy/dev-only and controlled-testnet signing must use backend/operator custody.
3. Define durable PQ signing policy for public evidence bundles and any future production helper receipt/certificate authority before enabling production helper execution.
4. Obtain external cryptographic review before any long-lived public network or mainnet claim.

## Final claim boundary

WeAll remains a pre-public-testnet protocol implementation under active hardening. The controlled-testnet signing profile has transitioned from classical-only Ed25519 to profile-aware ML-DSA signing for protocol authority surfaces covered by this pass. This supports quantum-resistance hardening but does not claim completed production cryptographic audit, public mainnet readiness, live economics, public multi-validator BFT readiness, production helper execution readiness, or production constitutional governance readiness.
