# Crypto Agility and Quantum-Resistance Posture

WeAll is a pre-public-testnet protocol implementation under active hardening.

This document records the Pass 33 transition away from a classical-only Ed25519 signing assumption and toward profile-aware post-quantum signing gates. It is a truth-boundary document, not a cryptographic audit. WeAll does not claim public mainnet readiness, live economics, public multi-validator BFT readiness, production constitutional governance readiness, public beta readiness, or completed production cryptographic review.

Because WeAll is public-only, the critical quantum-resistance surface is protocol signing and authority. This pass does not reintroduce private messaging, private groups, private E2EE product claims, or confidential protocol content.

## Profile registry

| Profile | Purpose | Status | Post-quantum | Current admission posture |
| --- | --- | --- | --- | --- |
| `legacy-ed25519-v1` | legacy transaction/account/operator/registry signatures | legacy/transitional | no | dev/local and explicit migration tests only in strict testnet mode |
| `pq-mldsa-v1` | controlled-testnet target signing profile | active target | yes | default strict controlled/public testnet signing profile; verifier must be real and externally reviewed before durable public network claims |
| `pq-slhdsa-v1` | optional future backup signature profile | reserved | yes | not accepted by runtime admission |
| `pq-mlkem-v1` | transport/key-establishment only | reserved | yes | not accepted for transaction or block signing |

ML-DSA is the NIST FIPS 204 digital signature family. ML-KEM is a NIST key-establishment/encryption family and must not be used as a transaction signature profile. SLH-DSA is reserved as an optional backup signature family and is not active in this repository state.

## Dependency decision record

The repository now contains an optional adapter for pyca/cryptography's ML-DSA hazmat API. Cryptography added ML-DSA support in version 47.0.0, but practical availability depends on the linked backend supporting ML-DSA. The default wheels may not expose that backend everywhere. Therefore this pass does not silently emulate ML-DSA and does not add toy signatures. If the real backend is unavailable, `pq-mldsa-v1` verification fails closed and the evidence bundle must mark real ML-DSA as not implemented in that environment.

Pure-Python educational packages were not integrated as production protocol signing because at least one widely visible ML-DSA Python implementation explicitly warns against cryptographic application use. liboqs-style bindings remain candidates, but they introduce system-library and reproducible-build requirements that must be pinned and rehearsed before the repository can claim real controlled-testnet PQ signing.

## Inventory by surface

| Surface | Current algorithm in this tree | Target profile | Consensus-critical | Account custody | Observer trust | Transport/local only | Before closed testnet | Before public testnet | Before mainnet |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Transaction signatures | Ed25519 legacy compatibility plus profile gate | `pq-mldsa-v1` | yes | yes | yes | no | real verifier required for live rehearsal | required | external crypto review required |
| Account keys | legacy `pubkey` fields plus profile-aware key records | `pq-mldsa-v1` key records | yes | yes | yes | no | required | required | external crypto review required |
| Account recovery keys | not fully migrated end-to-end | `pq-mldsa-v1` | yes | yes | yes | no | blocker | blocker | external crypto review required |
| Validator/operator signatures | profile validator helper added; legacy implementation remains in some flows | `pq-mldsa-v1` | yes | no | yes | no | partial blocker | blocker | external crypto review required |
| Block signatures | profile metadata helper and strict gate added | `pq-mldsa-v1` | yes | no | yes | no | partial blocker | blocker | external crypto review required |
| BFT/QC signatures | existing HotStuff/QC surfaces remain classical/profile-incomplete | `pq-mldsa-v1` or audited aggregate/threshold profile | yes | no | yes | no | not required for single-validator closed rehearsal if BFT remains gated | blocker for public multi-validator BFT | external crypto review required |
| Seed registry signatures | checked-in registry remains legacy-signed and marked transitional | `pq-mldsa-v1` | no, but bootstrap-critical | no | yes | no | blocker if strict public registry bootstrap is used | required | external crypto review required |
| Public testnet trust roots | active profile declares `pq-mldsa-v1`; legacy listed as transitional only | `pq-mldsa-v1` | no | no | yes | no | required | required | external crypto review required |
| Validator endpoint advertisements | profile-aware verification helper added | `pq-mldsa-v1` | no, but observer safety-critical | no | yes | no | required for trusted validator discovery | required | external crypto review required |
| Peer identity signatures | still partly Ed25519 in gossip/peer modules | `pq-mldsa-v1` | no/transport-adjacent | no | yes | mixed | blocker for public observer authority trust | blocker | external crypto review required |
| Gossip signatures | still Ed25519 in existing gossip helper | `pq-mldsa-v1` | can affect propagation trust | no | yes | no | blocker if signed gossip becomes authority evidence | blocker | external crypto review required |
| Relay signatures | not fully migrated | `pq-mldsa-v1` | no unless relay evidence becomes authority | no | yes | mixed | document/gate | document/gate | external crypto review required |
| Observer onboarding signatures | legacy signing helpers remain | `pq-mldsa-v1` | no, but observer evidence-critical | no | yes | no | blocker for fresh observer evidence | blocker | external crypto review required |
| Evidence bundle signatures/digests | digests mostly SHA-256; signatures legacy where present | `pq-mldsa-v1` signatures plus SHA-256/SHA-3 digest policy | no, but reviewer-critical | no | yes | no | recommended | required for public proof packages | external crypto review required |
| Frontend signing assumptions | must not present Ed25519 as the future testnet profile | `pq-mldsa-v1` or clearly backend/dev signer only | no | yes if local wallet signs | yes | no | profile disclosure required | real client or controlled signer required | external crypto review required |
| Local wallet/key storage encryption | symmetric/local storage implementation varies | AES-256-equivalent plus PQ-aware key backup plan | no | yes | no | local only | document | document and test | external crypto review required |
| Transport/TLS assumptions | conventional TLS stack | TLS plus future `pq-mlkem-v1`/hybrid KEM where supported | no | no | yes | transport only | document | document/gate | external crypto review required |

## Canonical signing context

Protocol-critical signed payloads must carry or derive all of the following context before strict closed/public testnet use:

- `chain_id`;
- `network_id` where relevant;
- domain separator;
- object kind such as `tx`, `block`, `seed_registry`, `validator_record`, or `observer_evidence`;
- transaction or action type where relevant;
- signer/account id where relevant;
- nonce or anti-replay field where relevant;
- `sig_profile`;
- activation height or epoch where relevant.

Ambiguous algorithm-free signatures, silent Ed25519 fallback, unknown profile acceptance, profile downgrade, and missing `chain_id` in strict testnet modes are rejected or treated as blockers.

## ML-KEM transport note

`pq-mlkem-v1` is for future key establishment and encrypted transport use cases only. It may become relevant for node transport, authenticated registry fetch channels, local wallet backup wrapping, or future confidential operator channels. It is not a WeAll private messaging feature. Public chain content remains public.

Local key storage may still use symmetric encryption such as AES-256-equivalent mechanisms. The quantum-risk posture for local encryption is separate from protocol-signature authority and must be documented before public launch.

## Remaining blockers

1. Integrate and pin a reproducible ML-DSA implementation with positive and negative verification tests.
2. Re-sign seed registry and trust-root materials with `pq-mldsa-v1`.
3. Migrate account recovery keys and key rotation flows to profile-aware key records.
4. Migrate validator/operator, block, BFT/QC, peer, gossip, relay, and observer evidence signatures end-to-end.
5. Update frontend account creation/signing so users can see the active chain crypto profile and no UI implies Ed25519 is the future testnet signing profile.
6. Obtain external cryptographic review before any long-lived public network or mainnet claim.

## Final claim boundary

WeAll remains a pre-public-testnet protocol implementation under active hardening. This patch adds fail-closed post-quantum signature-profile scaffolding and makes `pq-mldsa-v1` the controlled-testnet target profile, but real quantum-resistant signing remains blocked until a reproducible ML-DSA implementation is integrated, pinned, tested, and externally reviewed.
