# P2P Encrypted Messaging Production Gate

Status: production gate definition. Current implementation is E2EE v1 for controlled testnet use, not final production P2P private messaging.

## Current implemented baseline

- Direct-message plaintext `body` and plaintext content `cid` payloads are rejected by the backend apply path.
- Clients encrypt direct-message bodies before submission.
- Encrypted message envelopes are bound to the sender and recipient messaging keys currently published in account security policy when account state is available.
- Key replacement requires an explicit previous key id and rotation reason.
- Messaging key history and metadata visibility status are recorded.

## What “production-ready P2P encrypted messaging” requires

The production target is stronger than body encryption:

1. **End-to-end body secrecy** — backend/chain never receives plaintext bodies.
2. **Key authenticity** — users can verify stable peer fingerprints and are warned on key change.
3. **Forward secrecy** — compromise of a static device key should not expose all old messages.
4. **Multi-device safety** — adding/removing devices must be explicit and reviewable.
5. **Recovery semantics** — lost keys should not silently rotate or decrypt old messages unexpectedly.
6. **Metadata truth** — UI must say sender, recipient, message existence, order, and thread ids remain visible unless a future metadata-hiding layer exists.
7. **P2P transport separation** — direct peer transport is non-authoritative; consensus/read APIs remain the source of committed message existence.
8. **Independent crypto review** — production claims require review beyond source-level tests.

## Near-term acceptable testnet claim

> WeAll direct-message bodies are client-side encrypted and plaintext is rejected by the protocol. Metadata remains visible. This is a testnet-hardened E2EE v1 path, not Signal-grade production private messaging.

## Required next engineering batches

- Device-bound non-extractable private key storage where browser support allows it.
- Peer fingerprint display and key-change warning UX.
- Per-thread session keys and ratchet/forward-secrecy research spike.
- Multi-device key records, revocation, and recovery flows.
- P2P delivery/read convergence tests that distinguish encrypted transport from consensus authority.

## Batch 457 peer-key trust implementation

Batch 457 implements a first production-facing key-authenticity step for current E2EE v1 messaging:

- recipients are trusted on first use by storing the peer account, key id, public key, and visible fingerprint in browser-local trust state;
- future key changes trigger an explicit confirmation before sending;
- the backend still rejects plaintext direct-message bodies and requires envelopes to match account-published messaging keys when account state is available.

This still is not Signal-grade production E2EE. It is a concrete trust-on-first-use and key-change-warning implementation step while ratcheting, multi-device verification, encrypted backup, and external cryptographic review remain future work.

## Batch 458-461 implementation surface

The client now supports local device-key lifecycle controls:

- local messaging device record;
- encrypted passphrase-protected key backup export/import;
- local device revocation marker;
- peer trust reset for key-change verification;
- trust-on-first-use plus explicit key-change confirmation.

This improves production orientation, but it still is not Signal-grade P2P private
messaging. Metadata is visible and the v1 scheme still lacks double-ratchet
forward secrecy and independently reviewed multi-device cryptographic semantics.
