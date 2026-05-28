# WeAll Messaging E2EE Security Model

Status: controlled-testnet hardened, not Signal-grade production E2EE.

WeAll direct messages use a client-side encrypted envelope. The backend and chain
must never receive plaintext message bodies or plaintext content CIDs for direct
messages. The protocol stores ciphertext, IV, associated-data metadata, sender and
recipient public messaging keys, and key identifiers.

## Current guarantees

- Direct-message plaintext `body` and plaintext `cid` payloads are rejected by the
  messaging apply path.
- The client encrypts message bodies before submission using the browser WebCrypto
  API.
- When account state is available, `DIRECT_MESSAGE_SEND` envelopes must match the
  sender and recipient messaging keys currently published in account security
  policy. This prevents silent recipient-key substitution by stale UI, relays, or
  malicious clients that submit a canon-valid but wrong-key envelope.
- Messaging key publication records key history, key-change count, visible metadata
  status, and the fact that this v1 scheme does not provide forward secrecy.
- Replacing an already published messaging key requires an explicit previous key id
  and a human-readable rotation reason. The UI must not silently replace a key just
  because a browser generated a new local key.

## Non-goals / current limitations

- This is not Signal Protocol and does not yet provide a double-ratchet.
- Message metadata remains visible: sender, recipient, thread id, message id,
  nonces/order, and message existence are not hidden.
- Browser-local private keys are currently stored as local device material for the
  controlled testnet UX. Production hardening still needs non-extractable key
  storage where possible, encrypted backup/recovery, multi-device key management,
  and strong device revocation.
- Key authenticity is account-state based. Users should eventually see key-change
  warnings and stable fingerprints in normal UI before trusting sensitive messages.

## Production-readiness requirement

Do not describe WeAll messaging as final production-safe private messaging until
key lifecycle, key backup/recovery, multi-device semantics, key-change warnings,
ratcheting/forward secrecy, and independent cryptographic review are complete.
