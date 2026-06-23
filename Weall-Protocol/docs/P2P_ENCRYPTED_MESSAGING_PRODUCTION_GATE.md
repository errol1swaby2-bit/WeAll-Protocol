# P2P Encrypted Messaging Production Gate

Status: closed as unsupported.

WeAll is not a private messaging protocol. The protocol intentionally rejects protocol-native private/direct messages, encrypted social payloads, private threads, and private groups with `PRIVATE_MESSAGING_UNSUPPORTED` or `ENCRYPTED_PROTOCOL_PAYLOAD_UNSUPPORTED`.

The replacement surface is public activity: notifications derive from public protocol events such as mentions, replies, group invitations, moderation notices, dispute assignments, governance notices, and validator/operator alerts.
