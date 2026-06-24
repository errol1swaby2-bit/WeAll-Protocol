# P2P Encrypted Messaging Production Gate

Status: closed as unsupported.

WeAll is not a private messaging protocol. The protocol intentionally rejects protocol-native private/direct messages, encrypted social payloads, private threads, and private groups with `PRIVATE_MESSAGING_UNSUPPORTED` or `ENCRYPTED_PROTOCOL_PAYLOAD_UNSUPPORTED`.

The replacement surface is public activity: notifications derive from public protocol events such as mentions, replies, group invitations, moderation notices, dispute assignments, governance notices, and validator/operator alerts.

## Public-only group and archive rule

Group membership may gate posting, commenting, voting, moderation, invitations, and administration, but it must never gate read visibility for protocol-native group content. New private groups, member-only-readable posts, direct-message transactions, encrypted social payloads, and ciphertext-bearing protocol metadata are rejected at admission and replay boundaries.

Legacy compatibility reads must not preserve private archives. Owner-authenticated account feeds and scoped content routes apply the same public-only read rule as anonymous protocol reads: public posts remain readable, legacy group-scoped posts with group IDs are public-readable group content, and direct/private/member-only records are not exposed.

Local drafts, mutes, blocks, and client filters are local client behavior only. They do not make protocol-native content private and they do not create consensus-affecting private state. External private communication is outside the WeAll protocol scope.
