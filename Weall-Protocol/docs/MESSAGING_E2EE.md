# Protocol-Native Messaging Status

Status: removed / unsupported by the public-only protocol redesign.

WeAll does not provide protocol-native encrypted direct messages, encrypted P2P chat, message threads, private threads, or end-to-end encrypted social payloads. Historical E2EE messaging work is retained only as legacy context; current runtime admission and replay reject `DIRECT_MESSAGE_SEND`, `DIRECT_MESSAGE_REDACT`, encrypted protocol payload fields, and member-only-readable group content.

The supported replacement is a public activity inbox derived from public protocol events: mentions, replies, group invitations, moderation notices, dispute assignments, governance notices, and validator/operator alerts.

External private communication is outside protocol scope.
