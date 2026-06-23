# WeAll Public-Only Protocol Rule

Status: mandatory protocol rule for the public civic redesign.

WeAll is not a private messaging protocol. It does not provide encrypted P2P chat, protocol-native direct messages, private groups, member-only-readable group posts, or consensus-affecting encrypted social payloads.

All protocol-native social, civic, governance, moderation, dispute, group, reputation, and validator/operator activity must be publicly inspectable. Group membership may gate posting, commenting, voting, moderation, invitations, and administration, but it must not gate read visibility of protocol-native content.

## Group model

- Group content is publicly readable.
- Group posts are publicly readable.
- Group comments are publicly readable.
- Group moderation actions are publicly visible.
- Group membership may gate posting.
- Group membership may gate commenting.
- Group membership may gate voting.
- Group membership may gate moderation.
- Group membership may gate administration.
- Group membership cannot gate read visibility.
- Group membership cannot create private content archives.

## Notifications and activity

The client may provide an activity inbox for mentions, replies, group invitations, moderation notices, dispute assignments, governance notices, and validator/operator alerts. That inbox must be derived from public protocol events. It must not contain private user-to-user messages, private threads, or encrypted conversations.

## Local-only controls

Local client mute, block, hide, filtering, and ranking controls may change what a user sees in their own client. They do not make protocol content private and must not be represented as private consensus state.

Private drafts may exist locally before publication. Once content is submitted to the protocol, protocol-native meaning must be publicly inspectable.

External private communication tools are outside protocol scope.

## Stable hard-failure codes

- `PRIVATE_MESSAGING_UNSUPPORTED`
- `PRIVATE_GROUPS_UNSUPPORTED`
- `ENCRYPTED_PROTOCOL_PAYLOAD_UNSUPPORTED`
- `GROUP_READ_VISIBILITY_MUST_BE_PUBLIC`
