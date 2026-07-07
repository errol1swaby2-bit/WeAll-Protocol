# WeAll Public Protocol Rule

Status: mandatory protocol rule for the public civic redesign.

All protocol-native social, civic, governance, moderation, dispute, group, reputation, and validator/operator activity must be publicly inspectable. The protocol records public civic state only. Local clients may prepare drafts before publication, but submitted protocol meaning must be inspectable by validators and observers.

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
- Group membership cannot create non-public protocol archives.

## PoH identity evidence boundary

The public-only protocol rule does not require raw Proof-of-Humanhood identity evidence, live verification media, device fingerprints, government identifiers, or similar sensitive identity material to be publicly exposed. PoH may protect raw identity evidence behind authenticated applicant/reviewer access, while the consensus-affecting facts remain publicly inspectable through commitments, assignments, participation records, reviewer actions, votes, outcomes, receipts, timestamps, and state-root effects.

This boundary is not a protocol-native hidden communication channel. It cannot carry user-to-user social messages, group content, governance meaning, dispute arguments, moderation actions, reputation edits, validator/operator instructions, or any other civic state hidden from public inspection.

## Notifications and activity

The client may provide an activity notices for mentions, replies, group invitations, moderation notices, dispute assignments, governance notices, and validator/operator alerts. The input_queue is derived from public protocol events and carries no user-to-user sealed thread semantics.

## Local-only controls

Local client mute, block, hide, filtering, and ranking controls may change what a user sees in their own client. They do not change protocol read visibility and must not be represented as hidden consensus state.

External communications are outside protocol scope.

## Stable hard-failure codes

- `NON_PUBLIC_GROUP_UNSUPPORTED`
- `OPAQUE_PROTOCOL_PAYLOAD_UNSUPPORTED`
- `PUBLIC_READ_VISIBILITY_REQUIRED`
