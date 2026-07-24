# Milestone 2 live Tier 2 reviewer runbook

## Preconditions

- Applicant is already Tier 1.
- Every reviewer is a distinct Tier 2 human with live-review responsibility.
- Applicant and reviewers use independent browser profiles or devices.
- Browser camera and microphone permissions are available. CI may use deterministic fake media; external rehearsal must use real devices without publishing raw media.

## Workflow

1. Applicant opens a live request with the required challenge, liveness, room, and media commitments.
2. The chain creates the live case, session, applicant participant, and deterministic reviewer assignments.
3. Assigned reviewers accept or decline in their own sessions.
4. A decline or timeout must produce a replacement without changing already committed reviewers.
5. Reviewers join the WebRTC room. Signaling, STUN, and TURN are transport only.
6. Each reviewer submits a separate signed attendance transaction after observing the applicant.
7. Verdict controls remain unavailable before attendance.
8. Reviewers submit signed verdicts.
9. The chain finalizes the case and emits a receipt.
10. Applicant observes Tier 2 and completes a Tier-2-gated action.

## Media interruption rehearsal

During a controlled run, perform at least one of each:

- Deny camera permission and recover.
- Remove a remote stream and reconnect.
- Refresh one reviewer browser.
- Force ICE restart or relay fallback.
- Decline one reviewer and confirm deterministic replacement.
- Restart the signaling service while preserving chain state.

No transport event may record attendance, cast a verdict, or award Tier 2.

## Evidence capture

Record case/session IDs, signed accept/attendance/verdict transaction IDs, replacement receipt, final Tier 2 receipt, gated-action confirmation, state roots, and sanitized WebRTC diagnostics. Do not publish raw camera/microphone media.
