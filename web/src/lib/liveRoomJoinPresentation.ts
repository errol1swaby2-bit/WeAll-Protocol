export type LiveRoomJoinInputs = {
  canJoinReview: boolean;
  busy: string;
  isReviewer: boolean;
  acceptedOnChain: boolean;
  attendedOnChain: boolean;
  p2pRunning: boolean;
  activeLocalMedia: boolean;
  expectedPeerCount: number;
  connectedPeerCount: number;
};

export type LiveRoomJoinPresentation = {
  buttonLabel: string;
  disabled: boolean;
  mediaStatus: string;
};

/** UI presentation only. Chain attendance and remote WebRTC transport are independent. */
export function getLiveRoomJoinPresentation(input: LiveRoomJoinInputs): LiveRoomJoinPresentation {
  const peers = Math.max(0, input.expectedPeerCount);
  const connected = Math.max(0, Math.min(peers, input.connectedPeerCount));
  const chainRecorded = !input.isReviewer || (input.acceptedOnChain && input.attendedOnChain);
  const mediaStatus = input.p2pRunning
    ? !input.activeLocalMedia
      ? "Local media capture is inactive. Stop media and retry; peer connection is not verified."
      : !connected
        ? peers
          ? `Local media and signaling active; waiting for remote peer connection (0/${peers} connected). Chain attendance is separate.`
          : "Local media and signaling active; no remote peers currently listed. Chain attendance is separate."
        : `WebRTC connection established with ${connected}/${peers} remote peer(s). Chain attendance is separate.`
    : "Local browser media is not started. Chain attendance alone does not connect a video call.";

  if (input.busy) return { buttonLabel: input.busy, disabled: true, mediaStatus };
  if (!input.canJoinReview) return { buttonLabel: "Live room joining unavailable", disabled: true, mediaStatus };
  if (input.p2pRunning) {
    if (!chainRecorded) return { buttonLabel: "Local media active — chain check-in unconfirmed", disabled: true, mediaStatus };
    if (!input.activeLocalMedia) return { buttonLabel: "Media interrupted — stop to retry", disabled: true, mediaStatus };
    if (!connected) return { buttonLabel: "Local media active — waiting for peer", disabled: true, mediaStatus };
    return { buttonLabel: `Connected to ${connected} remote peer(s)`, disabled: true, mediaStatus };
  }
  if (input.isReviewer && !input.acceptedOnChain) return { buttonLabel: "Accept review, check in, then start local media", disabled: false, mediaStatus };
  if (input.isReviewer && !input.attendedOnChain) return { buttonLabel: "Record attendance, then start local media", disabled: false, mediaStatus };
  return { buttonLabel: "Start local media and connect to peers", disabled: false, mediaStatus };
}
