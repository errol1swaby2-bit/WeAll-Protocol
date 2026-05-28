# Known limitations for the NLnet external observer milestone

WeAll is pre-production. These limits should be disclosed in reviewer docs and grant materials.

## Not yet claimed

- Not a public mainnet.
- Not a production multi-validator network.
- Not a public validator onboarding launch.
- Not a fully decentralized, self-bootstrapped human-verification network.
- Not a guarantee that gossip, relay, rendezvous, IPFS, or content storage is authoritative.

## Current milestone boundary

The defensible milestone is external reviewability:

- documented production-like genesis posture,
- verifiable observer/operator bundle or chain manifest,
- two-machine observer reachability,
- signed observer onboarding/account/networking/native-PoH-adjacent transaction submission,
- frontend representation of protocol truth in normal user language,
- deterministic backend authority with inspectable tx status/receipts.

## Native PoH bootstrap boundary

Native async/live PoH exists as protocol-state transaction families, but the first live verified humans and jurors still require an auditable bootstrap path. This is a trust boundary, not a contradiction. Bootstrap authority must remain visible, limited, receipt-backed, and progressively replaceable by native juror-attested verification as the network gains enough reviewers.

## Validator-ready boundary

Observer-to-validator scripts and runbooks are readiness gates. They must not be presented as proof that an outside observer can immediately become a production validator. A safe validator-ready definition for this milestone is:

1. account exists on chain,
2. account/device/node key binding exists,
3. chain identity and tx canon match,
4. observer cannot sign blocks,
5. validator signing and BFT stay disabled unless explicit on-chain authority and local preflight pass,
6. reboot preserves identity and chain alignment.

## Frontend boundary

The frontend is not authority. Disabled buttons and capability messages are advisory. Direct API calls must still be rejected by backend gates. Production UI must avoid stale email, Cloudflare, CAPTCHA, OAuth, KYC, oracle, or inbox-control assumptions for primary verification.


## Batch 437-446 remaining limits

The next hardening batch adds explicit P0/P2 proof surfaces but does not convert the project into a public or multi-validator testnet. The safe claim after these checks pass is narrower:

- a trusted external observer can prove local observer-only authority posture;
- frontend node compatibility can be pinned to a manifest/build baseline;
- bootstrap PoH policy is visible and bounded by committed state;
- live-room API responses expose commitments, not raw join URLs;
- status surfaces label governance/disputes/economics as limited or locked unless activation/enforcement rules prove otherwise.

Public governance, public moderation, public economics, and multi-validator BFT remain separate milestones.

## Batch 448 review/read-model QoL hardening

Local two-frontend rehearsal exposed a read-model drift class: completed reviews could remain in active queues, removed content could still appear in account-authored feeds, and appeal controls could depend on fetching content that had already been hidden. Batch 448 treats these as first-tester readiness bugs, not cosmetic polish.

Current intended behavior:

- removed/hidden/deleted content must be suppressed consistently from public, scoped, group, and account-authored feed reads;
- appeal ownership must come from the dispute record and viewer session, not from a best-effort content fetch;
- the affected creator can file an appeal during the appeal window when eligible;
- reviewer accounts that already acted should see history/status, not pending work;
- finalized async/Tier2/live PoH cases should leave active juror queues by default and appear only when `include_completed=1` is requested.

This does not complete public moderation or constitutional due-process for mainnet. It closes the local rehearsal contradiction where successful actions remained visible as stale active work.

## Messaging E2EE v1 limitations

Direct-message plaintext is rejected and ciphertext envelopes are bound to the
currently published account messaging keys. This is safer for trusted testnet
use, but it is not final production-safe private messaging. Metadata remains
visible, browser-local key storage is still a controlled-testnet compromise, and
there is no Signal-style ratchet/forward secrecy yet. See
`docs/MESSAGING_E2EE_SECURITY_MODEL.md`.

## Batch 453 live-room media transport limits

The local live verification room uses browser WebRTC as non-authoritative transport. Batch 453 hardens local two-tab/two-node media setup by materializing remote track-only streams, queuing ICE candidates that arrive before a remote description, retrying deterministic offers for missing remote media, and surfacing peer connection state in the UI.

This improves the local rehearsal, but it does not make media transport authoritative. Live verification authority still comes only from chain-recorded attendance, reviewer verdicts, and finalization. Remote media may still require TURN/relay configuration on real external networks, and a failed media connection must remain visible as a transport problem rather than a failed or passed verification outcome.

## Batch 456 production-readiness gates

The repository now contains explicit production-oriented readiness gates for the remaining pre-external-tester blockers: local block-production proof with an explicit non-BFT boundary, locked tokenomics/economics, full local production-oriented rehearsal completion, reviewer/CI evidence, and production P2P encrypted messaging requirements.

These gates do not mean the blockers are complete. They make the blockers reviewable and prevent overclaiming:

- block production remains local/rehearsal-oriented until a separate production validator/BFT proof and adversarial BFT evidence pass;
- tokenomics remain locked by default and live economics are not claimed;
- direct-message bodies are encrypted, but metadata remains visible and Signal-grade/private P2P messaging is not claimed;
- the reviewer readiness workflow is a targeted reproducibility gate, not a substitute for full pytest or a public testnet.

## Batch 458-461 implementation limits

This batch begins implementation of the remaining production-oriented surfaces:
local block-production proof with an explicit non-BFT boundary, economics activation/transfer/treasury read models,
P2P E2EE device-key backup/recovery controls, and TURN/ICE live-room diagnostics.

These are still not public-testnet or mainnet claims. The repository now exposes
stronger proof and user-facing controls, but public multi-validator BFT, live
tokenomics, Signal-grade private messaging, and external-network media reliability
remain follow-up milestones.
