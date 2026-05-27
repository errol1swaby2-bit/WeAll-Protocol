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
