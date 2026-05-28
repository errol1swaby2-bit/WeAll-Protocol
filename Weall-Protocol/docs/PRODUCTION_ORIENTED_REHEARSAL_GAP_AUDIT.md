# Production-Oriented Rehearsal Gap Audit

Status: local multi-node rehearsal is working, but the repository must not claim external tester, public testnet, or mainnet readiness until the gates below pass.

This document turns the current gaps into explicit engineering targets for NLnet/reviewer visibility. It is intentionally conservative: if a feature is not proven by code, tests, and a reproducible runbook, it is listed as a blocker rather than treated as complete.

## Current safe claim

WeAll has a working controlled local two-node/two-frontend rehearsal with native verification, posting, group activity, community review, encrypted direct-message bodies, and live-room diagnostics.

## Claims that are not yet safe

- Production/public multi-validator BFT readiness.
- Public mainnet readiness.
- Fully production-grade P2P encrypted messaging.
- Live tokenomics/economics.
- A reproducible external tester path where every surface can be used as intended without founder intervention.

## Blocker 1 — block production proof truth boundary

The local rehearsal may exercise block production and synchronization paths, but the current gate is intentionally local block-production evidence, not production-profile validator/BFT proof. Reviewer docs must keep that boundary explicit until a separate production validator/BFT gate exists proving:

- the genesis/producer node can start with an explicit chain manifest under the intended profile;
- observer nodes cannot sign or produce blocks;
- block-loop status is exposed in `/v1/status` and `/v1/readyz`;
- produced blocks commit state/receipt/helper roots deterministically;
- a node restart does not create replay divergence;
- the docs distinguish local block production, production validator authority, observer mode, and multi-validator BFT.

Required acceptance evidence:

```bash
bash scripts/reviewer_production_readiness_gate.sh
```

and a saved local rehearsal transcript showing the genesis node, observer node, block-loop status, tx confirmation, and cross-node read convergence.

## Blocker 2 — locked tokenomics/economics model

Economics do not need to be live for the first trusted external observer milestone, but the model must be locked, visible, and deterministic.

Minimum external-testnet posture:

- WeCoin/economic transfers remain unavailable while the Genesis Constitutional Phase is locked.
- Civic, social, verification, governance, and review flows remain fee-free.
- Treasury spend and rewards remain unavailable unless governance activation conditions are satisfied.
- The UI must show economics as locked/unavailable rather than half-live.
- `/v1/status` must expose the locked economics posture.

Required future work:

- balance state audit;
- transfer/fee/reward/treasury activation tests;
- governance activation threshold/challenge-window proof;
- frontend wallet/treasury truth-sync.

## Blocker 3 — full local production-oriented rehearsal completion

The local rehearsal becomes production-oriented only when every normal-user surface is coherent:

- account creation and restore;
- Tier 1 async verification;
- Tier 2 live verification with truthful media diagnostics;
- content create/report/review/remove/appeal;
- group post, group feed, group report, group review;
- encrypted direct-message body flow;
- node switching and stale-node warnings;
- no stale action toasts or completed work in active queues;
- center content and side panels do not overlap at normal screen widths.

## Blocker 4 — CI/reviewer runbook evidence

Local full pytest results are valuable, but reviewers need a reproducible command set. The repo must maintain:

- a reviewer gate script;
- a GitHub workflow for the reviewer gate;
- a short milestone document for what is proven versus intentionally deferred;
- known limitation docs that do not overclaim.

## Blocker 5 — production-ready P2P encrypted messaging

Current messaging encrypts direct-message bodies client-side and rejects plaintext direct-message bodies/CIDs at the protocol layer. This is controlled-testnet hardened, not final production P2P private messaging.

Production P2P encrypted messaging remains blocked by:

- no double-ratchet/forward secrecy;
- metadata visibility;
- browser-local private key compromise/recovery model;
- incomplete multi-device semantics;
- account-state key authenticity rather than user-verified fingerprints;
- no independent cryptographic review.

External-testnet-safe wording:

> Direct-message bodies are client-side encrypted. Metadata remains visible. The current scheme is testnet-hardened E2EE v1, not final production private messaging.

## Batch 458-461 implementation pass

The remaining issues have begun moving from documentation-only gates into product
and API implementation:

- block-production root evidence is available through a proof endpoint and local-only proof gate;
- economics activation, transfer preview, and treasury lock status are visible to users/reviewers;
- E2EE v1 now has local device backup/import/revocation controls and peer trust reset;
- live-room transport now supports browser-local TURN/ICE configuration and automatic polling.

These changes improve production orientation but do not yet close public testnet,
public economics, public BFT, or Signal-grade private messaging readiness.
