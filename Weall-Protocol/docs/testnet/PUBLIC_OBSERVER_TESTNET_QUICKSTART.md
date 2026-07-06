# Public Observer Testnet Quickstart Pointer

Current allowed claim: **WeAll is a pre-public-testnet protocol implementation under active hardening, with local/devnet/public-observer-oriented evidence present and public beta readiness still blocked by explicit external observer, replay, validator/operator, storage, legal, upgrade-execution, and helper-topology gates.**

This file exists to prevent reviewer/operator confusion between the current testnet runbook location and the older detailed public-discovery supplement.

## Canonical current runbook

Use `docs/testnet/PUBLIC_OBSERVER_QUICKSTART.md` for the next bounded two-node/public-observer rehearsal.

It contains the current copy-pasteable path for:

- clean clone and backend environment setup;
- repository truth-boundary checks;
- observer boot with `WEALL_PUBLIC_TESTNET=1`;
- backend status endpoint capture;
- frontend build/source checks;
- evidence package pointers;
- disabled/forbidden readiness claims.

## Detailed discovery supplement

The older detailed discovery guide remains at `docs/PUBLIC_OBSERVER_TESTNET_QUICKSTART.md`. Treat that file as a provider-independent discovery and registry-signing supplement only. It does not replace the canonical current runbook above and must not be used to claim public observer launch readiness by itself.

## Claim boundary

This pointer does not close `AUD-628-P1-001`. Public observer launch and public beta remain blocked until a completed external clean-clone/open-download/state-sync/frontend rendered journey transcript is attached and reviewed.

## Observer proof tiers and capture path

Observer proof is intentionally tiered:

1. local observer proof: local checkout verifies chain identity/trust roots and boots observer mode;
2. same-machine dual-node proof: two local nodes rehearse controlled devnet flows on one machine;
3. remote two-machine signed observer proof: a fresh external machine/operator captures a commit-bound transcript.

First external observer readiness requires a fresh remote/signed observer run. This quickstart alone does not close that gate. Use `docs/testnet/OBSERVER_PROOF_POSTURE_AND_CAPTURE.md` and capture outputs under `audit-metadata/reviewer-evidence-YYYY-MM-DD/`.
