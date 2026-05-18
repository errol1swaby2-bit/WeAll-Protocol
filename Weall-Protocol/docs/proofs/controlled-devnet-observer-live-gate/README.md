# WeAll Controlled-Devnet Two-Machine Observer Live Gate Proof

Result: PASS

This proof captures the controlled-devnet two-machine external observer onboarding live gate.

Machine B verified the controlled-devnet observer bundle, reached Machine 1 over LAN, generated fresh observer account/node keys locally, submitted real signed observer onboarding transactions to genesis, and confirmed account/device/network/async-PoH onboarding transactions while validator signing, BFT, helper authority, and block-loop authority remained disabled on the observer side.

Confirmed steps:
- ACCOUNT_REGISTER
- ACCOUNT_DEVICE_REGISTER node key binding
- PEER_ADVERTISE
- PEER_REQUEST_CONNECT
- POH_ASYNC_REQUEST_OPEN
- POH_ASYNC_EVIDENCE_DECLARE
- POH_ASYNC_EVIDENCE_BIND

Safety note:
Do not include /tmp/weall-external-observer-live-gate.* work directories in the repo. Those retained directories include private observer account/node keys. This proof bundle contains logs/summaries only.
