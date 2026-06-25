# Public Beta Blockers

The repository is currently a controlled multi-node testnet candidate.
Public beta and mainnet readiness remain blocked by evidence and release gates.

The source of truth is:

- `generated/public_beta_blocker_report_v1_5.json`
- `generated/external_operator_transcript_requirements_v1_5.json`
- `generated/controlled_testnet_go_gate_v1_5.json`
- `/v1/status/testnet-capabilities`

## Remaining blocker classes

1. Independent validator operator transcript.
2. Real storage/IPFS daemon/operator topology transcript.
3. Legal/compliance attestation.
4. Production helper execution safety gates.
5. Signed protocol upgrade execution/rollback gates.
6. External state-sync and restart evidence.
7. Rendered frontend evidence for launch blockers and accessibility.
8. Public route response-vector expansion and freshness checks.
9. Release runbook and clean worktree gate.

These blockers are intentional. They prevent the project from accidentally
marketing a local controlled rehearsal as a public decentralized network.
