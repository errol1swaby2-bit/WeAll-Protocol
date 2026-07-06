# Public Beta Blockers

The repository is currently a controlled multi-node testnet candidate.
Public beta and mainnet readiness remain blocked by evidence and release gates.

The source of truth is:

- `generated/public_beta_blocker_report_v1_5.json`
- `generated/external_operator_transcript_requirements_v1_5.json`
- `generated/controlled_testnet_go_gate_v1_5.json`
- `/v1/status/testnet-capabilities`


## Count semantics

The blocker report keeps all historical catalog entries visible. In the generated
JSON, `blocker_count` is a compatibility alias for `blocker_catalog_count`; it is
not the number still open. Reviewers should read the top-level counts this way:

| Field | Current meaning | Expected value in this branch |
| --- | --- | ---: |
| `blocker_catalog_count` / `blocker_count` | Full blocker catalog kept visible for audit continuity. | 14 |
| `closed_in_repository_count` / `closed_blocker_count` | Closed by repository evidence, generated artifacts, docs, or source-level UX gates. | 7 |
| `remaining_blocker_count` / `open_blocker_count` | Still-open blockers before public beta can be claimed. | 7 |
| `remaining_external_evidence_required_count` | Open blockers that need independent transcripts, real-operator proof, counsel attestation, or other external evidence. | 7 |
| `p0_open_count` | Still-open P0 blockers. | 3 |
| `p1_open_count` | Still-open P1 blockers. | 4 |
| `p2_open_count` | Still-open P2 blockers. | 0 |
| `p3_open_count` | Still-open P3 blockers. | 0 |

The report must continue to keep `public_beta_ready=false`. A clean repository
blocker inventory only means the evidence gates are current and explicit.

## Still-open blocker ids

- `AUD-618-P0-001` — independent public validator/operator transcript.
- `AUD-618-P0-002` — legal/compliance counsel attestation.
- `AUD-618-P0-003` — executable protocol upgrade staging/rollback proof.
- `AUD-618-P1-003` — external machine replay transcript.
- `AUD-618-P1-004` — real IPFS/storage operator transcript.
- `AUD-618-P1-005` — production helper topology enablement gate.
- `AUD-628-P1-001` — external public observer open-download/state-sync/rendered journey transcript.

## Closed-in-repository blocker ids

These are still visible in the catalog, but their current gates are closed by
tracked repository artifacts/docs/source gates rather than external evidence:

- `AUD-618-P1-001`
- `AUD-618-P1-002`
- `AUD-618-P1-006`
- `AUD-618-P2-001`
- `AUD-618-P2-002`
- `AUD-618-P2-003`
- `AUD-618-P3-001`

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

### Pass 33 signature-profile truth boundary

WeAll is a pre-public-testnet protocol implementation under active hardening. The controlled-testnet signing profile has transitioned to profile-aware `pq-mldsa-v1` ML-DSA signing for protocol authority surfaces covered by this pass; `legacy-ed25519-v1` is legacy/transitional/dev-only unless explicitly allowed by chain configuration. This does not claim completed production cryptographic audit, mainnet readiness, live economics, public multi-validator BFT readiness, production helper execution readiness, production constitutional governance readiness, or public beta readiness. Public-only protocol surfaces remain public.
