# WeAll current state update

Status: pre-public-testnet / mainnet-readiness hardening.

This document summarizes current repository evidence. Generated artifacts remain authoritative for mutable readiness facts.

## Current claim boundary

WeAll is an open-source deterministic civic coordination protocol implementation under active hardening. The repository contains implementation-stage code, tests, generated artifacts, operator runbooks, public civic surfaces, governance, disputes, reputation, observer/testnet tooling, tokenomics scaffolding, and protocol-safety boundaries.

Current generated state keeps public beta and mainnet readiness unclaimed. Controlled-testnet mechanism completion is also currently **NO-GO** because the production-helper state-root/restart equivalence gate remains incomplete.

Do not infer public validator safety, public multi-validator BFT readiness, live economics, automatic software upgrades, production helper execution, legal/compliance approval, public storage-market readiness, or completed production cryptographic review from local repository evidence.

## Public-only protocol direction

Protocol-native social, civic, governance, moderation, dispute, group, reputation, validator/operator, and protocol-state activity is intended to be publicly inspectable. Group membership may gate participation and administration, but it must not gate read visibility for protocol-native social or civic content. Sensitive Proof-of-Humanity evidence, account recovery secrets, private keys, and private local UI preferences remain outside that public-state rule.

## Current evidence posture

Repository evidence includes public-only regression checks, signed/pinned observer discovery inputs, governance/dispute lifecycle tests, record-only protocol-upgrade tests, economics-lock tests, release hygiene, secret guard, generated artifact checks, and deterministic source/derivative validation.

External evidence remains required for stronger launch claims, including independent validator/operator operation, cross-machine replay, real storage/IPFS operation, legal/compliance attestation, executable upgrade staging/rollback proof, production-helper topology proof, external observer journey evidence, and independent cryptographic review.

## Performance boundary

Historical local throughput measurements exist, but **no scalar TPS value is a current verified performance claim for this tree**. Any future scalar performance claim must be bound to the exact commit/tree and document workload semantics, cryptographic/signature behavior, persistence, network/consensus scope, topology, hardware, OS/runtime, warmup, duration, repetitions, latency and throughput distributions, error rate, and resource utilization.

## Canonical verification sources

Use the current generated artifacts rather than prose copies of mutable values:

- `generated/public_beta_blocker_report_v1_5.json`
- `generated/controlled_testnet_go_gate_v1_5.json`
- `generated/final_public_observer_controlled_testnet_go_gate_v1_5.json`
- `generated/release_evidence_manifest_v1_5.json`
- `generated/tx_index.json`
- `generated/v2/spec_compilation_manifest.json`
- `docs/CURRENT_VERIFIED_CLAIMS.md`

Current blocker totals, transaction counts, route counts, test counts, and other mutable measurements should be read directly from their generated authority instead of copied into this document.
