# Counsel review evidence pack

Status: non-lawyer draft, pending counsel review.

This pack organizes the material needed to review `AUD-618-P0-002` before any
public beta, mainnet, live-economics, public-validator, treasury, storage-market,
or legal/compliance readiness claim is made. It is not legal advice, does not
substitute for counsel, and does not mark WeAll legally approved.

## Purpose

The repository may truthfully describe a bounded controlled-testnet/public-observer
rehearsal candidate only while the legal gate remains open. Counsel or another
controlled external reviewer must separately attest to the public claims that are
allowed, the claims that remain restricted, and the launch-disabled matrix that
keeps high-risk features inactive.

## Source documents for review

Counsel should review these tracked documents and artifacts at the exact commit
being considered for a release:

| Area | Files/artifacts |
| --- | --- |
| Public claims and truth boundaries | `docs/TRUTH_BOUNDARY.md`, `docs/PUBLIC_BETA_BLOCKERS.md`, `docs/reviewer/PUBLIC_BETA_BLOCKER_STATUS.md`, `docs/reviewer/CURRENT_TESTNET_READINESS_STATEMENT.md`, `docs/legal/PUBLIC_CLAIMS_CHECKLIST.md` |
| Token/economics claims | `docs/ECONOMICS_LOCKED_TOKENOMICS_MODEL.md`, `docs/TOKENOMICS_TESTNET_FLOW_AUDIT.md`, `docs/legal/TOKEN_MARKETING_GUARDRAILS.md`, `generated/tokenomics_simulation_v1_5.json`, `generated/launch_disabled_matrix_v1_5.json` |
| Governance/treasury claims | `docs/CONSTITUTIONAL_PROCEDURE_TESTNET.md`, `docs/EMISSARY_AND_TREASURY_GOVERNANCE_JOURNEY.md`, `docs/PROTOCOL_UPGRADE_RECORD_ONLY_BOUNDARY.md`, `docs/legal/AML_MONEY_TRANSMISSION_BOUNDARY.md` |
| Privacy/public-only posture | `docs/PUBLIC_ONLY_PROTOCOL.md`, `docs/ARCHITECTURE_DECISIONS/0002-remove-protocol-native-private-messaging.md`, `docs/ARCHITECTURE_DECISIONS/0003-public-group-visibility-member-gated-participation.md`, `docs/legal/PRIVACY_DATA_PROTECTION_POSTURE.md` |
| Minors, sanctions, severe harm, NCIM | `docs/legal/MINORS_AND_AGE_POLICY.md`, `docs/legal/SANCTIONS_AND_BLOCKED_PARTY_POLICY.md`, `docs/legal/SEVERE_HARM_AND_NCIM_POLICY.md` |
| Current launch-disabled matrix | `docs/LAUNCH_DISABLED_FEATURE_MATRIX.md`, `generated/launch_disabled_matrix_v1_5.json`, `src/weall/runtime/launch_matrix.py` |

## Claims counsel must classify

Counsel should classify each item as allowed, restricted, or requiring changes:

- bounded controlled-testnet/public-observer rehearsal candidate;
- public beta readiness;
- public mainnet readiness;
- public validator safety or public multi-validator BFT readiness;
- locked tokenomics implementation;
- live economics, transfers, fees, rewards, staking, slashing, treasury spending,
  or market behavior;
- governance and constitution/protocol upgrade language;
- public-only social/group/dispute/reputation activity;
- public storage/IPFS durability or storage-market claims;
- helper execution, production helper topology, or performance claims;
- anti-Sybil, identity, moderation, dispute, and reviewer-safety claims.

## Launch-disabled matrix counsel must confirm

For the current bounded release posture, counsel review should confirm that public
copy does not imply any of the following are active:

- live economics;
- token transfers, fees, staking, rewards, slashing, or market behavior;
- treasury spending as a live financial operation;
- public validator enrollment or public multi-validator BFT safety;
- automatic software upgrades, migrations, or rollbacks;
- production helper execution;
- public storage-market readiness or public decentralized media durability;
- legal/compliance approval.

## Attestation artifact

Use the template at:

```text
docs/proofs/legal-compliance-counsel/2026-07-05/ATTESTATION_TEMPLATE.json
```

A strict-release attestation must validate with:

```bash
PYTHONPATH=src:scripts python scripts/validate_external_operator_transcript_v1_5.py \
  --kind legal_compliance_attestation \
  --strict-release \
  --path <attestation.json>
```

The template intentionally fails strict-release validation because it contains
placeholder references and `sample_transcript_only=true`.

## Closure rule for AUD-618-P0-002

AUD-618-P0-002 remains open until a real counsel or controlled external review
attestation is attached to the release evidence package and passes strict-release
validation. Local draft docs, founder review, generated artifacts, and checklist
completion can improve readiness, but they cannot close the blocker.
