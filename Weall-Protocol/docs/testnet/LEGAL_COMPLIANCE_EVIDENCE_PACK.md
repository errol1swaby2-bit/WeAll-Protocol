# Legal/compliance evidence pack for bounded testnet readiness

Status: non-lawyer draft, pending counsel review.

This page explains how testers and reviewers should interpret the legal/compliance
work for the bounded public observer / controlled testnet candidate. It is not
legal advice and does not state that WeAll is legally approved.

## Current status

- `AUD-618-P0-002` is still open.
- Public beta readiness remains unclaimed.
- Mainnet readiness remains unclaimed.
- Live economics remain disabled and unclaimed.
- Public validator safety and public multi-validator BFT remain unclaimed.
- Public storage-market and decentralized media durability claims remain unclaimed.

## What this pass adds

The repository now has a counsel-review evidence pack that organizes the exact
materials a reviewer or counsel should inspect before public launch claims:

```text
docs/legal/COUNSEL_REVIEW_EVIDENCE_PACK.md
docs/proofs/legal-compliance-counsel/2026-07-05/ATTESTATION_TEMPLATE.json
```

The pack maps token/economics, governance, treasury, privacy/public-only,
moderation, identity, storage, helper, and validator claims to the launch-disabled
matrix. It also records the claims that must stay restricted until counsel or a
controlled external reviewer signs an attestation.

## Required evidence to close AUD-618-P0-002

A real closure requires all of the following:

1. exact commit and branch reviewed;
2. counsel or controlled external reviewer reference;
3. scope covering public claims, token/economics, governance, treasury,
   privacy/public-only posture, minors/safety/sanctions policy, storage claims,
   helper claims, public validator claims, and public beta/mainnet language;
4. approved public claims list;
5. restricted claims list;
6. launch-disabled matrix check confirming live economics, token transfers,
   staking, validator rewards/slashing, automatic upgrades, treasury spending,
   public storage-market readiness, and production helper execution remain off;
7. signature or controlled reference;
8. strict-release validation command output.

## Validation command

```bash
cd ~/WeAll-Protocol/Weall-Protocol
source .venv/bin/activate

PYTHONPATH=src:scripts python scripts/validate_external_operator_transcript_v1_5.py \
  --kind legal_compliance_attestation \
  --strict-release \
  --path <attestation.json>
```

## Allowed wording before closure

Allowed:

```text
Ready for controlled internal/public-observer rehearsal candidate, with public
beta readiness still blocked by explicit external evidence and counsel-review gates.
```

Forbidden before closure:

```text
legal approval
legal clearance
public beta ready
mainnet ready
live economics ready
public validator safe
public multi-validator BFT ready
production helper execution ready
public storage-market ready
```
