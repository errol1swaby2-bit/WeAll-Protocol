# WeAll Node Operator Onboarding

Status: **SUPERSEDED**.

This document has been superseded by the current first-run operator guide:

```text
docs/NEW_NODE_OPERATOR_QUICKSTART.md
```

This file is retained only as a compatibility pointer. Do not use it as a current release, transaction-canon, readiness, validator-authority, or production-service authority.

Compatibility lifecycle reminders retained for older links:

- Start with the current guide's observer/onboarding node path; it does not grant production service authority.
- After enrollment, deterministic protocol eligibility checks may automatically activate baseline Node Operator status when the current guide's prerequisites are satisfied.
- Baseline Node Operator status does not automatically grant validator authority.
- Baseline Node Operator status does not automatically grant storage allocation authority.
- The node key must be separate from the account recovery key.

Current mutable repository facts must be read from their generated authorities, including `generated/tx_index.json` for the transaction canon and the generated release/readiness artifacts for release status.
