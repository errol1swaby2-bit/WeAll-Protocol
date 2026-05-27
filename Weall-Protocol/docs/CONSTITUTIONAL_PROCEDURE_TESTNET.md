# Constitutional Procedure Testnet Notes

This batch converts constitutional process from documentation into a testnet-facing protocol target.

## Proposal flow

Proposals are expected to move through staged deliberation:

```text
draft -> poll -> revision -> validation -> voting -> closed -> tallied -> executed -> finalized
```

Constitutional-clock executable proposals cannot skip directly into voting. They must first pass through deliberation/revision/freeze semantics. Proposal comments and version history are protocol-visible so a voting version can be audited against prior deliberation.

## Dispute appeal flow

When the constitutional clock is enabled, dispute verdicts open an appeal window instead of immediately finalizing serious outcomes. The appeal deadline is a block height. System finalization is scheduled only after the appeal window closes and only if the dispute has not entered appeal review.

## Frontend role

The frontend explains stage, deadline block, blocks remaining, estimated time, proposal versions, deliberation comments, and appeal status. It does not decide stages. Backend/protocol state remains authority.
