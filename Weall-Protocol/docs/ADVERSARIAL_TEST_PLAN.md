# Adversarial Network Test Plan

## Goal
Prove consensus safety and liveness under realistic validator and network faults.

## Required scenarios
### 1. Proposal equivocation attempt
- two different proposals for the same view
- confirm followers reject the non-leader or bad-signature proposal
- confirm no conflicting QCs form

### 2. Missing block with received QC
- follower receives a QC before the referenced block
- confirm node records the missing block request state
- confirm node commits only after the block is fetched and replayed

### 3. Validator-set transition under load
- commit a `VALIDATOR_SET_UPDATE`
- inject old-epoch votes and timeouts after the transition
- confirm they are rejected deterministically

### 4. Network partition
- partition validators into two groups
- ensure neither side commits conflicting blocks
- verify the minority partition stalls safely
- verify convergence after healing

### 5. Crash/restart mid-consensus
- crash leader after proposal broadcast, before QC
- crash follower after receiving proposal, before vote persistence
- restart and verify monotonic view and no duplicate commits

### 6. Delayed/reordered consensus messages
- randomize vote, timeout, and proposal arrival order
- confirm finality remains monotonic

### 7. Malicious peer flood
- duplicate proposals
- malformed signatures
- stale-epoch votes
- oversized message spam
- confirm node remains live and memory stays bounded

## Success criteria
- never more than one committed block at a given height
- finalized height is monotonic
- validators never sign two blocks in the same view
- old-epoch consensus messages are rejected after reconfiguration
- restarted validators rejoin without manual state repair
