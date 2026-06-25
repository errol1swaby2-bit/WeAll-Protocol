# Choose your WeAll node mode

This quickstart is a claim-control guide for controlled testnet rehearsals. It does not claim public beta, mainnet, public validator onboarding, live economics, production helper execution, or legal/compliance readiness.

## 1. Genesis node

Choose this only for the first local rehearsal authority. A Genesis node initializes the chain identity, genesis state, API surface, block loop, persistence store, and local frontend surface.

Use the Genesis path when you are creating a private rehearsal from a clean clone and can protect the authority profile. Do not distribute Genesis validator secrets in observer bundles.

## 2. Observer node

Choose this for a second user or external reviewer who needs to read public chain state, submit signed onboarding transactions through the observer edge, sync from the Genesis node, and verify chain identity without receiving validator authority.

Observer mode must keep validator signing disabled. An observer can progress through account creation and PoH, but observer boot is not validator readiness.

## 3. Promoted validator node

Choose this after the human account has completed the required PoH tier, registered a node device, enrolled as a node operator, opted into validator responsibility, passed readiness proof, and been activated into the validator set.

Switching from observer to production validator posture must go through the preflight scripts and runtime status surfaces. Do not mutate local state manually to create authority.

## 4. Storage/IPFS operator

Choose this only after explicit storage responsibility opt-in and capacity proof. Local browser storage preferences do not create protocol storage responsibility. IPFS/provider duties require verified capacity, durability checks, and revalidation.

## 5. Helper executor

Production helper execution remains disabled. Node operator status is not helper consent. Helper work requires explicit helper responsibility opt-in and future production helper gates.

## 6. Reviewer/juror lanes

Tier 2 identity is not consent to review. Reviewer work requires explicit lane opt-in for the exact responsibility:

- content review
- dispute review
- PoH async review
- PoH live review

Users can opt out of each lane independently.

## Current release boundary

The current repository posture is controlled testnet candidate evidence. Public beta still requires independent validator transcripts, real storage/IPFS operator transcripts, legal/compliance review, expanded public capability evidence, and future signed protocol-upgrade execution gates.


## Batch 620 public-beta evidence boundary

Current release posture remains: controlled multi-node testnet candidate.
Do not claim public beta, mainnet, public validator enablement, live economics,
production helper execution, public storage-market readiness, or legal/compliance
readiness until the external transcript requirements in
`Weall-Protocol/generated/external_operator_transcript_requirements_v1_5.json`
and `Weall-Protocol/docs/PUBLIC_BETA_EXTERNAL_EVIDENCE_RUNBOOK.md` are satisfied.

### Batch 626 public observer discovery note

Public observer launch evidence now requires the fail-closed seed registry flow documented in `PUBLIC_OBSERVER_TESTNET_QUICKSTART.md`, recovery guidance in `PUBLIC_TESTNET_NAT_FIREWALL_TLS_RECOVERY.md`, and external transcript capture from `PUBLIC_OBSERVER_EVIDENCE_RUNBOOK.md`. A public observer can be open-download only after real public seed URLs and pinned commitments are configured; validator activation remains protocol-gated.
