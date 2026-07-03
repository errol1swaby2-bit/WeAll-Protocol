# Late-stage NLnet / public-testnet readiness gap inventory v1.5

Status: recursive audit inventory for late pre-public-testnet hardening.

This inventory is a reviewer-confidence map, not a readiness claim. It records what the repository currently proves, what was safely tightened in this pass, and what must remain open for funded mainnet-readiness hardening.

## Claim boundary

WeAll should be described as **late-stage pre-public-testnet / mainnet-readiness hardening**. The repository must not claim public mainnet readiness, production-safe live economics, automatic protocol-upgrade execution, global 2350 TPS throughput, or completed public multi-validator BFT readiness.

## Inventory results

| Area | Current repository signal | Gap class | Safe action in this pass | Must remain open |
| --- | --- | --- | --- | --- |
| Public-only protocol surface | Public-only docs/tests and route policy are present. Recursive search found no active protocol-native DM, encrypted-message, private-group, member-only-read, ciphertext, sealed-payload, or inbox/outbox implementation path. | Policy regression risk | Kept strict boundary; added no private surfaces. | Continue running public-only route/source tests on every release. |
| Protocol upgrades | `PROTOCOL_UPGRADE_DECLARE` and `PROTOCOL_UPGRADE_ACTIVATE` are record-only and block-height scheduled. Automatic software apply/migration/rollback is disabled. | Mainnet-readiness hardening | Tightened duplicate declaration/activation behavior so duplicate records cannot silently rewrite upgrade targets or activation heights; duplicate activation now returns the matching scheduled record instead of a global last-active record. | Signed manifests, compatibility windows, deterministic migration vectors, rollback semantics, and multi-node rehearsal. |
| Governance lifecycle | Governance has a block-height system-queue lifecycle and deterministic stage stamps. | Protocol-safety hardening | Hardened `_due_height` trust: user-submitted governance payloads can no longer forge lifecycle heights; only SYSTEM queue-bound txs may use scheduler `_due_height`. | Full UI/API E2E evidence for proposal creation through finalization. |
| Dispute lifecycle | Dispute juror accept/vote/withdraw/timeout windows are block-height based; appeal windows are deterministic when the constitutional clock is enabled. | Observability and replay hardening | Added explicit block-height markers for dispute opening, stage transition, and juror assignment. | Broader appeal-panel E2E evidence, public reviewer notes, and multi-node replay transcripts. |
| Economics | Tokenomics are scaffolded but live economics remain locked. | Launch-disabled feature | No activation path was loosened. | Legal/compliance review and governed activation evidence. |
| Public observer / closed testnet | Chain identity, seed registry, observer boot, and authority-boundary tests/runbooks exist. | External evidence required | Documented the closed-testnet rehearsal path and evidence bundle separately from public-mainnet claims. | External clean-clone observer transcript, independent operator transcript, state-sync proof, rendered frontend journey. |
| Performance | Sustained-load harness and local evidence path exist; local 2350 TPS evidence must be tied to the submitted commit before use. | Evidence packaging | Kept wording as local harness only. | Public network performance evidence and hardware/environment-specific transcripts. |
| UX coherence | Frontend has public activity, groups, governance, disputes, economics-locked, and node status surfaces. | UX follow-up | No speculative rebuild; bounded docs/tests point reviewers to existing surfaces. | Guided operator wizard, tx propagation timeline, incident timeline, accessibility pass. |
| Generated artifacts | Readiness artifacts separate controlled-testnet ready-to-run from public-beta readiness. | Freshness gate | Failure-code registry should be regenerated whenever source error codes change. | Keep generated checks in release gate. |

## Blocker classification summary

The public-beta blocker report should remain split into these buckets:

- **Closed artifact/docs blockers**: API response vectors, launch-disabled matrix snapshot, release-evidence manifest / clean-clone gate, node-mode quickstart.
- **External-evidence blockers**: public validator operator transcript, legal/compliance attestation, cross-machine state-root replay export, real storage/IPFS operator transcript, public observer open-download transcript.
- **Mainnet-readiness hardening blockers**: automatic protocol-upgrade execution, production helper topology, public multi-validator adversarial proof.
- **UX/observability follow-ups**: operator wizard, tx propagation lifecycle, incident timeline.

## Safety checks added by this pass

- Protocol-upgrade duplicate declarations are idempotent only when the existing record is identical; conflicting re-declarations fail closed.
- Protocol-upgrade duplicate activations must match the already scheduled target and activation height; conflicting duplicate activations fail closed.
- Duplicate activation replay returns the scheduled record for the requested upgrade id, not whichever activation record was scheduled last.
- External governance transactions cannot use `_due_height` to forge creation, vote, update, or lifecycle heights.
- Disputes now record explicit block-height phase markers for opening, stage set, and juror assignment.

## Recommended next audit focus

The next bounded pass should target frontend/API reviewer flow coherence and evidence capture: one public civic loop from account state, public post, public group read/participation boundary, proposal lifecycle, dispute lifecycle, reputation outcome, protocol-upgrade record, observer status, and economics-locked status.
