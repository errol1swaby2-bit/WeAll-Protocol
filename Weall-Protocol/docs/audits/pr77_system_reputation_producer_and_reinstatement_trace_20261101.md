# PR #77 — SYSTEM reputation producer reachability and reinstatement consistency

**Decision: REVIEW INPUT ONLY. No semantic approval, runtime migration, merge, or network activation.**

## Source and test pin

Audited draft starting HEAD `dd9f7f6a76c1cbd363ef2f3368dda7d19e76d149`, with follow-up regression commits `7916f766fc1c96df9700dfbb4f62bebc236f7194` and `9e057f793bb6de47946007ae2dfa69354b00d85f`. Tests added in `tests/test_pr77_account_reinstatement_state_consistency.py`; the existing `tests/test_pr77_reputation_floor_ban_boundary_characterization.py` remains unchanged. All cases use synthetic state and envelopes and therefore do not authenticate a real SYSTEM producer, juror vote, appeal, or historical block.

## Canonical SYSTEM authority chain

1. `src/weall/runtime/tx_contracts.py` has an explicit canonical handler registry. `ACCOUNT_BAN` is in `REPUTATION_TX_TYPES`, **not** in `IDENTITY_TX_TYPES`. `src/weall/runtime/domain_dispatch.py::apply_tx` calls `resolve_applier_for_tx_type` and then the selected handler. The old `src/weall/runtime/apply/identity.py::_apply_account_ban` implementation still exists and is reachable by direct helper calls, but is **not the production canonical ACCOUNT_BAN handler**. Merely noticing that old function is not a proven canonical bypass.
2. `src/weall/runtime/tx_admission.py::_system_origin_ok` requires a SYSTEM flag and canonical system signer for a SYSTEM-origin TX. Public-ingress and block-account signer checks are separate. `src/weall/runtime/system_tx_engine.py::validate_system_tx_queue_binding` checks emitted SYSTEM envelopes against deterministic persisted queue ID, type, due height, phase, signer, parent, payload and lineage shape. Matching the queue is a prerequisite, **not proof that the queue producer had adequate constitutional authority to create the item**.
3. `src/weall/runtime/reputation_accrual.py::schedule_reputation_accrual_system_txs` is intentionally a no-op: the former content-maturity `REPUTATION_DELTA_APPLY` producer is retired. Repository code search did not reveal a non-test caller of exported `apply_reputation_delta_system`. No live `REPUTATION_DELTA_APPLY` production source was established in this bounded source review. Dynamic dispatch, runtime integrations, untracked code and external producers were not exhaustively disproven.
4. `src/weall/runtime/apply/reputation.py::_apply_rep_delta_and_autoban` nevertheless writes both `accounts[id].banned=true` and `reputation.bans[id].banned=true, auto=true` upon floor crossing, including with constitutional-clock enabled, when called with an otherwise admitted synthetic SYSTEM delta. This is an executable **latent alternate exclusion path**, not a verified remotely triggerable exploit. Preserve old behavior for historical replay until a version/activation decision is proven.

## Reinstatement is presently not state-surface equivalent

A full synthetic `DISPUTE_FINAL_RECEIPT` with an `appeal_resolution.decision=modify` and an `ACCOUNT_REINSTATE` action takes the approved ordinary enforcement-action filter and `src/weall/runtime/apply/dispute.py::_apply_inline_content_enforcement` branch:

- The inline account remedy sets `accounts[id].restricted=false`, `accounts[id].locked=false`, `accounts[id].banned=false` and records a remedy.
- It does **not** clear or change an existing `reputation.bans[id]` record. The regression seeds a prior automatic ban and observes the account flag **false** but its ban-index `banned` flag **true** after the full transaction.
- `src/weall/runtime/apply/reputation.py::_apply_account_reinstate`, invoked directly with a synthetic canonical SYSTEM envelope for comparison, sets `accounts[id].banned=false` **and** records `reputation.bans[id].banned=false`.
- `src/weall/runtime/tx_admission.py::_reputation_and_flags_ok` checks the account's `banned` flag, rather than the reputation ban-index record. Other reputation and capability gates continue to apply. The index mismatch is not proof that a previously banned person necessarily gains all capabilities.
- The same synthetic inline mismatch is observed with constitutional-clock disabled and enabled, in both bounded-rollback and deepcopy oracles. **Engine parity is not constitutional correctness**. These are direct application tests; they do not prove a verified SYSTEM queue parent, successful block commitment, adjudicated appeal, or network replay.

The canonical transaction route and the old identity helper distinction are regression-pinned: `handler_claims_for_tx_type("ACCOUNT_BAN") == ["reputation"]`.

## Required decisions before modifying consensus state

1. Identify the normative source of truth for account exclusion and its audit history. Decide whether `reputation.bans` is an immutable event log, an active status index, or both; if it is an active index, define exact correction and restoration semantics.
2. Clarify whether an automatic -100 reputation floor imposes temporary capabilities loss or the **same** severe account-wide exclusion that requires full constitutional 25/20 initial-panel and fresh automatic appeal / narrowly valid waiver under the v2 First Draft. A reputation score by itself is not severe-sanction authorization.
3. Trace and authenticate each actual queue producer that could emit `REPUTATION_DELTA_APPLY`, `ACCOUNT_REINSTATE`, `DISPUTE_RESOLVE`, or `DISPUTE_FINAL_RECEIPT`. Inspect canonical parent references and consumer checks, not only the SYSTEM flag. Full-chain source coverage remains an open proof obligation.
4. Reconcile direct canonical and inline remedies using a **versioned and replay-safe** change if the active ban record must be updated. A naive inline update changes the state root of a historically valid final receipt. Obtain authentic old-height ledger/blocks and old software before authorizing such a change.
5. Preserve the constitutional-clock `ACCOUNT_BAN` fail-closed guard and ordinary-dispute `ACCOUNT_BAN` filter. Do not treat an account reinstatement as an authorized severe-sanction decision producer.
6. Keep V2's existing **15 stale semantic contracts** and the authentic historical replay gap unresolved until reviewed. A clean focused test suite is not a substitution for an independent reviewer or a public-beta release gate.

## Verification

Focused workflow: [PR77 severe-account finality fail-closed validation, run 41368536456](https://github.com/errol1swaby2-bit/WeAll-Protocol/actions/runs/41368536456). **PASS**, including existing severe-account cases, reputation-floor characterization, the new full-TX reinstatement characterization and canonical-routing check; Ruff checks and format checks passed. This proves only these current synthetic regression expectations.

**Release disposition stays NO-GO.** The source inconsistency is characterized and regression-pinned but not silently repaired; the correct constitutional remedy, authenticated producer and historical replay policy remain open.
