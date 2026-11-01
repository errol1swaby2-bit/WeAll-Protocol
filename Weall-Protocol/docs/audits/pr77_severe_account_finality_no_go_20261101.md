# PR77 — severe-account final receipt remains blocked (interim)

A constitutional-clock appeal-window expiry is **not** evidence of the automatic
fresh-panel appeal required by v2.0 §32 and DSP-210. The existing canonical
DISPUTE_OPEN schema records no severe-sanction class, so no comprehensive
automatic appeal producer can currently be authorized from that entry point.

This change adds a conservative predicate for **already explicitly classified**
account-targeted severe / critical / S4 cases; it prevents the existing
appeal-window scheduler from enqueuing their DISPUTE_FINAL_RECEIPT and the
dispute applier from executing a directly supplied final receipt.

Importantly, this is an incomplete safeguard: cases **without** an explicit
severity/class marker are not recognized, and an attacker must not be able to
choose a weaker class to evade the future canonical authorization policy.
ACCOUNT_BAN remains independently blocked in constitutional-clock mode by
PR77's earlier reputation-domain guard. No severe ban producer is enabled.

The canonical source of truth for case classification, initial 25/20 verdict
validation, automatic fresh 25/20 appeal and conflict clearance, deadline,
waiver after receipt of the full reasoned outcome, queue-parent binding,
restitution and restoration, consensus activation, and replay transition
remains **unimplemented**. These require substantive v2 semantic and
historical-adjudication review.

The focused tests are synthetic; passing them cannot authorize a merge,
release or live severe-sanction execution. This patch intentionally preserves
the ordinary-dispute and legacy-clock paths.
