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

## GitHub evidence and remaining gates

- PR77 severe-account finality fail-closed validation: **PASS** on source guard commit `83a1ff7bc0733ba9ecced799d9f1074375b9a082` (run `41319299349`), including targeted dispute, scheduler, constitutional-clock and legacy behavior tests.
- Bounded V1.5 evidence refresh: **PASS**, run `41319395407`. Ruff checks succeeded and **41 focused tests passed**; seven declared artifacts were regenerated. Six derivative files changed; the API contract map was already current. Bot commit `9e0dd6fd8f40897ab2cc679a58c98ee05e788a13` also contains only Ruff formatting of the pre-reviewed source/test paths.
- The generated public-beta report still has **8 open blockers**.
- A bot-authored derivative commit can show `action_required` for follow-on PR workflows; this evidence note is committed separately to trigger ordinary PR checks.

### Explicit safety caveat

The `DISPUTE_OPEN` schema does **not** yet provide authenticated severity/sanction-class admission. This guard applies only to cases **already carrying explicit severe/critical/S4 account-targeted classification** and cannot substitute for a canonical classification and appeal producer. Other severe-like matters and any direct `ACCOUNT_BAN` execution require independent checks. The V2 `TX-0904` semantic review remains unapproved; the new `DISPUTE_FINAL_RECEIPT` behavior also warrants semantic/replay review. No launch or merge authorization is implied.


## Follow-up: unclassified ban-intent detection

The initial clock-mode hold required a declared severe/critical/S4 account class.
The follow-up extends the **hold only** to `ACCOUNT_BAN` actions in recorded
initial/final/appeal-panel resolutions and directly supplied final-receipt
resolutions. This includes account-ban actions mislabeled as a lower-severity
case or attached to another target type. Conflicting severity fields are
conservatively treated as severe when either level declares a severe class.

This is **not** canonical, authenticated classification. A case that omits
explicit severe metadata and contains no visible ban action cannot be
recognized by this predicate. The separate reputation-domain `ACCOUNT_BAN`
clock-mode reject continues to block direct execution. Unauthenticated
payload actions can HOLD a final receipt but can never GRANT authorization.

No protocol activation, automatic juror appeal, V2 semantic acceptance,
legacy replay change, or ban producer is introduced.
