# PR77 current-version full-inventory executor oracle — no attestation

This is a **236-transaction synthetic fixture differential**, distinct
from authentic historical ledger replay.

The new `tests/test_pr77_all_tx_deepcopy_oracle.py` prepares identical
transaction envelopes and state using the existing A02 lifecycle fixtures.
For each of the 236 current transaction types it runs the bounded rollback
executor and independent deepcopy executor, requiring equal metadata,
full post-transaction states, roots, and absence of escaped journal proxies.

The CI workflow collects a JUnit test report without updating any derived
lifecycle JSON, review digests, genesis, production switches, or root
commitments.

**Limits:** Current-version oracle agreement proves neither compatibility
with software used to produce old blocks nor path-complete coverage of
unseen transaction payloads. In particular, CPython's native JSON encoder
may inspect internal storage of dict subclasses rather than proxied backing
dictionaries. The bounded rollback `JournaledDict` intentionally keeps
its inherited dict storage empty. Hash-input call sites need targeted
adversarial verification of nested proxy serialization; a 236-fixture
green result alone cannot dismiss that risk.

The four stale V1.5 lifecycle vectors and 15 stale V2 semantic reviews
remain independently fail-closed pending retained-history evidence and
authorized semantic adjudication. No public testnet or merge approval.
