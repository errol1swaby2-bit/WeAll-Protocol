# src/weall/storage/__init__.py
"""
Operator-side tooling (off-chain workers).

These modules are intentionally small, explicit, and fail-closed:
- they read ledger state (SQLite),
- perform side effects (e.g., IPFS pin),
- then enqueue SYSTEM txs into ledger["system_queue"] for deterministic inclusion.
"""
