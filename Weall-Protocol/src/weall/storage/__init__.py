"""Storage helpers for non-consensus API-side services.

This package intentionally contains node-local storage and quota helpers only.
Consensus execution must not depend on filesystem state.
"""

__all__ = ["ipfs_partition"]
