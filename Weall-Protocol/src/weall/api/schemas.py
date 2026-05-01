from __future__ import annotations

"""Pydantic request/response schemas for the public API.

Keep this module intentionally small and stable.

Note:
  The protocol's canonical tx payload schemas live elsewhere (tx_schema/tx_canon).
  These API schemas exist only for HTTP input validation and UX stability.

External identity-provider PoH request schemas were removed when PoH moved to
protocol-native async/live verification. Add new HTTP schemas here only when they
represent native protocol surfaces.
"""
