from __future__ import annotations

from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from typing import Any, Dict

Json = Dict[str, Any]

REPUTATION_SCALE = 1000
REPUTATION_MIN_UNITS = -100 * REPUTATION_SCALE
REPUTATION_MAX_UNITS = 100 * REPUTATION_SCALE
_DEC_SCALE = Decimal(REPUTATION_SCALE)


def _to_decimal(value: Any, default: Decimal = Decimal(0)) -> Decimal:
    if isinstance(value, Decimal):
        return value
    if value is None:
        return default
    if isinstance(value, bool):
        return Decimal(int(value))
    if isinstance(value, int):
        return Decimal(value)
    if isinstance(value, float):
        return Decimal(str(value))
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return default
        try:
            return Decimal(s)
        except InvalidOperation:
            return default
    try:
        return Decimal(str(value))
    except Exception:
        return default


def reputation_to_units(value: Any, *, default: int = 0) -> int:
    dec = _to_decimal(value, Decimal(default) / _DEC_SCALE)
    try:
        units = int((dec * _DEC_SCALE).to_integral_value(rounding=ROUND_HALF_UP))
    except Exception:
        return int(default)
    return int(units)


def units_to_reputation(units: Any, *, default: float = 0.0) -> float:
    try:
        return float(Decimal(int(units)) / _DEC_SCALE)
    except Exception:
        return float(default)


def clamp_reputation_units(units: int) -> int:
    u = int(units)
    if u < REPUTATION_MIN_UNITS:
        return REPUTATION_MIN_UNITS
    if u > REPUTATION_MAX_UNITS:
        return REPUTATION_MAX_UNITS
    return u


def account_reputation_units(acct: Json | None, *, default: int = 0) -> int:
    if not isinstance(acct, dict):
        return int(default)
    if "reputation_milli" in acct:
        try:
            return int(acct.get("reputation_milli") or 0)
        except Exception:
            return int(default)
    return reputation_to_units(acct.get("reputation", 0.0), default=default)


def sync_account_reputation(acct: Json, *, default_units: int = 0) -> int:
    units = account_reputation_units(acct, default=default_units)
    units = clamp_reputation_units(units)
    acct["reputation_milli"] = int(units)
    acct["reputation"] = units_to_reputation(units)
    return int(units)


def threshold_to_units(value: Any, *, default: int = 0) -> int:
    return reputation_to_units(value, default=default)
