from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from typing import Any

from weall.runtime.reputation_units import REPUTATION_SCALE

PROTOCOL_VERSION = "2026.03-prod.6"
GENESIS_CREATED_MS = 0
DEFAULT_MAX_BLOCK_FUTURE_DRIFT_MS = 2 * 60 * 1000
DEFAULT_CLOCK_SKEW_WARN_MS = 30 * 1000
DEFAULT_STARTUP_CLOCK_HARD_FAIL_MS = 24 * 60 * 60 * 1000
DEFAULT_MAX_BLOCK_TIME_ADVANCE_MS = 60 * 1000


@dataclass(frozen=True, slots=True)
class ProductionConsensusProfile:
    protocol_version: str = PROTOCOL_VERSION
    sigverify_required: bool = True
    legacy_sig_domain_allowed: bool = False
    qc_less_blocks_allowed: bool = False
    unsafe_autocommit_allowed: bool = False
    trusted_anchor_required: bool = True
    proposal_requires_justify_qc: bool = True
    handshake_requires_profile_match: bool = True
    handshake_requires_validator_epoch_match_for_bft: bool = True
    reputation_scale: int = REPUTATION_SCALE
    max_block_future_drift_ms: int = DEFAULT_MAX_BLOCK_FUTURE_DRIFT_MS
    clock_skew_warn_ms: int = DEFAULT_CLOCK_SKEW_WARN_MS
    monotonic_block_timestamps_required: bool = True
    startup_clock_sanity_required: bool = False
    startup_clock_hard_fail_ms: int = DEFAULT_STARTUP_CLOCK_HARD_FAIL_MS
    max_block_time_advance_ms: int = DEFAULT_MAX_BLOCK_TIME_ADVANCE_MS
    vrf_required: bool = False
    timestamp_rule: str = "chain_time_successor_only"

    def to_json(self) -> dict[str, object]:
        return {
            "protocol_version": self.protocol_version,
            "sigverify_required": bool(self.sigverify_required),
            "legacy_sig_domain_allowed": bool(self.legacy_sig_domain_allowed),
            "qc_less_blocks_allowed": bool(self.qc_less_blocks_allowed),
            "unsafe_autocommit_allowed": bool(self.unsafe_autocommit_allowed),
            "trusted_anchor_required": bool(self.trusted_anchor_required),
            "proposal_requires_justify_qc": bool(self.proposal_requires_justify_qc),
            "handshake_requires_profile_match": bool(self.handshake_requires_profile_match),
            "handshake_requires_validator_epoch_match_for_bft": bool(
                self.handshake_requires_validator_epoch_match_for_bft
            ),
            "reputation_scale": int(self.reputation_scale),
            "max_block_future_drift_ms": int(self.max_block_future_drift_ms),
            "clock_skew_warn_ms": int(self.clock_skew_warn_ms),
            "monotonic_block_timestamps_required": bool(self.monotonic_block_timestamps_required),
            "startup_clock_sanity_required": bool(self.startup_clock_sanity_required),
            "startup_clock_hard_fail_ms": int(self.startup_clock_hard_fail_ms),
            "max_block_time_advance_ms": int(self.max_block_time_advance_ms),
            "vrf_required": bool(self.vrf_required),
            "timestamp_rule": str(self.timestamp_rule),
        }

    def profile_hash(self) -> str:
        canon = json.dumps(self.to_json(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canon.encode("utf-8")).hexdigest()


PRODUCTION_CONSENSUS_PROFILE = ProductionConsensusProfile()


@dataclass(frozen=True, slots=True)
class _EnvCheck:
    kind: str
    names: tuple[str, ...]
    expected: bool | int
    allow_heal_forward: bool = False


def _mode() -> str:
    explicit = os.environ.get("WEALL_MODE")
    if explicit is not None:
        return str(explicit or "prod").strip().lower() or "prod"
    if os.environ.get("PYTEST_CURRENT_TEST"):
        return "test"
    if str(os.environ.get("WEALL_UNSAFE_DEV") or "").strip() == "1":
        return "testnet"
    return "prod"


def runtime_mode() -> str:
    return _mode()


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return bool(default)
    s = str(raw).strip().lower()
    if not s:
        return bool(default)
    if s in {"1", "true", "yes", "y", "on"}:
        return True
    if s in {"0", "false", "no", "n", "off"}:
        return False
    return bool(default)


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return int(default)
    try:
        return int(str(raw).strip())
    except Exception:
        return int(default)


def _env_bool_audit(name: str, default: bool) -> dict[str, Any]:
    raw = os.environ.get(name)
    if raw is None:
        return {
            "name": name,
            "present": False,
            "raw": None,
            "value": bool(default),
            "invalid": False,
        }
    s = str(raw).strip().lower()
    if not s:
        return {
            "name": name,
            "present": True,
            "raw": str(raw),
            "value": bool(default),
            "invalid": False,
        }
    if s in {"1", "true", "yes", "y", "on"}:
        value = True
        invalid = False
    elif s in {"0", "false", "no", "n", "off"}:
        value = False
        invalid = False
    else:
        value = bool(default)
        invalid = True
    return {
        "name": name,
        "present": True,
        "raw": str(raw),
        "value": bool(value),
        "invalid": bool(invalid),
    }


def _env_int_audit(name: str, default: int) -> dict[str, Any]:
    raw = os.environ.get(name)
    if raw is None:
        return {
            "name": name,
            "present": False,
            "raw": None,
            "value": int(default),
            "invalid": False,
        }
    s = str(raw).strip()
    if not s:
        return {
            "name": name,
            "present": True,
            "raw": str(raw),
            "value": int(default),
            "invalid": False,
        }
    try:
        value = int(s)
        invalid = False
    except Exception:
        value = int(default)
        invalid = True
    return {
        "name": name,
        "present": True,
        "raw": str(raw),
        "value": int(value),
        "invalid": bool(invalid),
    }


def _production_consensus_env_checks() -> tuple[_EnvCheck, ...]:
    p = PRODUCTION_CONSENSUS_PROFILE
    return (
        _EnvCheck("bool", ("WEALL_UNSAFE_DEV",), False),
        _EnvCheck("bool", ("WEALL_SIGVERIFY",), p.sigverify_required),
        _EnvCheck("bool", ("WEALL_ALLOW_LEGACY_SIG_DOMAIN",), p.legacy_sig_domain_allowed),
        _EnvCheck("bool", ("WEALL_BFT_ALLOW_QC_LESS_BLOCKS",), p.qc_less_blocks_allowed),
        _EnvCheck("bool", ("WEALL_BFT_UNSAFE_AUTOCOMMIT",), p.unsafe_autocommit_allowed),
        _EnvCheck("bool", ("WEALL_BFT_ALLOW_UNSIGNED_TIMEOUTS",), False),
        _EnvCheck(
            "bool",
            (
                "WEALL_STATE_SYNC_REQUIRE_TRUSTED_ANCHOR",
                "WEALL_SYNC_REQUIRE_TRUSTED_ANCHOR",
            ),
            p.trusted_anchor_required,
        ),
        _EnvCheck("int", ("WEALL_MAX_BLOCK_FUTURE_DRIFT_MS",), p.max_block_future_drift_ms),
        _EnvCheck("int", ("WEALL_CLOCK_SKEW_WARN_MS",), p.clock_skew_warn_ms),
        _EnvCheck(
            "int",
            ("WEALL_STARTUP_CLOCK_HARD_FAIL_MS",),
            p.startup_clock_hard_fail_ms,
        ),
        _EnvCheck(
            "int",
            ("WEALL_MAX_BLOCK_TIME_ADVANCE_MS",),
            p.max_block_time_advance_ms,
        ),
        _EnvCheck("bool", ("WEALL_REQUIRE_VRF",), p.vrf_required),
        _EnvCheck(
            "bool",
            ("WEALL_STARTUP_CLOCK_SANITY_REQUIRED",),
            p.startup_clock_sanity_required,
            allow_heal_forward=True,
        ),
    )


def production_consensus_env_audit() -> dict[str, Any]:
    """Return a structured audit of production consensus/profile env posture.

    The goal is to keep all consensus-critical runtime overrides behind one
    pinned fail-closed profile and expose the exact env surface operators need
    to compare across nodes. In non-production modes the report is still useful,
    but it is informational only.
    """
    p = PRODUCTION_CONSENSUS_PROFILE
    mode = _mode()
    checks = _production_consensus_env_checks()
    entries: list[dict[str, Any]] = []
    violations: list[str] = []

    for check in checks:
        if check.kind == "bool":
            observed = [_env_bool_audit(name, bool(check.expected)) for name in check.names]
        else:
            observed = [_env_int_audit(name, int(check.expected)) for name in check.names]
        present_values = [entry["value"] for entry in observed if entry["present"]]
        invalid_names = [str(entry["name"]) for entry in observed if entry["invalid"]]
        conflict = len(set(present_values)) > 1
        mismatch_names = [
            str(entry["name"])
            for entry in observed
            if entry["present"] and not entry["invalid"] and entry["value"] != check.expected
        ]
        ignored_names = list(mismatch_names) if check.allow_heal_forward else []
        effective_mismatch_names = [] if check.allow_heal_forward else list(mismatch_names)
        if invalid_names:
            violations.extend([f"invalid_env:{name}" for name in invalid_names])
        if conflict:
            violations.append("env_alias_conflict:" + "/".join(check.names))
        if effective_mismatch_names:
            violations.extend(effective_mismatch_names)
        entries.append(
            {
                "kind": check.kind,
                "names": list(check.names),
                "expected": check.expected,
                "observed": observed,
                "conflict": bool(conflict),
                "ignored_for_heal_forward": bool(check.allow_heal_forward),
                "mismatch_names": mismatch_names,
                "effective_mismatch_names": effective_mismatch_names,
                "ignored_names": ignored_names,
            }
        )

    canonical_payload = {
        "protocol_version": str(p.protocol_version),
        "protocol_profile_hash": str(p.profile_hash()),
        "mode": mode,
        "checks": [
            {
                "kind": entry["kind"],
                "names": entry["names"],
                "expected": entry["expected"],
                "observed": [
                    {
                        "name": observed["name"],
                        "present": observed["present"],
                        "value": observed["value"],
                        "invalid": observed["invalid"],
                    }
                    for observed in entry["observed"]
                ],
                "conflict": entry["conflict"],
                "ignored_for_heal_forward": entry["ignored_for_heal_forward"],
            }
            for entry in entries
        ],
    }
    canon = json.dumps(canonical_payload, sort_keys=True, separators=(",", ":"))
    return {
        "mode": mode,
        "profile_enforced": bool(mode == "prod"),
        "protocol_version": str(p.protocol_version),
        "protocol_profile_hash": str(p.profile_hash()),
        "ok": not violations,
        "violations": sorted(set(violations)),
        "checks": entries,
        "audit_fingerprint": hashlib.sha256(canon.encode("utf-8")).hexdigest(),
    }


def active_consensus_profile() -> ProductionConsensusProfile:
    return PRODUCTION_CONSENSUS_PROFILE


def runtime_protocol_version() -> str:
    return active_consensus_profile().protocol_version


def runtime_protocol_profile_hash() -> str:
    return active_consensus_profile().profile_hash()


def runtime_max_block_future_drift_ms() -> int:
    return int(active_consensus_profile().max_block_future_drift_ms)


def runtime_clock_skew_warn_ms() -> int:
    return int(active_consensus_profile().clock_skew_warn_ms)


def runtime_startup_clock_hard_fail_ms() -> int:
    return int(active_consensus_profile().startup_clock_hard_fail_ms)


def runtime_max_block_time_advance_ms() -> int:
    return int(active_consensus_profile().max_block_time_advance_ms)


def runtime_vrf_required() -> bool:
    p = active_consensus_profile()
    if _mode() == "prod":
        return bool(p.vrf_required)
    return bool(_env_bool("WEALL_REQUIRE_VRF", p.vrf_required))


def effective_runtime_consensus_posture() -> dict[str, object]:
    """
    Return the effective runtime consensus posture that operators should rely on.

    In production, this is the pinned production profile regardless of unsafe
    environment overrides. In non-production modes we still expose the raw
    effective env-driven toggles because testnet/dev flows intentionally use
    some compatibility switches.
    """
    p = active_consensus_profile()
    mode = _mode()
    env_audit = production_consensus_env_audit()

    if mode == "prod":
        return {
            "mode": mode,
            "profile_enforced": True,
            "sigverify_required": bool(p.sigverify_required),
            "legacy_sig_domain_allowed": bool(p.legacy_sig_domain_allowed),
            "qc_less_blocks_allowed": bool(p.qc_less_blocks_allowed),
            "unsafe_autocommit_allowed": bool(p.unsafe_autocommit_allowed),
            "trusted_anchor_required": bool(p.trusted_anchor_required),
            "proposal_requires_justify_qc": bool(p.proposal_requires_justify_qc),
            "handshake_requires_profile_match": bool(p.handshake_requires_profile_match),
            "handshake_requires_validator_epoch_match_for_bft": bool(
                p.handshake_requires_validator_epoch_match_for_bft
            ),
            "max_block_future_drift_ms": int(p.max_block_future_drift_ms),
            "clock_skew_warn_ms": int(p.clock_skew_warn_ms),
            "startup_clock_sanity_required": bool(p.startup_clock_sanity_required),
            "startup_clock_hard_fail_ms": int(p.startup_clock_hard_fail_ms),
            "max_block_time_advance_ms": int(p.max_block_time_advance_ms),
            "protocol_version": str(p.protocol_version),
            "protocol_profile_hash": str(p.profile_hash()),
            "vrf_required": bool(p.vrf_required),
            "timestamp_rule": str(p.timestamp_rule),
            "consensus_env_audit_ok": bool(env_audit["ok"]),
            "consensus_env_audit_fingerprint": str(env_audit["audit_fingerprint"]),
        }

    return {
        "mode": mode,
        "profile_enforced": False,
        "sigverify_required": bool(_env_bool("WEALL_SIGVERIFY", p.sigverify_required)),
        "legacy_sig_domain_allowed": bool(
            _env_bool("WEALL_ALLOW_LEGACY_SIG_DOMAIN", p.legacy_sig_domain_allowed)
        ),
        "qc_less_blocks_allowed": bool(
            _env_bool("WEALL_BFT_ALLOW_QC_LESS_BLOCKS", p.qc_less_blocks_allowed)
        ),
        "unsafe_autocommit_allowed": bool(
            _env_bool("WEALL_BFT_UNSAFE_AUTOCOMMIT", p.unsafe_autocommit_allowed)
        ),
        "trusted_anchor_required": bool(
            _env_bool(
                "WEALL_STATE_SYNC_REQUIRE_TRUSTED_ANCHOR",
                _env_bool("WEALL_SYNC_REQUIRE_TRUSTED_ANCHOR", p.trusted_anchor_required),
            )
        ),
        "proposal_requires_justify_qc": bool(p.proposal_requires_justify_qc),
        "handshake_requires_profile_match": bool(p.handshake_requires_profile_match),
        "handshake_requires_validator_epoch_match_for_bft": bool(
            p.handshake_requires_validator_epoch_match_for_bft
        ),
        "max_block_future_drift_ms": int(
            _env_int("WEALL_MAX_BLOCK_FUTURE_DRIFT_MS", p.max_block_future_drift_ms)
        ),
        "clock_skew_warn_ms": int(_env_int("WEALL_CLOCK_SKEW_WARN_MS", p.clock_skew_warn_ms)),
        "startup_clock_sanity_required": bool(
            _env_bool("WEALL_STARTUP_CLOCK_SANITY_REQUIRED", p.startup_clock_sanity_required)
        ),
        "startup_clock_hard_fail_ms": int(
            _env_int("WEALL_STARTUP_CLOCK_HARD_FAIL_MS", p.startup_clock_hard_fail_ms)
        ),
        "max_block_time_advance_ms": int(
            _env_int("WEALL_MAX_BLOCK_TIME_ADVANCE_MS", p.max_block_time_advance_ms)
        ),
        "protocol_version": str(p.protocol_version),
        "protocol_profile_hash": str(p.profile_hash()),
        "vrf_required": bool(_env_bool("WEALL_REQUIRE_VRF", p.vrf_required)),
        "timestamp_rule": str(p.timestamp_rule),
        "consensus_env_audit_ok": bool(env_audit["ok"]),
        "consensus_env_audit_fingerprint": str(env_audit["audit_fingerprint"]),
    }


def runtime_startup_fingerprint(
    *,
    chain_id: str,
    node_id: str,
    tx_index_hash: str,
    schema_version: str,
    bft_enabled: bool = False,
    validator_epoch: int = 0,
    validator_set_hash: str = "",
) -> dict[str, object]:
    """
    Deterministic operator-facing startup fingerprint.

    Operators can compare this across nodes to catch configuration drift before
    participating in consensus.
    """
    p = active_consensus_profile()
    posture = effective_runtime_consensus_posture()
    payload = {
        "chain_id": str(chain_id or ""),
        "node_id": str(node_id or ""),
        "protocol_version": str(p.protocol_version),
        "protocol_profile_hash": str(p.profile_hash()),
        "schema_version": str(schema_version or ""),
        "tx_index_hash": str(tx_index_hash or ""),
        "mode": str(posture.get("mode") or _mode()),
        "profile_enforced": bool(posture.get("profile_enforced", False)),
        "sigverify_required": bool(posture.get("sigverify_required", p.sigverify_required)),
        "qc_less_blocks_allowed": bool(
            posture.get("qc_less_blocks_allowed", p.qc_less_blocks_allowed)
        ),
        "unsafe_autocommit_allowed": bool(
            posture.get("unsafe_autocommit_allowed", p.unsafe_autocommit_allowed)
        ),
        "trusted_anchor_required": bool(
            posture.get("trusted_anchor_required", p.trusted_anchor_required)
        ),
        "max_block_future_drift_ms": int(
            posture.get("max_block_future_drift_ms", p.max_block_future_drift_ms)
        ),
        "clock_skew_warn_ms": int(posture.get("clock_skew_warn_ms", p.clock_skew_warn_ms)),
        "startup_clock_sanity_required": bool(
            posture.get("startup_clock_sanity_required", p.startup_clock_sanity_required)
        ),
        "startup_clock_hard_fail_ms": int(
            posture.get("startup_clock_hard_fail_ms", p.startup_clock_hard_fail_ms)
        ),
        "max_block_time_advance_ms": int(
            posture.get("max_block_time_advance_ms", p.max_block_time_advance_ms)
        ),
        "vrf_required": bool(posture.get("vrf_required", p.vrf_required)),
        "timestamp_rule": str(posture.get("timestamp_rule") or p.timestamp_rule),
        "consensus_env_audit_ok": bool(posture.get("consensus_env_audit_ok", False)),
        "consensus_env_audit_fingerprint": str(
            posture.get("consensus_env_audit_fingerprint") or ""
        ),
        "bft_enabled": bool(bft_enabled),
        "validator_epoch": int(validator_epoch),
        "validator_set_hash": str(validator_set_hash or ""),
    }
    canon = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return {
        **payload,
        "fingerprint": hashlib.sha256(canon.encode("utf-8")).hexdigest(),
    }


def validate_runtime_consensus_profile() -> None:
    """Fail closed when production nodes try to start with unsafe consensus overrides."""
    if _mode() != "prod":
        return

    p = PRODUCTION_CONSENSUS_PROFILE
    audit = production_consensus_env_audit()
    if audit["ok"]:
        return
    joined = ", ".join(str(item) for item in audit["violations"])
    raise ValueError(
        "production consensus profile mismatch: "
        f"{joined}. Expected pinned profile {p.protocol_version} "
        f"({p.profile_hash()[:16]}...)."
    )
