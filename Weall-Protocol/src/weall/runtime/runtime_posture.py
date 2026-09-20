from __future__ import annotations

"""Node lifecycle, observer mode, validator signing posture, and startup safety delegates.

This module is intentionally a structural extraction from ``weall.runtime.executor``.
It keeps the executor public API stable while shrinking the trusted surface area of
the monolithic facade. The extracted functions still operate on ``WeAllExecutor``
instances and intentionally preserve behavior byte-for-byte where possible.
"""

from typing import Any

from weall.runtime.executor import (
    BFT_MIN_VALIDATORS,
    CONSENSUS_PHASE_BFT_ACTIVE,
    PRODUCTION_CONSENSUS_PROFILE,
    PRODUCTION_SERVICE,
    ExecutorError,
    _env_bool,
    _helper_execution_profile_hash,
    _mode,
    _now_ms,
    evaluate_node_lifecycle_status,
    os,
)

Json = dict[str, Any]


def _runtime_meta(self) -> Json:
    meta = self.state.get("meta")
    if not isinstance(meta, dict):
        meta = {}
        self.state["meta"] = meta
    return meta


def _persist_runtime_meta(self) -> None:
    self._ledger_store.write(self.state)


def _evaluate_node_lifecycle_status(self):
    return evaluate_node_lifecycle_status(
        state=self.state,
        node_id=str(getattr(self, "node_id", "") or ""),
        chain_id=str(self.state.get("chain_id") or getattr(self, "chain_id", "") or ""),
        schema_version=str(getattr(self, "_schema_version_cached", "") or ""),
        tx_index_hash=str(getattr(self, "_tx_index_hash", "") or ""),
        runtime_profile_hash=str(PRODUCTION_CONSENSUS_PROFILE.profile_hash()),
    )


def _apply_node_lifecycle_runtime_overrides(self) -> None:
    status = self._evaluate_node_lifecycle_status()
    effective_roles = tuple(str(r) for r in (getattr(status, "service_roles_effective", ()) or ()))
    requested_state = str(getattr(status, "requested_state", "") or "")
    strict_authority = bool(_mode() == "prod" or requested_state == PRODUCTION_SERVICE)
    self._node_lifecycle_effective_state = str(getattr(status, "effective_state", "") or "")
    self._service_roles_effective = effective_roles
    if strict_authority:
        self._helper_mode_enabled_effective = bool(
            getattr(status, "helper_enabled_effective", False) and "helper" in set(effective_roles)
        )
        self._helper_fast_path_enabled_effective = bool(
            self._helper_mode_enabled_effective and self._helper_fast_path_enabled_default
        )
        self._bft_enabled_effective = bool(
            getattr(status, "bft_enabled_effective", False) and "validator" in set(effective_roles)
        )
    else:
        # Compatibility posture for bootstrap/dev nodes: keep helper/BFT runtime
        # availability aligned with the explicit local runtime request unless the
        # operator has opted into the stricter production_service lifecycle.
        self._helper_mode_enabled_effective = bool(self._helper_mode_enabled_default)
        self._helper_fast_path_enabled_effective = bool(
            self._helper_mode_enabled_effective and self._helper_fast_path_enabled_default
        )
        self._bft_enabled_effective = bool(_env_bool("WEALL_BFT_ENABLED", False))

    # Persist the runtime-effective helper profile only as node-local posture.
    # ``meta["helper_execution_profile"]`` is the consensus-pinned profile used
    # by block construction/replay and is state-root bound; overwriting it from
    # local lifecycle authority would make honest nodes commit different roots.
    meta = self._runtime_meta()
    runtime_helper_execution_profile = (
        self._effective_helper_execution_profile()
        if strict_authority
        else self._requested_helper_execution_profile()
    )
    meta["runtime_helper_execution_profile"] = dict(runtime_helper_execution_profile)
    meta["runtime_helper_execution_profile_hash"] = _helper_execution_profile_hash(
        runtime_helper_execution_profile
    )


def _persist_node_lifecycle_meta(self) -> None:
    meta = self._runtime_meta()
    status = self._evaluate_node_lifecycle_status()
    meta["node_lifecycle"] = status.to_json()


def _enforce_node_lifecycle_startup(self) -> None:
    status = self._evaluate_node_lifecycle_status()
    if bool(getattr(status, "startup_refusal_required", False)):
        reasons = list(getattr(status, "promotion_failure_reasons", ()) or ())
        detail = ",".join(str(r) for r in reasons if str(r).strip()) or "unknown"
        raise ExecutorError(f"node_lifecycle_startup_refused:{detail}")


def _init_validator_runtime_posture(self) -> None:
    meta = self._runtime_meta()
    runtime_open = bool(meta.get("runtime_open", False))
    previous_clean = bool(meta.get("last_shutdown_clean", True)) and not runtime_open
    observer_requested = _env_bool("WEALL_OBSERVER_MODE", False)
    signing_requested = _env_bool("WEALL_VALIDATOR_SIGNING_ENABLED", True)
    lifecycle = self._evaluate_node_lifecycle_status()

    forced_observer = False
    reason = ""
    if observer_requested:
        signing_requested = False
        forced_observer = True
        reason = "observer_mode_env"
    elif signing_requested and not bool(getattr(self, "_bft_restart_safety_ok", True)):
        signing_requested = False
        forced_observer = True
        reason = "bft_restart_qc_revalidation_failed"
    elif (
        _mode() == "prod"
        and getattr(self, "_startup_clock_observer_required", False)
        and signing_requested
    ):
        signing_requested = False
        forced_observer = True
        reason = str(getattr(self, "_startup_clock_observer_reason", "") or "clock_skew_warning")
    elif (
        bool(getattr(lifecycle, "bft_enabled_requested", False))
        and not bool(getattr(lifecycle, "bft_enabled_effective", False))
        and signing_requested
    ):
        signing_requested = False
        forced_observer = True
        reason = "node_lifecycle_not_validator_ready"
    elif _mode() == "prod" and not previous_clean and signing_requested:
        signing_requested = False
        forced_observer = True
        reason = "unclean_shutdown"

    self._validator_signing_enabled = bool(signing_requested)
    self._observer_mode_forced = bool(forced_observer)
    self._signing_block_reason = str(reason) if not self._validator_signing_enabled else ""

    meta.pop("last_startup_ms", None)
    meta["last_shutdown_clean"] = bool(previous_clean)
    meta["runtime_open"] = True
    meta["validator_signing_enabled"] = bool(self._validator_signing_enabled)
    meta["observer_mode"] = bool(not self._validator_signing_enabled)
    if self._signing_block_reason:
        meta["signing_block_reason"] = str(self._signing_block_reason)
    else:
        meta.pop("signing_block_reason", None)
    self._persist_node_lifecycle_meta()
    self._persist_runtime_meta()


def mark_clean_shutdown(self) -> None:
    meta = self._runtime_meta()
    meta["last_shutdown_clean"] = True
    meta["runtime_open"] = False
    meta["validator_signing_enabled"] = bool(self._validator_signing_enabled)
    meta["observer_mode"] = bool(not self._validator_signing_enabled)
    if self._signing_block_reason:
        meta["signing_block_reason"] = str(self._signing_block_reason)
    else:
        meta.pop("signing_block_reason", None)
    meta["last_clean_shutdown_ms"] = int(_now_ms())
    self._persist_node_lifecycle_meta()
    self._persist_runtime_meta()


def _effective_validator_signing_state(self) -> tuple[bool, str]:
    enabled = bool(self._validator_signing_enabled)
    reason = str(self._signing_block_reason or "")
    if not enabled:
        return False, reason
    if not bool(getattr(self, "_bft_restart_safety_ok", True)):
        return False, "bft_restart_qc_revalidation_failed"

    # Production validator operators must never keep automatic signing
    # enabled once the local security model degrades below public BFT.
    # This is evaluated against committed state so validator-set churn,
    # bootstrap phases, and partial recovery immediately force observer
    # posture even when the process started with signing enabled.
    if _mode() != "prod":
        return True, ""

    local_validator = self._local_validator_account()
    active_validators = self._active_validators()
    active_count = len(active_validators)
    current_phase = self._current_consensus_phase()

    if not local_validator:
        return False, "local_validator_identity_not_active"
    if local_validator not in set(active_validators):
        return False, "local_validator_not_in_active_set"
    if current_phase != CONSENSUS_PHASE_BFT_ACTIVE:
        return False, f"consensus_phase_not_bft_active:{current_phase or 'unknown'}"
    if active_count < int(BFT_MIN_VALIDATORS):
        return (
            False,
            f"validator_count_below_bft_minimum:{active_count}/{int(BFT_MIN_VALIDATORS)}",
        )

    return True, ""


def node_lifecycle_status(self) -> Json:
    state = self.read_state()
    meta = state.get("meta") if isinstance(state.get("meta"), dict) else {}
    persisted = meta.get("node_lifecycle") if isinstance(meta.get("node_lifecycle"), dict) else None
    if isinstance(persisted, dict) and persisted:
        return dict(persisted)
    status = self._evaluate_node_lifecycle_status()
    return status.to_json()


def validator_signing_enabled(self) -> bool:
    # Runtime/operator status surface: whether this node is currently
    # allowed to sign as a validator under committed chain state.  This must
    # reflect validator-set membership, consensus phase, and minimum BFT
    # validator count rather than only the startup/env request bit.  BFT
    # test helpers that manufacture signed artifacts can still use
    # _validator_signing_permitted(), which has the narrow pytest-local
    # compatibility override below.
    enabled, _reason = self._effective_validator_signing_state()
    return bool(enabled)


def _effective_signing_block_reason(self) -> str:
    enabled, reason = self._effective_validator_signing_state()
    return "" if enabled else str(reason or "")


def _explicit_validator_signing_override(self) -> bool:
    """Allow legacy local signing helpers outside real production runtime.

    Real production validator signing must come from the lifecycle-effective
    validator path in ``_effective_validator_signing_state()``.  Pytest-local
    BFT fixtures may still use explicit validator env tuples to manufacture
    signed artifacts without constructing the full node-operator lifecycle.
    """
    # Production validator authority must come only from committed lifecycle
    # and consensus state.  Unit-test detection is not an authority source.
    if _mode() == "prod":
        return False
    acct = str(os.environ.get("WEALL_VALIDATOR_ACCOUNT") or "").strip()
    pub = str(os.environ.get("WEALL_NODE_PUBKEY") or "").strip()
    priv = str(os.environ.get("WEALL_NODE_PRIVKEY") or "").strip()
    if not acct or not pub or not priv:
        return False
    active = set(self._active_validators())
    if acct not in active:
        return False
    expected = str(self._validator_pubkeys().get(acct) or "").strip()
    return (not expected) or expected == pub


def _validator_signing_permitted(self) -> bool:
    if not bool(getattr(self, "_bft_restart_safety_ok", True)):
        return False
    enabled, _reason = self._effective_validator_signing_state()
    return bool(enabled) or self._explicit_validator_signing_override()


def observer_mode(self) -> bool:
    return not bool(self.validator_signing_enabled())


def _prod_observer_block_production_reason(self) -> str:
    if _mode() != "prod":
        return ""
    lifecycle_state = str(os.environ.get("WEALL_NODE_LIFECYCLE_STATE") or "").strip().lower()
    explicit_observer = _env_bool("WEALL_OBSERVER_MODE", False)
    observer_onboarding = lifecycle_state == "observer_onboarding"
    if not explicit_observer and not observer_onboarding:
        return ""
    return self._effective_signing_block_reason() or (
        "observer_onboarding" if observer_onboarding else "observer_mode"
    )
