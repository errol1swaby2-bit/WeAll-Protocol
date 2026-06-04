from __future__ import annotations

"""Genesis profile, initial state, and explicit bootstrap grant delegates.

This module is intentionally a structural extraction from ``weall.runtime.executor``.
It keeps the executor public API stable while shrinking the trusted surface area of
the monolithic facade. The extracted functions still operate on ``WeAllExecutor``
instances and intentionally preserve behavior byte-for-byte where possible.
"""


def _bind_executor_globals() -> None:
    """Lazily mirror executor globals after executor import has completed.

    The first refactor pass is deliberately behavior-preserving. Existing method
    bodies reference executor-level imports and helpers. Binding lazily avoids
    circular imports while keeping this patch focused on module boundaries rather
    than protocol semantics.
    """
    from weall.runtime import executor as _executor_mod

    for _name, _value in vars(_executor_mod).items():
        if _name not in globals():
            globals()[_name] = _value


def _current_genesis_bootstrap_profile(self) -> Json:
    _bind_executor_globals()
    explicit_enabled = _env_bool("WEALL_GENESIS_BOOTSTRAP_ENABLE", False)
    genesis_mode_enabled = _env_bool("WEALL_GENESIS_MODE", False)
    acct = str(os.environ.get("WEALL_GENESIS_BOOTSTRAP_ACCOUNT") or "").strip()
    pk = str(os.environ.get("WEALL_GENESIS_BOOTSTRAP_PUBKEY") or "").strip()
    mode = "disabled"
    if genesis_mode_enabled:
        mode = "genesis_mode"
        acct = acct or str(
            os.environ.get("WEALL_VALIDATOR_ACCOUNT")
            or self.node_id
            or os.environ.get("WEALL_NODE_ID")
            or ""
        ).strip()
        pk = pk or str(os.environ.get("WEALL_NODE_PUBKEY") or "").strip()
    elif explicit_enabled:
        mode = "explicit"

    enabled = bool(explicit_enabled or genesis_mode_enabled)
    bootstrap_rep_raw = os.environ.get("WEALL_GENESIS_BOOTSTRAP_REPUTATION")
    bootstrap_rep_units = threshold_to_units(
        bootstrap_rep_raw if bootstrap_rep_raw is not None else "1.0",
        default=REPUTATION_SCALE,
    )
    if bootstrap_rep_units < 0:
        bootstrap_rep_units = 0
    try:
        storage_capacity = int(
            os.environ.get("WEALL_GENESIS_BOOTSTRAP_STORAGE_CAPACITY_BYTES") or 0
        )
    except Exception:
        storage_capacity = 0
    if storage_capacity < 0:
        storage_capacity = 0
    return {
        "enabled": bool(enabled),
        "mode": str(mode),
        "account": str(acct),
        "pubkey": str(pk),
        "reputation_milli": int(bootstrap_rep_units),
        "storage_capacity_bytes": int(storage_capacity),
    }

def _initial_state(self) -> Json:
    _bind_executor_globals()
    genesis_bootstrap_profile = self._current_genesis_bootstrap_profile()
    # Open PoH bootstrap is a local-dev-only escape hatch.  It must never be
    # enabled implicitly, because controlled multi-node devnet readiness must
    # exercise real Tier1 -> Tier2 -> Live protocol onboarding instead of a
    # bounded self-grant shortcut.  Operators who intentionally need the old
    # local helper must opt in with WEALL_MODE=dev and WEALL_POH_BOOTSTRAP_OPEN=1.
    bootstrap_open_enabled = (
        True if _mode() == "dev" and _env_bool("WEALL_POH_BOOTSTRAP_OPEN", False) else False
    )
    bootstrap_max_height = (
        max(1, _env_int("WEALL_POH_BOOTSTRAP_MAX_HEIGHT", 50)) if bootstrap_open_enabled else 0
    )

    params: Json = {
        "poh_bootstrap_open": bootstrap_open_enabled,
    }
    if bootstrap_open_enabled:
        params["poh_bootstrap_mode"] = "open"
        params["poh_bootstrap_max_height"] = bootstrap_max_height

    poh_params: Json = {}
    _tier2_env_map = {
        "tier2_n_jurors": "WEALL_POH_TIER2_N_JURORS",
        "tier2_min_total_reviews": "WEALL_POH_TIER2_MIN_TOTAL_REVIEWS",
        "tier2_pass_threshold": "WEALL_POH_TIER2_PASS_THRESHOLD",
        "tier2_fail_max": "WEALL_POH_TIER2_FAIL_MAX",
        "tier2_min_rep_milli": "WEALL_POH_TIER2_MIN_REP_MILLI",
        # Native async Tier-1 review parameters.  These are normally
        # governance/chain defaults, but controlled local rehearsals need a
        # deterministic one-reviewer quorum so the end-to-end browser path
        # can complete with only the genesis reviewer online.
        "async_n_jurors": "WEALL_POH_ASYNC_N_JURORS",
        "async_min_reviews": "WEALL_POH_ASYNC_MIN_REVIEWS",
        "async_approval_threshold": "WEALL_POH_ASYNC_APPROVAL_THRESHOLD",
        "async_rejection_threshold": "WEALL_POH_ASYNC_REJECTION_THRESHOLD",
        "async_expiry_window_blocks": "WEALL_POH_ASYNC_EXPIRY_WINDOW_BLOCKS",
        "async_min_rep_milli": "WEALL_POH_ASYNC_MIN_REP_MILLI",
        # Native live Tier-2 review parameters.  Controlled local
        # rehearsals use a one-reviewer bootstrap panel so the browser
        # conference path can progress with only the genesis reviewer
        # online. Production remains governed by committed params.
        "live_min_rep_milli": "WEALL_POH_LIVE_MIN_REP_MILLI",
        "live_pass_threshold_num": "WEALL_POH_LIVE_PASS_THRESHOLD_NUM",
        "live_pass_threshold_den": "WEALL_POH_LIVE_PASS_THRESHOLD_DEN",
        "live_partial_until_height": "WEALL_POH_LIVE_PARTIAL_UNTIL_HEIGHT",
    }
    for _param_key, _env_key in _tier2_env_map.items():
        _raw = os.environ.get(_env_key)
        if _raw is None or str(_raw).strip() == "":
            continue
        try:
            poh_params[_param_key] = max(0, int(str(_raw).strip()))
        except Exception:
            raise ExecutorError(
                f"genesis_config_error: {_env_key} must be an integer when set"
            )
    _live_partial_raw = os.environ.get("WEALL_POH_LIVE_PARTIAL_PANELS_ENABLED")
    if _live_partial_raw is not None and str(_live_partial_raw).strip() != "":
        _live_partial_text = str(_live_partial_raw).strip().lower()
        if _live_partial_text in {"1", "true", "yes", "y", "on"}:
            poh_params["live_partial_panels_enabled"] = True
        elif _live_partial_text in {"0", "false", "no", "n", "off"}:
            poh_params["live_partial_panels_enabled"] = False
        else:
            raise ExecutorError(
                "genesis_config_error: WEALL_POH_LIVE_PARTIAL_PANELS_ENABLED must be boolean-like when set"
            )

    if poh_params:
        params["poh"] = poh_params

    return {
        "chain_id": self.chain_id,
        "created_ms": GENESIS_CREATED_MS,
        "time": 0,
        "meta": {
            "protocol_version": PROTOCOL_VERSION,
            "production_consensus_profile": PRODUCTION_CONSENSUS_PROFILE.to_json(),
            "production_consensus_profile_hash": PRODUCTION_CONSENSUS_PROFILE.profile_hash(),
            "mempool_selection_policy": _normalize_mempool_selection_policy(
                os.environ.get("WEALL_MEMPOOL_SELECTION_POLICY") or "canonical"
            ),
            "helper_execution_profile": self._requested_helper_execution_profile(),
            "helper_execution_profile_hash": _helper_execution_profile_hash(
                self._requested_helper_execution_profile()
            ),
            "reputation_scale": REPUTATION_SCALE,
            "max_block_future_drift_ms": MAX_BLOCK_FUTURE_DRIFT_MS,
            "clock_skew_warn_ms": CLOCK_SKEW_WARN_MS,
            "genesis_bootstrap_profile": genesis_bootstrap_profile,
            "genesis_bootstrap_profile_hash": _genesis_bootstrap_profile_hash(
                genesis_bootstrap_profile
            ),
        },
        "accounts": {},
        "roles": {},
        "params": params,
        "poh": {},
        "last_block_ts_ms": 0,
        "height": 0,
        "tip": "",
        "tip_hash": "",
        "tip_ts_ms": 0,
        "blocks": {},
        "finalized": {"height": 0, "block_id": ""},
    }

def _mk_key_id(pubkey: str) -> str:
    """Stable deterministic key id for accounts[acct]["keys"]["by_id"]."""
    _bind_executor_globals()
    h = hashlib.sha256(str(pubkey).encode("utf-8")).hexdigest()
    return f"k:{h[:16]}"

def _apply_genesis_bootstrap_live(self, state: Json) -> None:
    """Genesis bootstrap for the founder/operator account.

    This executes only when the ledger is first created (height == 0).
    It seeds the configured bootstrap account with:
      - a registered main key
      - legacy bootstrap PoH (v2.1 user-facing Tier 2 / Live Verified Human)
      - adequate starting reputation for operator duties
      - an active node-operator role record
      - an enabled storage-operator record
      - validator-role enrollment + active validator set membership
      - consensus validator pubkey registry
      - genesis bootstrap founder allowlist/metadata used by PoH bootstrap authority

    Bootstrap activation modes:
      - Explicit mode: WEALL_GENESIS_BOOTSTRAP_ENABLE=1 plus ACCOUNT/PUBKEY envs
      - Genesis-node mode: WEALL_GENESIS_MODE=1 derives account/pubkey from the
        normal validator identity envs so an authorized genesis node can boot
        without a second set of bootstrap-only secrets.

    Safety properties:
      - No implicit "first node" auto-elevation.
      - Bootstrap is still off by default unless explicit bootstrap or genesis mode is enabled.
      - Missing or partial config fails closed.
      - If WEALL_NODE_ID is set and differs from BOOTSTRAP_ACCOUNT, fail-closed.
    """
    _bind_executor_globals()

    try:
        height = int(state.get("height", 0) or 0)
    except Exception:
        height = 0
    if height != 0:
        return

    profile = self._current_genesis_bootstrap_profile()
    explicit_enabled = bool(profile.get("enabled", False)) and str(profile.get("mode") or "") == "explicit"
    genesis_mode_enabled = bool(profile.get("enabled", False)) and str(profile.get("mode") or "") == "genesis_mode"
    if not explicit_enabled and not genesis_mode_enabled:
        return

    acct = str(profile.get("account") or "").strip()
    pk = str(profile.get("pubkey") or "").strip()

    if not acct and not pk:
        raise ExecutorError(
            "genesis_bootstrap_config_error: genesis bootstrap requires an account and pubkey. "
            "Set WEALL_GENESIS_BOOTSTRAP_ACCOUNT/WEALL_GENESIS_BOOTSTRAP_PUBKEY or enable "
            "WEALL_GENESIS_MODE=1 with WEALL_VALIDATOR_ACCOUNT and WEALL_NODE_PUBKEY."
        )

    if not acct or not pk:
        raise ExecutorError(
            "genesis_bootstrap_config_error: both bootstrap account and bootstrap pubkey must be set (or neither)."
        )

    node_id = str(os.environ.get("WEALL_NODE_ID") or self.node_id or "").strip()
    # In genesis-node mode, the local node identity is the bootstrap authority
    # and must match the bootstrap account.  In explicit genesis-bootstrap
    # mode, non-authoritative joining nodes must be able to derive the exact
    # same genesis state from the same bootstrap profile while keeping their
    # own node_id, so do not require WEALL_NODE_ID to equal the bootstrap
    # account there.  Validator authority is still gated below by
    # WEALL_VALIDATOR_ACCOUNT and local signing material.
    if genesis_mode_enabled and node_id and node_id != acct:
        raise ExecutorError(
            "genesis_bootstrap_config_error: WEALL_NODE_ID does not match bootstrap account."
        )

    validator_account = str(os.environ.get("WEALL_VALIDATOR_ACCOUNT") or "").strip()
    if validator_account and validator_account != acct:
        raise ExecutorError(
            "genesis_bootstrap_config_error: WEALL_VALIDATOR_ACCOUNT does not match bootstrap account."
        )

    bootstrap_rep_units = int(profile.get("reputation_milli") or 0)
    if bootstrap_rep_units < 0:
        bootstrap_rep_units = 0

    storage_capacity = int(profile.get("storage_capacity_bytes") or 0)
    if storage_capacity < 0:
        storage_capacity = 0

    accounts = state.get("accounts")
    if not isinstance(accounts, dict):
        accounts = {}
        state["accounts"] = accounts

    a = accounts.get(acct)
    if not isinstance(a, dict):
        a = {
            "nonce": 0,
            "poh_tier": 0,
            "banned": False,
            "locked": False,
            "reputation": "0",
            "reputation_milli": 0,
            "balance": 0,
            "keys": {"by_id": {}},
            "devices": {"by_id": {}},
            "recovery": {"config": None, "proposals": {}},
            "session_keys": {},
        }
        accounts[acct] = a
    sync_account_reputation(a, default_units=0)

    keys = a.get("keys")
    if not isinstance(keys, dict):
        keys = {"by_id": {}}
        a["keys"] = keys
    by_id = keys.get("by_id")
    if not isinstance(by_id, dict):
        by_id = {}
        keys["by_id"] = by_id

    kid = self._mk_key_id(pk)
    rec = by_id.get(kid)
    if not isinstance(rec, dict):
        by_id[kid] = {"pubkey": pk, "key_type": "main", "revoked": False, "revoked_at": None}
    else:
        rec.setdefault("pubkey", pk)
        rec.setdefault("key_type", "main")
        rec.setdefault("revoked", False)
        rec.setdefault("revoked_at", None)

    a["poh_tier"] = 2
    cur_rep_units = account_reputation_units(a, default=0)
    a["reputation_milli"] = max(cur_rep_units, bootstrap_rep_units)
    a["reputation"] = units_to_reputation_text(a["reputation_milli"])
    a["banned"] = False
    a["locked"] = False

    poh_meta = a.get("poh")
    if not isinstance(poh_meta, dict):
        poh_meta = {}
        a["poh"] = poh_meta
    poh_meta.setdefault("live_source", "genesis_bootstrap")
    poh_meta.setdefault("live_reason", "genesis_bootstrap_live")
    poh_meta.setdefault("bootstrap_operator_bundle", True)

    params = state.get("params")
    if not isinstance(params, dict):
        params = {}
        state["params"] = params
    params.setdefault("bootstrap_founder_account", acct)
    allowlist = params.get("bootstrap_allowlist")
    if not isinstance(allowlist, dict):
        allowlist = {}
        params["bootstrap_allowlist"] = allowlist
    allow_rec = allowlist.get(acct)
    if not isinstance(allow_rec, dict):
        allow_rec = {}
        allowlist[acct] = allow_rec
    allow_rec["pubkey"] = pk
    allow_rec.setdefault("source", "genesis_bootstrap")

    roles = ensure_roles_schema(state)
    node_ops = roles.get("node_operators")
    if not isinstance(node_ops, dict):
        node_ops = {"by_id": {}, "active_set": []}
        roles["node_operators"] = node_ops
    by_id_ops = node_ops.get("by_id")
    if not isinstance(by_id_ops, dict):
        by_id_ops = {}
        node_ops["by_id"] = by_id_ops
    rec_op = by_id_ops.get(acct)
    if not isinstance(rec_op, dict):
        rec_op = {}
    rec_op["enrolled"] = True
    rec_op["active"] = True
    rec_op.setdefault("enrolled_at_nonce", 0)
    rec_op.setdefault("activated_at_nonce", 0)
    rec_op.setdefault("source", "genesis_bootstrap")
    by_id_ops[acct] = rec_op
    aset = node_ops.get("active_set")
    if not isinstance(aset, list):
        aset = []
    if acct not in aset:
        aset = sorted({*(str(x) for x in aset if str(x).strip()), acct})
    node_ops["active_set"] = aset

    if _env_bool("WEALL_GENESIS_BOOTSTRAP_JUROR_ENABLE", False):
        jurors_role = roles.get("jurors")
        if not isinstance(jurors_role, dict):
            jurors_role = {"by_id": {}, "active_set": []}
            roles["jurors"] = jurors_role
        jur_by_id = jurors_role.get("by_id")
        if not isinstance(jur_by_id, dict):
            jur_by_id = {}
            jurors_role["by_id"] = jur_by_id
        jur_rec = jur_by_id.get(acct)
        if not isinstance(jur_rec, dict):
            jur_rec = {}
        jur_rec["enrolled"] = True
        jur_rec["active"] = True
        jur_rec.setdefault("enrolled_at_nonce", 0)
        jur_rec.setdefault("activated_at_nonce", 0)
        jur_rec.setdefault("source", "genesis_bootstrap")
        jur_by_id[acct] = jur_rec
        jur_active = jurors_role.get("active_set")
        if not isinstance(jur_active, list):
            jur_active = []
        if acct not in jur_active:
            jur_active = sorted({*(str(x) for x in jur_active if str(x).strip()), acct})
        jurors_role["active_set"] = jur_active

    validators_role = roles.get("validators")
    if not isinstance(validators_role, dict):
        validators_role = {}
        roles["validators"] = validators_role
    active_validators = validators_role.get("active_set")
    if not isinstance(active_validators, list):
        active_validators = []
    if acct not in active_validators:
        active_validators = sorted({*(str(x) for x in active_validators if str(x).strip()), acct})
    validators_role["active_set"] = active_validators

    consensus = state.get("consensus")
    if not isinstance(consensus, dict):
        consensus = {}
        state["consensus"] = consensus
    consensus_validators = consensus.get("validators")
    if not isinstance(consensus_validators, dict):
        consensus_validators = {}
        consensus["validators"] = consensus_validators
    registry = consensus_validators.get("registry")
    if not isinstance(registry, dict):
        registry = {}
        consensus_validators["registry"] = registry
    reg = registry.get(acct)
    if not isinstance(reg, dict):
        reg = {}
        registry[acct] = reg
    reg["account_id"] = acct
    reg["pubkey"] = pk
    reg["status"] = str(reg.get("status") or "active")
    reg.setdefault("source", "genesis_bootstrap")

    validators_root = state.get("validators")
    if not isinstance(validators_root, dict):
        validators_root = {}
        state["validators"] = validators_root
    validators_registry = validators_root.get("registry")
    if not isinstance(validators_registry, dict):
        validators_registry = {}
        validators_root["registry"] = validators_registry
    vroot = validators_registry.get(acct)
    if not isinstance(vroot, dict):
        vroot = {}
        validators_registry[acct] = vroot
    vroot["account_id"] = acct
    vroot["pubkey"] = pk
    vroot["status"] = str(vroot.get("status") or "active")
    vroot.setdefault("source", "genesis_bootstrap")

    storage = state.get("storage")
    if not isinstance(storage, dict):
        storage = {}
        state["storage"] = storage
    if not isinstance(storage.get("operators"), dict):
        storage["operators"] = {}
    op_rec_any = storage["operators"].get(acct)
    op_rec = op_rec_any if isinstance(op_rec_any, dict) else {"account_id": acct}
    op_rec["enabled"] = True
    op_rec.setdefault("used_bytes", 0)
    op_rec["capacity_bytes"] = max(
        int(op_rec.get("capacity_bytes") or 0), int(storage_capacity)
    )
    op_rec.setdefault("updated_at_nonce", 0)
    op_rec.setdefault("source", "genesis_bootstrap")
    storage["operators"][acct] = op_rec

    record_bootstrap_tier2_grant(
        state,
        account_id=acct,
        signer=acct,
        mode=str(profile.get("mode") or "genesis_bootstrap"),
        source="genesis_state",
        height=0,
        tx_type="GENESIS_BOOTSTRAP_TIER2_GRANT",
        nonce=0,
        authority_path="genesis_bootstrap_profile",
        reason_code="genesis_bootstrap_live",
        expires_height=None,
        pubkey=pk,
    )

