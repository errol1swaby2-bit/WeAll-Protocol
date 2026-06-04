from __future__ import annotations

"""BFT runtime helpers extracted from bft_runtime_adapter (bft_artifact_cache.py)."""

from weall.runtime.bft_executor_symbols import bind_executor_globals


def _bind_executor_globals() -> None:
    bind_executor_globals(globals())

def _ensure_recent_bft_artifact_caches(self) -> None:
    _bind_executor_globals()
    if not hasattr(self, "_max_recent_bft_proposals"):
        self._max_recent_bft_proposals = max(
            1, _safe_int(os.environ.get("WEALL_BFT_RECENT_PROPOSALS"), 2048)
        )
    if not hasattr(self, "_recent_bft_proposals") or not isinstance(
        self._recent_bft_proposals, OrderedDict
    ):
        self._recent_bft_proposals = OrderedDict()
    if not hasattr(self, "_max_recent_bft_qcs"):
        self._max_recent_bft_qcs = max(
            1, _safe_int(os.environ.get("WEALL_BFT_RECENT_QCS"), 2048)
        )
    if not hasattr(self, "_recent_bft_qcs") or not isinstance(
        self._recent_bft_qcs, OrderedDict
    ):
        self._recent_bft_qcs = OrderedDict()
    if not hasattr(self, "_max_recent_bft_votes"):
        self._max_recent_bft_votes = max(
            1, _safe_int(os.environ.get("WEALL_BFT_RECENT_VOTES"), 4096)
        )
    if not hasattr(self, "_recent_bft_votes") or not isinstance(
        self._recent_bft_votes, OrderedDict
    ):
        self._recent_bft_votes = OrderedDict()
    if not hasattr(self, "_max_recent_bft_timeouts"):
        self._max_recent_bft_timeouts = max(
            1, _safe_int(os.environ.get("WEALL_BFT_RECENT_TIMEOUTS"), 4096)
        )
    if not hasattr(self, "_recent_bft_timeouts") or not isinstance(
        self._recent_bft_timeouts, OrderedDict
    ):
        self._recent_bft_timeouts = OrderedDict()
    if not hasattr(self, "_max_recent_bft_sender_budgets"):
        self._max_recent_bft_sender_budgets = max(
            1, _safe_int(os.environ.get("WEALL_BFT_RECENT_SENDERS"), 4096)
        )
    if not hasattr(self, "_bft_sender_budget_window_ms"):
        self._bft_sender_budget_window_ms = max(
            1, _safe_int(os.environ.get("WEALL_BFT_SENDER_WINDOW_MS"), 1000)
        )
    if not hasattr(self, "_bft_sender_budget_per_window"):
        self._bft_sender_budget_per_window = max(
            1, _safe_int(os.environ.get("WEALL_BFT_SENDER_BUDGET"), 64)
        )
    if not hasattr(self, "_recent_bft_sender_budgets") or not isinstance(
        self._recent_bft_sender_budgets, OrderedDict
    ):
        self._recent_bft_sender_budgets = OrderedDict()

def _bft_sender_budget_key(self, artifact: Json) -> str:
    _bind_executor_globals()
    self._ensure_recent_bft_artifact_caches()
    if not isinstance(artifact, dict):
        return ""
    raw_sender = str(
        artifact.get("proposer")
        or artifact.get("signer")
        or artifact.get("sender")
        or artifact.get("from")
        or ""
    ).strip()
    if raw_sender:
        return raw_sender
    votes_any = artifact.get("votes")
    if isinstance(votes_any, list):
        senders: list[str] = []
        for item in votes_any:
            if not isinstance(item, dict):
                continue
            signer = str(
                item.get("signer") or item.get("sender") or item.get("from") or ""
            ).strip()
            if signer:
                senders.append(signer)
        if senders:
            senders.sort()
            return senders[0]
    return ""

def _consume_bft_sender_budget(self, artifact: Json) -> bool:
    _bind_executor_globals()
    self._ensure_recent_bft_artifact_caches()
    sender = self._bft_sender_budget_key(artifact)
    if not sender:
        return True
    now = _now_ms()
    try:
        window_start, used = self._recent_bft_sender_budgets.get(sender, (0, 0))
        if not isinstance(window_start, int):
            window_start = _safe_int(window_start, 0)
        if not isinstance(used, int):
            used = _safe_int(used, 0)
    except Exception:
        window_start, used = (0, 0)
    if (now - int(window_start)) >= int(self._bft_sender_budget_window_ms):
        window_start = now
        used = 0
    if int(used) >= int(self._bft_sender_budget_per_window):
        _bounded_put(
            self._recent_bft_sender_budgets,
            sender,
            (int(window_start), int(used)),
            cap=int(self._max_recent_bft_sender_budgets),
        )
        return False
    _bounded_put(
        self._recent_bft_sender_budgets,
        sender,
        (int(window_start), int(used) + 1),
        cap=int(self._max_recent_bft_sender_budgets),
    )
    return True

def _remember_recent_bft_proposal(self, proposal: Json) -> bool:
    _bind_executor_globals()
    self._ensure_recent_bft_artifact_caches()
    try:
        key = hashlib.sha256(_canon_json(dict(proposal)).encode("utf-8")).hexdigest()
    except Exception:
        return False
    if not key:
        return False
    if key in self._recent_bft_proposals:
        return True
    _bounded_put(
        self._recent_bft_proposals,
        key,
        _now_ms(),
        cap=int(self._max_recent_bft_proposals),
    )
    return False

def _recent_bft_qc_key(self, qcj: Json) -> str:
    _bind_executor_globals()
    self._ensure_recent_bft_artifact_caches()
    try:
        return hashlib.sha256(_canon_json(dict(qcj)).encode("utf-8")).hexdigest()
    except Exception:
        return ""

def _has_recent_bft_qc(self, qcj: Json) -> bool:
    _bind_executor_globals()
    key = self._recent_bft_qc_key(qcj)
    if not key:
        return False
    return key in self._recent_bft_qcs

def _record_recent_bft_qc(self, qcj: Json) -> None:
    _bind_executor_globals()
    key = self._recent_bft_qc_key(qcj)
    if not key:
        return
    _bounded_put(self._recent_bft_qcs, key, _now_ms(), cap=int(self._max_recent_bft_qcs))

def _remember_recent_bft_qc(self, qcj: Json) -> bool:
    _bind_executor_globals()
    if self._has_recent_bft_qc(qcj):
        return True
    self._record_recent_bft_qc(qcj)
    return False

def _remember_recent_bft_vote(self, votej: Json) -> bool:
    _bind_executor_globals()
    self._ensure_recent_bft_artifact_caches()
    try:
        key = hashlib.sha256(_canon_json(dict(votej)).encode("utf-8")).hexdigest()
    except Exception:
        return False
    if not key:
        return False
    if key in self._recent_bft_votes:
        return True
    _bounded_put(
        self._recent_bft_votes,
        key,
        _now_ms(),
        cap=int(self._max_recent_bft_votes),
    )
    return False

def _remember_recent_bft_timeout(self, timeoutj: Json) -> bool:
    _bind_executor_globals()
    self._ensure_recent_bft_artifact_caches()
    try:
        key = hashlib.sha256(_canon_json(dict(timeoutj)).encode("utf-8")).hexdigest()
    except Exception:
        return False
    if not key:
        return False
    if key in self._recent_bft_timeouts:
        return True
    _bounded_put(
        self._recent_bft_timeouts,
        key,
        _now_ms(),
        cap=int(self._max_recent_bft_timeouts),
    )
    return False

def _bft_artifact_shape_fast_fail(self, kind: str, payload: Json) -> bool:
    _bind_executor_globals()
    if not isinstance(payload, dict):
        return False

    max_field_chars = max(8, _safe_int(os.environ.get("WEALL_BFT_MAX_FIELD_CHARS"), 512))
    max_qc_votes = max(1, _safe_int(os.environ.get("WEALL_BFT_MAX_QC_VOTES_PER_ARTIFACT"), 512))

    def _str_field(name: str, *, required: bool = False, allow_empty: bool = False) -> bool:
        if name not in payload:
            return not required
        val = payload.get(name)
        if not isinstance(val, str):
            return False
        sval = val.strip()
        if not allow_empty and required and not sval:
            return False
        return len(sval) <= max_field_chars

    def _int_field(name: str, *, required: bool = False, minimum: int = 0) -> bool:
        if name not in payload:
            return not required
        val = payload.get(name)
        try:
            ival = int(val)
        except Exception:
            return False
        return ival >= minimum

    if not _str_field("chain_id", required=True):
        return False
    if str(payload.get("chain_id") or "").strip() != str(self.chain_id):
        return False

    if kind == "proposal":
        if not _str_field("block_id", required=True):
            return False
        if not _str_field("block_hash", required=True):
            return False
        if not _str_field("prev_block_id", required=False, allow_empty=True):
            return False
        if not _str_field("proposer", required=False):
            return False
        if not _int_field("view", required=True):
            return False
        if not _int_field("height", required=True):
            return False
        justify_qc = payload.get("justify_qc")
        if justify_qc is not None and not isinstance(justify_qc, dict):
            return False
        return True

    if kind == "qc":
        if not _str_field("block_id", required=True):
            return False
        if not _str_field("block_hash", required=True):
            return False
        if not _str_field("parent_id", required=False, allow_empty=True):
            return False
        if not _int_field("view", required=True):
            return False
        votes = payload.get("votes")
        if votes is not None:
            if not isinstance(votes, list):
                return False
            if len(votes) > max_qc_votes:
                return False
        return True

    if kind == "vote":
        if str(payload.get("t") or "") != "VOTE":
            return False
        for field in ("block_id", "block_hash", "signer", "pubkey", "sig"):
            if not _str_field(field, required=True):
                return False
        if not _str_field("parent_id", required=False, allow_empty=True):
            return False
        if not _int_field("view", required=True):
            return False
        if not _int_field("validator_epoch", required=False):
            return False
        return True

    if kind == "timeout":
        if str(payload.get("t") or "") != "TIMEOUT":
            return False
        for field in ("high_qc_id", "signer", "pubkey", "sig"):
            if not _str_field(field, required=True):
                return False
        if not _int_field("view", required=True):
            return False
        if not _int_field("validator_epoch", required=False):
            return False
        return True

    return False

