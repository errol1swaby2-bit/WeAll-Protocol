from __future__ import annotations

from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, found {count}")
    return text.replace(old, new, 1)


root = Path(__file__).resolve().parents[1] / "Weall-Protocol"

hotstuff = root / "src/weall/runtime/bft_hotstuff.py"
text = hotstuff.read_text(encoding="utf-8")
text = replace_once(
    text,
    "        self.high_qc: QuorumCert | None = None\n        self.locked_qc: QuorumCert | None = None\n",
    "        self.high_qc: QuorumCert | None = None\n        self.locked_qc: QuorumCert | None = None\n        # Generation-local certificate proving that the current validator set\n        # threshold-certified the canonical transition boundary. Unlike high_qc,\n        # this must remain available after later QCs advance the HotStuff head.\n        self.validator_transition_qc: QuorumCert | None = None\n",
    "hotstuff init transition qc",
)
text = replace_once(
    text,
    "        self.high_qc = None\n        self.locked_qc = None\n        self.finalized_block_id = str(finalized_block_id or \"\").strip()\n",
    "        self.high_qc = None\n        self.locked_qc = None\n        self.validator_transition_qc = None\n        self.finalized_block_id = str(finalized_block_id or \"\").strip()\n",
    "hotstuff generation reset transition qc",
)
text = replace_once(
    text,
    "        lqc = b.get(\"locked_qc\")\n        if isinstance(lqc, dict):\n            q = qc_from_json(lqc)\n            if q is not None:\n                self.locked_qc = q\n\n        self.finalized_block_id = _as_str(b.get(\"finalized_block_id\") or self.finalized_block_id)\n",
    "        lqc = b.get(\"locked_qc\")\n        if isinstance(lqc, dict):\n            q = qc_from_json(lqc)\n            if q is not None:\n                self.locked_qc = q\n\n        transition_qc = b.get(\"validator_transition_qc\")\n        if isinstance(transition_qc, dict):\n            q = qc_from_json(transition_qc)\n            if q is not None:\n                self.validator_transition_qc = q\n\n        self.finalized_block_id = _as_str(b.get(\"finalized_block_id\") or self.finalized_block_id)\n",
    "hotstuff load transition qc",
)
text = replace_once(
    text,
    "        if self.locked_qc is not None:\n            out[\"locked_qc\"] = self.locked_qc.to_json()\n        if self.last_timeout_certificate is not None and self._last_timeout_certificate_verified:\n",
    "        if self.locked_qc is not None:\n            out[\"locked_qc\"] = self.locked_qc.to_json()\n        if self.validator_transition_qc is not None:\n            out[\"validator_transition_qc\"] = self.validator_transition_qc.to_json()\n        if self.last_timeout_certificate is not None and self._last_timeout_certificate_verified:\n",
    "hotstuff export transition qc",
)
hotstuff.write_text(text, encoding="utf-8")

adapter = root / "src/weall/runtime/bft_runtime_adapter.py"
text = adapter.read_text(encoding="utf-8")
old_has = '''def _bft_transition_bridge_has_qc(self, descriptor: Json | None = None) -> bool:
    desc = descriptor if isinstance(descriptor, dict) else _bft_transition_bridge_descriptor(self)
    if not isinstance(desc, dict):
        return False
    qc = getattr(self._bft, "high_qc", None)
    if qc is None:
        return False
    if str(getattr(qc, "block_id", "") or "").strip() != str(desc.get("block_id") or ""):
        return False
    if str(getattr(qc, "block_hash", "") or "").strip() != str(desc.get("block_hash") or ""):
        return False
    if int(getattr(qc, "validator_epoch", 0) or 0) != int(self._current_validator_epoch()):
        return False
    if (
        str(getattr(qc, "validator_set_hash", "") or "").strip()
        != str(self._current_validator_set_hash() or "").strip()
    ):
        return False
    return self.bft_verify_qc_json(qc.to_json()) is not None
'''
new_has = '''def _bft_transition_bridge_has_qc(self, descriptor: Json | None = None) -> bool:
    desc = descriptor if isinstance(descriptor, dict) else _bft_transition_bridge_descriptor(self)
    if not isinstance(desc, dict):
        return False
    current_epoch = int(self._current_validator_epoch())
    current_set_hash = str(self._current_validator_set_hash() or "").strip()
    candidates = (
        getattr(self._bft, "validator_transition_qc", None),
        getattr(self._bft, "high_qc", None),
    )
    for qc in candidates:
        if qc is None:
            continue
        if str(getattr(qc, "block_id", "") or "").strip() != str(desc.get("block_id") or ""):
            continue
        if str(getattr(qc, "block_hash", "") or "").strip() != str(desc.get("block_hash") or ""):
            continue
        if int(getattr(qc, "view", -1)) != int(desc.get("view") or 0):
            continue
        if int(getattr(qc, "validator_epoch", 0) or 0) != current_epoch:
            continue
        if str(getattr(qc, "validator_set_hash", "") or "").strip() != current_set_hash:
            continue
        if self.bft_verify_qc_json(qc.to_json()) is not None:
            return True
    return False
'''
text = replace_once(text, old_has, new_has, "adapter transition qc gate")

old_remote = '''def bft_handle_qc(self, qcj: Json) -> bool:
    qc = self.bft_verify_qc_json(qcj)
    if qc is None:
        return False
    blocks_map = self._bft_speculative_blocks_map()
'''
new_remote = '''def bft_handle_qc(self, qcj: Json) -> bool:
    qc = self.bft_verify_qc_json(qcj)
    if qc is None:
        return False
    transition = _bft_transition_bridge_descriptor(self)
    if (
        isinstance(transition, dict)
        and str(qc.block_id) == str(transition.get("block_id") or "")
        and str(qc.block_hash) == str(transition.get("block_hash") or "")
        and int(qc.view) == int(transition.get("view") or 0)
        and int(qc.validator_epoch) == int(self._current_validator_epoch())
        and str(qc.validator_set_hash) == str(self._current_validator_set_hash() or "")
    ):
        self._bft.validator_transition_qc = qc
    blocks_map = self._bft_speculative_blocks_map()
'''
text = replace_once(text, old_remote, new_remote, "adapter remote transition qc retention")

old_local = '''    blocks_map = self._bft_speculative_blocks_map()
    prev_finalized = str(self._bft.finalized_block_id or "").strip()
    self._bft.observe_qc(blocks=blocks_map, qc=qc)
    self._put_pending_missing_qc(qc.to_json())
'''
new_local = '''    transition = _bft_transition_bridge_descriptor(self)
    if (
        isinstance(transition, dict)
        and str(qc.block_id) == str(transition.get("block_id") or "")
        and str(qc.block_hash) == str(transition.get("block_hash") or "")
        and int(qc.view) == int(transition.get("view") or 0)
        and int(qc.validator_epoch) == int(self._current_validator_epoch())
        and str(qc.validator_set_hash) == str(self._current_validator_set_hash() or "")
    ):
        self._bft.validator_transition_qc = qc
    blocks_map = self._bft_speculative_blocks_map()
    prev_finalized = str(self._bft.finalized_block_id or "").strip()
    self._bft.observe_qc(blocks=blocks_map, qc=qc)
    self._put_pending_missing_qc(qc.to_json())
'''
first = text.find(old_local)
if first < 0:
    raise SystemExit("adapter local transition qc retention: no post-QC sequence")
second = text.find(old_local, first + len(old_local))
if second < 0:
    raise SystemExit("adapter local transition qc retention: second post-QC sequence missing")
text = text[:second] + new_local + text[second + len(old_local) :]

old_qcless = '''    elif _mode() == "prod":
        state = getattr(self, "state", None)
        phase_reader = getattr(self, "_current_consensus_phase", None)
        current_phase = phase_reader() if callable(phase_reader) else ""
        if isinstance(state, dict) and current_phase == CONSENSUS_PHASE_BFT_ACTIVE:
            height = _safe_int(state.get("height"), 0)
            tip = str(state.get("tip") or "").strip()
            if height > 0 or tip:
                return None
'''
new_qcless = '''    elif _mode() == "prod":
        state = getattr(self, "state", None)
        phase_reader = getattr(self, "_current_consensus_phase", None)
        current_phase = phase_reader() if callable(phase_reader) else ""
        if isinstance(state, dict) and current_phase == CONSENSUS_PHASE_BFT_ACTIVE:
            # The production profile requires every BFT-active proposal to carry
            # a verified justify QC. Bootstrap must cross an authenticated
            # transition boundary first; height zero is not a QC-less exception.
            return None
'''
text = replace_once(text, old_qcless, new_qcless, "adapter production qcless removal")

old_vote_map = '''    blocks_map = self.state.get("blocks")
    if not isinstance(blocks_map, dict):
        blocks_map = {}
    else:
        blocks_map = dict(blocks_map)
    blocks_map[bid] = {
'''
new_vote_map = '''    # Vote safety must reason over the certified speculative branch, not only
    # the committed canonical prefix. Otherwise an honest follower cannot vote
    # for B2 while its certified parent B1 is still pending/uncommitted.
    blocks_map = self._bft_speculative_blocks_map()
    if not isinstance(blocks_map, dict):
        blocks_map = {}
    else:
        blocks_map = dict(blocks_map)
    blocks_map[bid] = {
'''
text = replace_once(text, old_vote_map, new_vote_map, "adapter follower speculative vote ancestry")
adapter.write_text(text, encoding="utf-8")

votecheck = root / "src/weall/runtime/bft_votecheck.py"
text = votecheck.read_text(encoding="utf-8")
old_missing_parent = '''    parent_id = str(block2.get("prev_block_id") or "").strip()
    if parent_id and not self._has_local_block(parent_id):
        if parent_id in self._pending_missing_fetches:
            # Missing-parent work is retryable local state, not intrinsic block invalidity.
            return False
'''
new_missing_parent = '''    parent_id = str(block2.get("prev_block_id") or "").strip()
    if parent_id and not self._has_local_block(parent_id):
        # A speculative parent is valid local ancestry even though it is not yet
        # in the canonical block table. If neither canonical nor pending ancestry
        # exists, fail retryably and let the fetch-descriptor machinery request it.
        pending_parent = self._bft_pending_block_json(parent_id)
        if not isinstance(pending_parent, dict):
            return False
'''
text = replace_once(
    text,
    old_missing_parent,
    new_missing_parent,
    "votecheck nonexistent pending fetch state",
)
votecheck.write_text(text, encoding="utf-8")

priority2 = root / "tests/test_priority2_votecheck_dos_hardening.py"
text = priority2.read_text(encoding="utf-8")
text = replace_once(
    text,
    '''    if not hasattr(ex, "_pending_missing_fetches"):
        ex._pending_missing_fetches = {}  # type: ignore[attr-defined]
    return ex
''',
    '''    return ex
''',
    "remove votecheck fake pending-fetch fixture",
)
priority2.write_text(text, encoding="utf-8")

fresh = root / "tests/test_fresh_ai_error_closure.py"
text = fresh.read_text(encoding="utf-8")
text = replace_once(
    text,
    '''    parent_id = str(block2.get("block_id") or "")
    if not hasattr(follower, "_pending_missing_fetches"):
        follower._pending_missing_fetches = {}  # type: ignore[attr-defined]
    follower._pending_missing_fetches[parent_id] = {"requested_ms": 1}
    assert follower._validate_remote_proposal_for_vote(block3) is False

    follower._pending_missing_fetches.pop(parent_id, None)
    assert follower.apply_block(block2).ok is True
''',
    '''    # Missing-parent work is retryable and derived from the real canonical/
    # pending frontier; no synthetic runtime attribute is required.
    assert follower._validate_remote_proposal_for_vote(block3) is False

    assert follower.apply_block(block2).ok is True
''',
    "remove votecheck fake missing-parent state",
)
fresh.write_text(text, encoding="utf-8")
