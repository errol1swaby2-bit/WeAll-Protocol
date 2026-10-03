from __future__ import annotations

from pathlib import Path


def index_after(lines: list[str], start: int, exact: str) -> int:
    for i in range(start, len(lines)):
        if lines[i] == exact:
            return i
    raise SystemExit(f"missing anchor after line {start + 1}: {exact!r}")


def index_before(lines: list[str], start: int, stop: int, exact: str) -> int:
    for i in range(start, stop, -1):
        if lines[i] == exact:
            return i
    raise SystemExit(f"missing reverse anchor before line {start + 1}: {exact!r}")


def replace_function_body(
    path: Path,
    *,
    function_line: str,
    next_function_line: str,
    body: list[str],
) -> None:
    lines = path.read_text(encoding="utf-8").splitlines()
    start = index_after(lines, 0, function_line)
    end = index_after(lines, start + 1, next_function_line)
    lines[start + 1 : end] = body + [""]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


root = Path(__file__).resolve().parents[1] / "Weall-Protocol"

# Preserve the existing commit-admission contract for a block that is a strict
# ancestor of the finalized head. Competing siblings/off-branch blocks still
# flow through proposal admission and retain the existing bft_conflict result.
admission = root / "src/weall/runtime/block_admission.py"
lines = admission.read_text(encoding="utf-8").splitlines()
fn = index_after(lines, 0, "def admit_bft_commit_block(")
old_start = index_after(lines, fn, "    ok, rej = admit_bft_block(")
old_end = index_after(lines, old_start, "    if not effective_bft_enabled:")
replacement = [
    "    effective_bft_enabled = (",
    '        _env_bool("WEALL_BFT_ENABLED", False) if bft_enabled is None else bool(bft_enabled)',
    "    )",
    "    effective_blocks = blocks_map if isinstance(blocks_map, dict) else {}",
    "    if not effective_blocks:",
    '        raw_blocks = state.get("blocks")',
    "        effective_blocks = raw_blocks if isinstance(raw_blocks, dict) else {}",
    "",
    "    if effective_bft_enabled:",
    '        bft_state = state.get("bft")',
    "        finalized = (",
    '            _as_str(bft_state.get("finalized_block_id") or "")',
    "            if isinstance(bft_state, dict)",
    '            else ""',
    "        )",
    '        bid = _as_str(block.get("block_id") or "")',
    "        if (",
    "            bid",
    "            and finalized",
    "            and bid != finalized",
    "            and _is_descendant(effective_blocks, candidate=finalized, ancestor=bid)",
    "        ):",
    "            return False, BlockReject(",
    '                "bft_not_finalized",',
    '                "block_not_on_finalized_path",',
    '                {"block_id": bid, "finalized_block_id": finalized},',
    "            )",
    "",
    "    ok, rej = admit_bft_block(",
    "        block=block,",
    "        state=state,",
    "        blocks_map=blocks_map,",
    "        bft_enabled=bft_enabled,",
    "    )",
    "    if not ok:",
    "        return ok, rej",
    "",
]
lines[old_start:old_end] = replacement
admission.write_text("\n".join(lines) + "\n", encoding="utf-8")

# The resilience matrix seeds validator state after executor construction. Give
# only that synthetic harness an explicit in-memory signer posture. Production
# runtime onboarding/authority code remains unchanged.
fault = root / "src/weall/runtime/fault_injection.py"
lines = fault.read_text(encoding="utf-8").splitlines()
helper = index_after(
    lines,
    0,
    "    def _mk_executor(db_path: Path, node_id: str, chain_id: str) -> WeAllExecutor:",
)
seed = index_after(
    lines,
    helper,
    "        _seed_validator_set_full(ex, validators=validators, pub=vpub, epoch=7)",
)
view = index_after(lines, seed, "        ex.bft_set_view(1)")
ret = index_after(lines, view, "        return ex")
lines[view : ret + 1] = [
    "        with _validator_env(node_id):",
    '            if not bool(getattr(ex, "_bft_restart_safety_ok", True)):',
    '                raise RuntimeError("synthetic validator failed restart safety revalidation")',
    "            ex._validator_signing_enabled = True",
    "            ex._observer_mode_forced = False",
    '            ex._signing_block_reason = ""',
    "            if not ex._validator_signing_permitted():",
    '                raise RuntimeError("synthetic validator signing posture unavailable")',
    "            ex.bft_set_view(1)",
    "        return ex",
]

# This scenario tests forged/non-leader rejection, not the production transition
# QC bootstrap contract. Pin it to explicit testnet/QC-less semantics so its CLI
# behavior is independent of ambient pytest environment variables.
conflict = index_after(lines, helper, '    conflict_chain_id = f"{chain_id_prefix}-conflict-reject"')
leader_start = index_after(lines, conflict, "    leader = WeAllExecutor(")
leader_view = index_after(lines, leader_start, "    leader.bft_set_view(1)")
lines[leader_start : leader_view + 1] = [
    "    leader = _mk_executor(",
    '        conflict_dir / f"{canonical_leader}.db", canonical_leader, conflict_chain_id',
    "    )",
    "    follower = _mk_executor(",
    '        conflict_dir / f"{follower_id}.db", follower_id, conflict_chain_id',
    "    )",
]

valid_line = index_after(lines, conflict, "        valid_proposal = leader.bft_leader_propose(max_txs=0)")
with_start = index_before(lines, valid_line - 1, conflict, "    with _EnvPatch(")
lines[with_start : valid_line + 1] = [
    "    with _EnvPatch(",
    "        {",
    '            "WEALL_MODE": "testnet",',
    '            "WEALL_BFT_ENABLED": "1",',
    '            "WEALL_BFT_ALLOW_QC_LESS_BLOCKS": "1",',
    '            "WEALL_AUTOVOTE": "1",',
    '            "WEALL_SIGVERIFY": "1",',
    '            "WEALL_VALIDATOR_ACCOUNT": canonical_leader,',
    '            "WEALL_NODE_PUBKEY": str(vpub[canonical_leader]),',
    '            "WEALL_NODE_PRIVKEY": str(vpriv[canonical_leader]),',
    "        }",
    "    ):",
    "        valid_proposal = leader.bft_leader_propose(max_txs=0)",
]

accepted = index_after(lines, conflict, "    accepted_vote = follower.bft_on_proposal(dict(valid_proposal))")
lines[accepted : accepted + 1] = [
    "    with _EnvPatch(",
    "        {",
    '            "WEALL_MODE": "testnet",',
    '            "WEALL_BFT_ENABLED": "1",',
    '            "WEALL_BFT_ALLOW_QC_LESS_BLOCKS": "1",',
    '            "WEALL_AUTOVOTE": "1",',
    '            "WEALL_VALIDATOR_ACCOUNT": follower_id,',
    '            "WEALL_NODE_PUBKEY": str(vpub[follower_id]),',
    '            "WEALL_NODE_PRIVKEY": str(vpriv[follower_id]),',
    "        }",
    "    ):",
    "        accepted_vote = follower.bft_on_proposal(dict(valid_proposal))",
]

rejected = index_after(lines, conflict, "    rejected_vote = follower.bft_on_proposal(dict(forged))")
lines[rejected : rejected + 1] = [
    "    with _EnvPatch(",
    "        {",
    '            "WEALL_MODE": "testnet",',
    '            "WEALL_BFT_ENABLED": "1",',
    '            "WEALL_BFT_ALLOW_QC_LESS_BLOCKS": "1",',
    '            "WEALL_AUTOVOTE": "1",',
    '            "WEALL_VALIDATOR_ACCOUNT": follower_id,',
    '            "WEALL_NODE_PUBKEY": str(vpub[follower_id]),',
    '            "WEALL_NODE_PRIVKEY": str(vpriv[follower_id]),',
    "        }",
    "    ):",
    "        rejected_vote = follower.bft_on_proposal(dict(forged))",
]
fault.write_text("\n".join(lines) + "\n", encoding="utf-8")

# Strict production epoch-binding tests must not depend on the intentionally
# forbidden production QC-less first-proposal path. Exercise the proposal epoch
# predicate directly and construct the QC from signed votes over a fixed identity.
strict = root / "tests/test_bft_strict_epoch_binding.py"
lines = strict.read_text(encoding="utf-8").splitlines()
proposal_fn = index_after(lines, 0, "def test_prod_rejects_proposal_missing_epoch_binding(")
proposal_next = index_after(lines, proposal_fn + 1, "def test_prod_rejects_vote_missing_epoch_binding(")
proposal_sig = lines[proposal_fn + 1 : proposal_fn + 3]
proposal_body = proposal_sig + [
    "    ex, _pubs, _privs = _mk_executor(tmp_path, monkeypatch)",
    "    proposal_binding = {",
    '        "validator_epoch": ex._current_validator_epoch(),',
    '        "validator_set_hash": ex._current_validator_set_hash(),',
    "    }",
    "    assert ex._bft_epoch_binding_matches(proposal_binding) is True",
    "",
    "    missing_epoch = dict(proposal_binding)",
    '    missing_epoch.pop("validator_epoch", None)',
    "    assert ex._bft_epoch_binding_matches(missing_epoch) is False",
    "",
    "    missing_set_hash = dict(proposal_binding)",
    '    missing_set_hash.pop("validator_set_hash", None)',
    "    assert ex._bft_epoch_binding_matches(missing_set_hash) is False",
]
lines[proposal_fn + 1 : proposal_next] = proposal_body + [""]
strict.write_text("\n".join(lines) + "\n", encoding="utf-8")

# Re-read after the first edit and surgically replace only the obsolete proposal
# construction in the QC test.
lines = strict.read_text(encoding="utf-8").splitlines()
qc_fn = index_after(lines, 0, "def test_prod_rejects_qc_missing_epoch_binding(")
proposal_start = index_after(lines, qc_fn, "    proposal = {")
votes_start = index_after(lines, proposal_start, "    votes = []")
lines[proposal_start:votes_start] = [
    '    bid = "strict-epoch-qc-block"',
    '    block_hash = "strict-epoch-qc-hash"',
    '    parent_id = "strict-epoch-parent"',
    "",
]
for i in range(votes_start, len(lines)):
    if 'block_hash=str(proposal.get("block_hash") or ""),' in lines[i]:
        lines[i] = "            block_hash=block_hash,"
        break
else:
    raise SystemExit("strict QC vote block-hash anchor missing")
strict.write_text("\n".join(lines) + "\n", encoding="utf-8")
