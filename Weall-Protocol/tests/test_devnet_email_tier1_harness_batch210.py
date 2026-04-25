from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from nacl.signing import SigningKey

from weall.poh.operator_email_receipts import validate_operator_email_receipt
from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _tx_index_path() -> str:
    return str(_repo_root() / "generated" / "tx_index.json")


def _script(path: str) -> Path:
    return _repo_root() / path


def test_devnet_email_scripts_are_syntax_valid_and_do_not_call_demo_seed() -> None:
    scripts = [
        "scripts/devnet_boot_genesis_node.sh",
        "scripts/devnet_boot_joining_node.sh",
        "scripts/devnet_request_email_verification.sh",
        "scripts/devnet_submit_email_attestation.sh",
        "scripts/devnet_full_onboarding_e2e.sh",
    ]
    for rel in scripts:
        path = _script(rel)
        subprocess.run(["bash", "-n", str(path)], check=True, timeout=10)
        text = path.read_text(encoding="utf-8")
        assert "/v1/dev/demo-seed" not in text
        assert "demo-seed" not in text


def test_devnet_boot_scripts_do_not_require_run_node_executable_bit() -> None:
    for rel in ("scripts/devnet_boot_genesis_node.sh", "scripts/devnet_boot_joining_node.sh"):
        text = _script(rel).read_text(encoding="utf-8")
        assert "exec bash ./scripts/run_node.sh" in text
        assert "exec ./scripts/run_node.sh" not in text


def test_devnet_tx_email_tier1_cli_help_and_keyfile_cli() -> None:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(_repo_root() / "src")
    for args in (["email-tier1", "--help"], ["ensure-keyfile", "--help"]):
        proc = subprocess.run(
            [sys.executable, str(_script("scripts/devnet_tx.py")), *args],
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
        )
        assert proc.returncode == 0, proc.stderr
        assert args[0] in proc.stdout


def test_devnet_email_receipt_helper_builds_chain_bound_valid_receipt(monkeypatch: pytest.MonkeyPatch) -> None:
    sys.path.insert(0, str(_repo_root() / "scripts"))
    import devnet_tx  # type: ignore

    relay_sk = SigningKey.generate()
    operator_sk = SigningKey.generate()
    subject_sk = SigningKey.generate()
    relay_pub = relay_sk.verify_key.encode().hex()
    operator_pub = operator_sk.verify_key.encode().hex()
    subject_pub = subject_sk.verify_key.encode().hex()

    monkeypatch.setenv("WEALL_EMAIL_RELAY_ACCOUNT_ID", "@relay")
    monkeypatch.setenv("WEALL_EMAIL_RELAY_PUBKEY", relay_pub)

    state = {
        "chain_id": "batch210-chain",
        "height": 0,
        "accounts": {
            "@operator": {
                "poh_tier": 3,
                "reputation": "1.0",
                "reputation_milli": 1000,
                "banned": False,
                "locked": False,
                "keys": {"by_id": {"k:operator": {"pubkey": operator_pub, "revoked": False}}},
            },
            "@subject": {
                "poh_tier": 0,
                "banned": False,
                "locked": False,
                "keys": {"by_id": {"k:subject": {"pubkey": subject_pub, "revoked": False}}},
            },
        },
        "roles": {
            "node_operators": {
                "by_id": {"@operator": {"enrolled": True, "active": True}},
                "active_set": ["@operator"],
            }
        },
        "poh": {},
    }

    relay_token = devnet_tx._make_relay_token(
        chain_id="batch210-chain",
        challenge_id="email:batch210",
        subject_account_id="@subject",
        operator_account_id="@operator",
        email="Errol1Swaby2@GMAIL.com",
        relay_account_id="@relay",
        relay_pubkey=relay_pub,
        relay_privkey=relay_sk.encode().hex(),
        ttl_ms=60_000,
    )
    receipt = devnet_tx._make_operator_email_receipt(
        chain_id="batch210-chain",
        subject_account_id="@subject",
        operator_account_id="@operator",
        operator_pubkey=operator_pub,
        operator_privkey=operator_sk.encode().hex(),
        relay_token=relay_token,
    )
    ok, code, payload = validate_operator_email_receipt(
        state, subject_account_id="@subject", receipt=receipt, chain_id="batch210-chain"
    )
    assert ok, code
    assert payload is not None
    assert payload["chain_id"] == "batch210-chain"
    assert payload["email_commitment"].startswith("sha256:")
    assert "gmail.com" not in json.dumps(receipt).lower()


def test_explicit_genesis_bootstrap_profile_can_be_derived_by_joining_node_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sk = SigningKey.generate()
    pub = sk.verify_key.encode().hex()
    acct = "@devnet-genesis"

    monkeypatch.setenv("WEALL_MODE", "dev")
    monkeypatch.setenv("WEALL_GENESIS_BOOTSTRAP_ENABLE", "1")
    monkeypatch.setenv("WEALL_GENESIS_BOOTSTRAP_ACCOUNT", acct)
    monkeypatch.setenv("WEALL_GENESIS_BOOTSTRAP_PUBKEY", pub)
    monkeypatch.setenv("WEALL_NODE_ID", "@devnet-joiner")
    monkeypatch.delenv("WEALL_GENESIS_MODE", raising=False)
    monkeypatch.delenv("WEALL_VALIDATOR_ACCOUNT", raising=False)
    monkeypatch.delenv("WEALL_NODE_PUBKEY", raising=False)
    monkeypatch.delenv("WEALL_NODE_PRIVKEY", raising=False)

    ex = WeAllExecutor(
        db_path=str(tmp_path / "joiner.db"),
        node_id="@devnet-joiner",
        chain_id="batch210-devnet",
        tx_index_path=_tx_index_path(),
    )
    st = ex.read_state()
    account = st.get("accounts", {}).get(acct)
    assert isinstance(account, dict)
    assert int(account.get("poh_tier") or 0) == 3
    meta = st.get("meta") if isinstance(st.get("meta"), dict) else {}
    profile = meta.get("genesis_bootstrap_profile") if isinstance(meta.get("genesis_bootstrap_profile"), dict) else {}
    assert profile.get("mode") == "explicit"
    assert profile.get("account") == acct


def test_devnet_cross_node_sync_scripts_are_syntax_valid_and_non_demo() -> None:
    scripts = [
        "scripts/devnet_sync_from_peer.sh",
        "scripts/devnet_full_onboarding_e2e.sh",
        "scripts/devnet_boot_joining_node.sh",
    ]
    for rel in scripts:
        path = _script(rel)
        subprocess.run(["bash", "-n", str(path)], check=True, timeout=10)
        text = path.read_text(encoding="utf-8")
        assert "/v1/dev/demo-seed" not in text
        assert "demo-seed" not in text


def test_full_onboarding_smoke_autostarts_and_syncs_joining_node() -> None:
    text = _script("scripts/devnet_full_onboarding_e2e.sh").read_text(encoding="utf-8")
    assert "WEALL_DEVNET_AUTOSTART_NODE2" in text
    assert "devnet_boot_joining_node.sh" in text
    assert "devnet_sync_from_peer.sh" in text
    assert "devnet_compare_state_roots.sh" in text
    assert "WEALL_ENABLE_DEVNET_SYNC_APPLY_ROUTE" in text


def test_state_sync_http_apply_is_explicitly_devnet_gated() -> None:
    text = _script("src/weall/api/routes_public_parts/state.py").read_text(encoding="utf-8")
    assert '@router.post("/sync/request")' in text
    assert '@router.post("/sync/apply")' in text
    assert "WEALL_ENABLE_DEVNET_SYNC_APPLY_ROUTE" in text
    assert "allow_snapshot_bootstrap" in text


def test_http_state_sync_request_header_uses_real_tx_index_hash() -> None:
    text = _script("src/weall/api/routes_public_parts/state.py").read_text(encoding="utf-8")
    assert "def _executor_tx_index_hash" in text
    assert "callable(fn)" in text
    assert 'return str(fn() or "").strip()' in text
    assert 'str(getattr(ex, "tx_index_hash", "") or "")' not in text


def test_full_onboarding_smoke_creates_fresh_account_by_default() -> None:
    script = _script("scripts/devnet_full_onboarding_e2e.sh").read_text(encoding="utf-8")
    helper = _script("scripts/devnet_tx.py").read_text(encoding="utf-8")
    assert "WEALL_DEVNET_FRESH_ACCOUNT" in script
    assert "Creating fresh account" in script
    assert "--fresh" in helper
    assert "--reuse-keyfile" in helper

def test_full_onboarding_smoke_resets_stale_autostart_state_and_asserts_tier1() -> None:
    script = _script("scripts/devnet_full_onboarding_e2e.sh").read_text(encoding="utf-8")
    assert "WEALL_DEVNET_RESET_ON_AUTOSTART" in script
    assert "devnet_reset_state.sh" in script
    assert "Resetting controlled devnet state before auto-start" in script
    assert "Tier-1 email verification did not elevate account" in script
    assert "Verified canonical Tier-1 account state" in script


def test_devnet_sync_replays_delta_from_height_zero_by_default() -> None:
    script = _script("scripts/devnet_sync_from_peer.sh").read_text(encoding="utf-8")
    assert "WEALL_DEVNET_SYNC_BOOTSTRAP_MODE" in script
    assert "WEALL_DEVNET_SYNC_BOOTSTRAP_MODE:-delta" in script
    assert "bootstrap_mode == 'snapshot'" in script
    assert "allow_snapshot_bootstrap" in script
    assert "HTTP ${code}" in script
    assert "curl -fsS -H 'content-type: application/json' --data-binary" not in script


def test_delta_state_sync_ancestry_uses_block_hash_not_block_id() -> None:
    text = _script("src/weall/net/state_sync.py").read_text(encoding="utf-8")
    assert "from weall.runtime.block_hash import compute_block_hash" in text
    assert "def _block_hash_for_sync_chain" in text
    assert "last_bid = _block_hash_for_sync_chain(blk)" in text
    assert 'last_bid = _as_str(blk.get("block_id") or blk.get("block_hash") or "")' not in text


def test_full_onboarding_smoke_checks_cross_node_account_tx_parity_and_node2_submit() -> None:
    script = _script("scripts/devnet_full_onboarding_e2e.sh").read_text(encoding="utf-8")
    assert "_assert_cross_node_account_and_tx_parity" in script
    assert "Verifying node 2 can read the same account and tx statuses" in script
    assert "Submitting Tier-1-gated FOLLOW_SET through node 2 normal tx flow" in script
    assert "devnet_submit_tx_node2.sh" in script
    assert "Syncing node 1 from node 2 after node-2-submitted tx" in script
    assert "node2-submit-convergence" in script
    assert "WEALL_NODE2_BLOCK_LOOP_AUTOSTART:-1" in script
    assert "WEALL_ENABLE_DEVNET_SYNC_APPLY_ROUTE=\"1\"" in script

def test_devnet_boot_scripts_use_per_node_block_loop_locks() -> None:
    genesis = _script("scripts/devnet_boot_genesis_node.sh").read_text(encoding="utf-8")
    joining = _script("scripts/devnet_boot_joining_node.sh").read_text(encoding="utf-8")
    assert 'WEALL_BLOCK_LOOP_LOCK_PATH="${WEALL_BLOCK_LOOP_LOCK_PATH:-${DEVNET_DIR}/node1/block_loop.lock}"' in genesis
    assert 'WEALL_BLOCK_LOOP_LOCK_PATH="${WEALL_BLOCK_LOOP_LOCK_PATH:-${DEVNET_DIR}/node2/block_loop.lock}"' in joining
    assert "block_loop_lock=${WEALL_BLOCK_LOOP_LOCK_PATH}" in genesis
    assert "block_loop_lock=${WEALL_BLOCK_LOOP_LOCK_PATH}" in joining


def test_node2_convergence_tx_id_command_substitution_is_clean() -> None:
    script = _script("scripts/devnet_full_onboarding_e2e.sh").read_text(encoding="utf-8")
    assert 'Submitting Tier-1-gated FOLLOW_SET through node 2 normal tx flow" >&2' in script
    assert 'NODE2_CONVERGENCE_TX_ID="$(_submit_node2_convergence_tx' in script
    assert 'raw = open(sys.argv[1]' in script
    assert 'json.JSONDecoder()' in script
    assert 'print(tx_id)' in script


def test_controlled_devnet_bootstrap_can_seed_explicit_juror_and_tier2_params(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sk = SigningKey.generate()
    pub = sk.verify_key.encode().hex()
    acct = "@devnet-genesis"

    monkeypatch.setenv("WEALL_MODE", "dev")
    monkeypatch.setenv("WEALL_GENESIS_BOOTSTRAP_ENABLE", "1")
    monkeypatch.setenv("WEALL_GENESIS_BOOTSTRAP_ACCOUNT", acct)
    monkeypatch.setenv("WEALL_GENESIS_BOOTSTRAP_PUBKEY", pub)
    monkeypatch.setenv("WEALL_GENESIS_BOOTSTRAP_JUROR_ENABLE", "1")
    monkeypatch.setenv("WEALL_POH_TIER2_N_JURORS", "1")
    monkeypatch.setenv("WEALL_POH_TIER2_MIN_TOTAL_REVIEWS", "1")
    monkeypatch.setenv("WEALL_POH_TIER2_PASS_THRESHOLD", "1")
    monkeypatch.setenv("WEALL_POH_TIER2_FAIL_MAX", "0")
    monkeypatch.setenv("WEALL_POH_TIER2_MIN_REP_MILLI", "0")
    monkeypatch.setenv("WEALL_NODE_ID", "@devnet-joiner")
    monkeypatch.delenv("WEALL_GENESIS_MODE", raising=False)
    monkeypatch.delenv("WEALL_VALIDATOR_ACCOUNT", raising=False)
    monkeypatch.delenv("WEALL_NODE_PUBKEY", raising=False)
    monkeypatch.delenv("WEALL_NODE_PRIVKEY", raising=False)

    ex = WeAllExecutor(
        db_path=str(tmp_path / "tier2-genesis.db"),
        node_id="@devnet-joiner",
        chain_id="batch217-devnet",
        tx_index_path=_tx_index_path(),
    )
    st = ex.read_state()
    jurors = (((st.get("roles") or {}).get("jurors") or {}))
    assert acct in list(jurors.get("active_set") or [])
    assert jurors.get("by_id", {}).get(acct, {}).get("active") is True
    poh_params = ((st.get("params") or {}).get("poh") or {})
    assert poh_params["tier2_n_jurors"] == 1
    assert poh_params["tier2_min_total_reviews"] == 1
    assert poh_params["tier2_pass_threshold"] == 1
    assert poh_params["tier2_fail_max"] == 0


def test_devnet_tier2_cli_and_scripts_are_present_and_non_demo() -> None:
    scripts = [
        "scripts/devnet_request_tier2.sh",
        "scripts/devnet_review_tier2.sh",
        "scripts/devnet_full_onboarding_e2e.sh",
        "scripts/devnet_boot_genesis_node.sh",
        "scripts/devnet_boot_joining_node.sh",
    ]
    for rel in scripts:
        path = _script(rel)
        subprocess.run(["bash", "-n", str(path)], check=True, timeout=10)
        text = path.read_text(encoding="utf-8")
        assert "/v1/dev/demo-seed" not in text
        assert "demo-seed" not in text

    env = dict(os.environ)
    env["PYTHONPATH"] = str(_repo_root() / "src")
    for args in (["tier2-request", "--help"], ["tier2-review", "--help"], ["tier2-case", "--help"], ["tick", "--help"]):
        proc = subprocess.run(
            [sys.executable, str(_script("scripts/devnet_tx.py")), *args],
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
        )
        assert proc.returncode == 0, proc.stderr
        assert args[0] in proc.stdout


def test_full_onboarding_smoke_runs_protocol_native_tier2_flow() -> None:
    script = _script("scripts/devnet_full_onboarding_e2e.sh").read_text(encoding="utf-8")
    assert "WEALL_DEVNET_RUN_TIER2" in script
    assert "devnet_request_tier2.sh" in script
    assert "devnet_review_tier2.sh" in script
    assert "Requesting Tier-2 async video PoH through node 1 normal tx flow" in script
    assert "protocol-assigned Tier-2 juror accept + review" in script
    assert "Verified canonical Tier-" in script
    assert "tier2-finalization" in script
    assert "Syncing node 2 from node 1 after Tier-2 finalization" in script


def test_tier2_request_skeletons_include_required_target_tier() -> None:
    poh_routes = _script("src/weall/api/routes_public_parts/poh.py").read_text(encoding="utf-8")
    helper = _script("scripts/devnet_tx.py").read_text(encoding="utf-8")
    assert 'target_tier = int(req.target_tier) if req.target_tier is not None else 2' in poh_routes
    assert 'payload: Json = {"account_id": acct, "target_tier": int(target_tier)}' in poh_routes
    assert '{"account_id": account, "target_tier": 2, "video_commitment": commitment}' in helper


def test_system_origin_tier2_replay_does_not_gate_literal_system_signer() -> None:
    text = _script("src/weall/runtime/tx_admission.py").read_text(encoding="utf-8")
    assert "def _canonical_system_tx_signer_ok" in text
    assert "Do not evaluate user/human role gates against the literal SYSTEM" in text
    assert "if _canonical_system_tx_signer_ok(env, ledger, spec):" in text



def test_system_signer_shape_bypass_is_limited_to_system_origin_txs() -> None:
    text = _script("src/weall/runtime/tx_admission.py").read_text(encoding="utf-8")
    assert "is_system_origin_tx = _system_origin_enforced(spec)" in text
    assert "and is_system_origin_tx" in text
    assert "system_only_tx_not_allowed_in_public_ingress" in text


def test_state_root_commits_post_prune_system_queue_state_for_leader_and_follower() -> None:
    text = _script("src/weall/runtime/executor.py").read_text(encoding="utf-8")
    assert "The state root must\n        # commit to that same durable post-prune state" in text
    assert "Match leader-side durable state before verifying commitments" in text
    assert "prune_emitted_system_queue(working)" in text
    # The leader-side prune must occur before production commitment to post-apply state.
    assert text.index("The state root must\n        # commit to that same durable post-prune state") < text.index("# Production commitment to post-apply state.")
    # The follower-side prune must occur before state_root verification.
    assert text.index("Match leader-side durable state before verifying commitments") < text.index("state_root = compute_state_root(working)", text.index("Match leader-side durable state before verifying commitments"))
