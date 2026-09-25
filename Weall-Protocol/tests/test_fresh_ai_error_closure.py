from __future__ import annotations

import json
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from weall.net.net_loop import NetMeshLoop, net_loop_config_from_env
from weall.net.node import NetConfig, NetNode, PeerPolicy
from weall.net.peer_store import PeerSecurityStore, PeerSecurityStoreError
from weall.net.transport_memory import InMemoryTransport
from weall.runtime import executor as executor_module
from weall.runtime.bft_journal import BftJournal, BftJournalCorruptionError
from weall.runtime.bft_outbox_store import BftOutboxStore, BftOutboxStoreError
from weall.runtime.executor import WeAllExecutor
from weall.runtime.sqlite_db import SqliteDB


def _root() -> Path:
    return Path(__file__).resolve().parents[1]


def _executor(tmp_path: Path, name: str, *, chain_id: str) -> WeAllExecutor:
    return WeAllExecutor(
        db_path=str(tmp_path / f"{name}.sqlite"),
        node_id=f"@{name}",
        chain_id=chain_id,
        tx_index_path=str(_root() / "generated" / "tx_index.json"),
    )


def _block(ex: WeAllExecutor, signer: str) -> dict:
    sub = ex.submit_tx(
        {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": signer,
            "nonce": 1,
            "payload": {"pubkey": f"k:{signer}"},
        }
    )
    assert sub["ok"] is True
    meta = ex.produce_block(max_txs=1)
    assert meta.ok is True
    block = ex.get_latest_block()
    assert isinstance(block, dict)
    return block


def _cfg(peer_id: str = "local") -> NetConfig:
    return NetConfig(
        chain_id="peer-security",
        schema_version="1",
        tx_index_hash="deadbeef",
        peer_id=peer_id,
    )


def test_votecheck_parent_pending_is_retryable_for_exact_same_block(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("WEALL_MODE", "testnet")
    monkeypatch.setenv("WEALL_SIGVERIFY", "0")
    monkeypatch.setenv("WEALL_BFT_VOTECHECK_PEER_MAX_PER_WINDOW", "100")

    leader = _executor(tmp_path, "leader", chain_id="retry-parent")
    follower = _executor(tmp_path, "follower", chain_id="retry-parent")

    block1 = _block(leader, "@u1")
    block2 = _block(leader, "@u2")
    block3 = _block(leader, "@u3")
    assert follower.apply_block(block1).ok is True

    parent_id = str(block2.get("block_id") or "")
    if not hasattr(follower, "_pending_missing_fetches"):
        follower._pending_missing_fetches = {}  # type: ignore[attr-defined]
    follower._pending_missing_fetches[parent_id] = {"requested_ms": 1}
    assert follower._validate_remote_proposal_for_vote(block3) is False

    follower._pending_missing_fetches.pop(parent_id, None)
    assert follower.apply_block(block2).ok is True
    assert follower._validate_remote_proposal_for_vote(block3) is True


def test_votecheck_speculative_exception_is_retryable_for_exact_same_block(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("WEALL_MODE", "testnet")
    monkeypatch.setenv("WEALL_SIGVERIFY", "0")

    leader = _executor(tmp_path, "leader", chain_id="retry-exception")
    follower = _executor(tmp_path, "follower", chain_id="retry-exception")
    block = _block(leader, "@u1")

    original = follower._reset_spec_exec_slot

    def fail_once(_slot):
        raise OSError("transient local speculative storage failure")

    monkeypatch.setattr(follower, "_reset_spec_exec_slot", fail_once)
    assert follower._validate_remote_proposal_for_vote(block) is False

    monkeypatch.setattr(follower, "_reset_spec_exec_slot", original)
    assert follower._validate_remote_proposal_for_vote(block) is True


def test_votecheck_speculative_executors_use_explicit_aux_paths_under_concurrency(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("WEALL_MODE", "testnet")
    monkeypatch.setenv("WEALL_SIGVERIFY", "0")
    monkeypatch.setenv("WEALL_AUX_DB_PATH", str(tmp_path / "poison-global.aux.sqlite"))

    follower = _executor(tmp_path, "follower", chain_id="aux-race")
    slots = [
        follower._spec_exec_paths_for_slot("race-a"),
        follower._spec_exec_paths_for_slot("race-b"),
    ]

    original = executor_module.prepare_executor_init_paths
    barrier = threading.Barrier(2)

    def synchronized_prepare(**kwargs):
        barrier.wait(timeout=10)
        return original(**kwargs)

    monkeypatch.setattr(executor_module, "prepare_executor_init_paths", synchronized_prepare)

    with ThreadPoolExecutor(max_workers=2) as pool:
        clones = list(pool.map(follower._reset_spec_exec_slot, slots))

    observed = {(clone.db_path, clone.aux_db_path) for clone in clones}
    assert observed == set(slots)
    assert all("poison-global" not in clone.aux_db_path for clone in clones)


def test_bft_journal_strict_recovery_rejects_truncation_and_tamper(
    tmp_path: Path,
) -> None:
    path = tmp_path / "bft.jsonl"
    journal = BftJournal(str(path))
    journal.append(
        "bft_outbound_enqueued",
        chain_id="c",
        node_id="n",
        kind="vote",
        key="vote:1:n:b",
        payload={"view": 1, "signer": "n", "block_id": "b"},
    )

    original = path.read_bytes()
    path.write_bytes(original.rstrip(b"\n"))
    with pytest.raises(BftJournalCorruptionError, match="truncated_final_record"):
        journal.bootstrap_state(strict=True)

    path.write_bytes(original)
    obj = json.loads(path.read_text(encoding="utf-8"))
    obj["payload"]["key"] = "tampered"
    path.write_text(json.dumps(obj, sort_keys=True, separators=(",", ":")) + "\n")
    with pytest.raises(BftJournalCorruptionError, match="checksum_mismatch"):
        journal.bootstrap_state(strict=True)


def test_bft_journal_strict_recovery_rejects_invalid_json_and_utf8(
    tmp_path: Path,
) -> None:
    path = tmp_path / "malformed.jsonl"
    path.write_bytes(b"{not-json}\n")
    journal = BftJournal(str(path))
    with pytest.raises(BftJournalCorruptionError, match="invalid_json"):
        journal.bootstrap_state(strict=True)

    path.write_bytes(b"\xff\n")
    with pytest.raises(BftJournalCorruptionError, match="invalid_utf8"):
        journal.bootstrap_state(strict=True)


def test_bft_journal_strict_recovery_accepts_well_formed_legacy_records(
    tmp_path: Path,
) -> None:
    path = tmp_path / "legacy.jsonl"
    record = {
        "ts_ms": 1,
        "event": "bft_outbound_enqueued",
        "payload": {
            "kind": "vote",
            "key": "vote:1:n:b",
            "payload": {"view": 1, "signer": "n", "block_id": "b"},
        },
    }
    path.write_text(json.dumps(record) + "\n", encoding="utf-8")
    journal = BftJournal(str(path))
    pending = journal.bootstrap_state(strict=True)["pending_outbound"]
    assert pending == [
        {
            "kind": "vote",
            "key": "vote:1:n:b",
            "payload": {"view": 1, "signer": "n", "block_id": "b"},
        }
    ]


def test_bft_journal_acknowledged_append_fsyncs(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "durable.jsonl"
    journal = BftJournal(str(path))
    calls: list[int] = []

    import weall.runtime.bft_journal as module

    real_fsync = module.os.fsync

    def recording_fsync(fd: int) -> None:
        calls.append(fd)
        real_fsync(fd)

    monkeypatch.setattr(module.os, "fsync", recording_fsync)
    journal.append("bft_view_advanced", view=1)
    assert calls
    assert journal.read_tail(strict=True)[-1]["event"] == "bft_view_advanced"


def test_peer_security_store_survives_netnode_restart(tmp_path: Path) -> None:
    db = SqliteDB(path=str(tmp_path / "peer-security.sqlite"))
    store1 = PeerSecurityStore(db=db)
    policy = PeerPolicy(max_strikes=1, ban_cooldown_ms=60_000)

    node1 = NetNode(
        cfg=_cfg("node-1"),
        peer_policy=policy,
        transport=InMemoryTransport(),
        peer_security_store=store1,
    )
    rec1 = node1._ensure_peer("evil")
    node1._strike(rec1, 1)
    assert node1.is_banned("evil") is True

    store2 = PeerSecurityStore(db=SqliteDB(path=str(tmp_path / "peer-security.sqlite")))
    node2 = NetNode(
        cfg=_cfg("node-2"),
        peer_policy=policy,
        transport=InMemoryTransport(),
        peer_security_store=store2,
    )
    assert node2.is_banned("evil") is True
    rec2 = node2._ensure_peer("evil")
    assert rec2.strikes == 1
    assert rec2.banned_until_ms == rec1.banned_until_ms


def test_peer_security_store_corrupt_row_fails_closed(tmp_path: Path) -> None:
    db = SqliteDB(path=str(tmp_path / "peer-security-corrupt.sqlite"))
    store = PeerSecurityStore(db=db)
    with db.write_tx() as con:
        con.execute(
            """
            INSERT INTO peer_security(peer_id, strikes, banned_until_ms, score, updated_ts_ms)
            VALUES(?, ?, ?, ?, ?)
            """,
            ("evil", "not-an-int", 99, 0.0, 1),
        )
    with pytest.raises(PeerSecurityStoreError, match="peer_security_record_corrupt"):
        store.load("evil")


def test_netmeshloop_wires_executor_aux_db_into_peer_security_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("WEALL_MODE", "testnet")
    monkeypatch.setenv("WEALL_NET_TRANSPORT", "memory")
    monkeypatch.setenv("WEALL_PEERS_FILE", str(tmp_path / "peers.json"))
    monkeypatch.delenv("WEALL_PEERS", raising=False)
    monkeypatch.delenv("WEALL_SEED_PEERS", raising=False)
    monkeypatch.delenv("WEALL_SEED_NODES", raising=False)

    ex = _executor(tmp_path, "mesh", chain_id="peer-security")

    class _Mempool:
        def read_all(self):
            return []

    loop = NetMeshLoop(executor=ex, mempool=_Mempool(), cfg=net_loop_config_from_env())
    node = loop._build_node()
    assert node._peer_security_store is not None
    assert node._peer_security_store._db.path == ex._aux_db.path


def test_shadow_protocol_implementations_are_reference_only_and_authority_bound() -> None:
    root = _root()
    assert not (root / "src/weall/poh/apply.py").exists()
    assert not (root / "src/weall/poh/finalize.py").exists()
    assert not (root / "src/weall/ledger/rewards.py").exists()

    reference_modules = (
        "weall.testing.poh_apply_reference",
        "weall.testing.poh_finalize_reference",
        "weall.testing.rewards_reference",
    )
    for path in (
        root / "src/weall/testing/poh_apply_reference.py",
        root / "src/weall/testing/poh_finalize_reference.py",
        root / "src/weall/testing/rewards_reference.py",
    ):
        assert path.is_file()
        assert "Reference-only" in path.read_text(encoding="utf-8")

    for path in sorted((root / "src/weall").rglob("*.py")):
        if "testing" in path.parts:
            continue
        text = path.read_text(encoding="utf-8")
        assert all(module not in text for module in reference_modules)

    authority = json.loads(
        (root / "configs/authoritative_mechanism_map.json").read_text(encoding="utf-8")
    )
    for mid in ("M-024", "M-028", "M-060", "M-061"):
        assert mid in authority["mechanisms"]
        assert mid in authority["required_high_risk_mechanisms"]

    assert "src/weall/poh/finalize.py" in authority["mechanisms"]["M-028"]["forbidden_shadow_paths"]
    assert (
        "src/weall/ledger/rewards.py" in authority["mechanisms"]["M-061"]["forbidden_shadow_paths"]
    )


def test_bft_outbox_preserves_more_than_256_unsent_obligations_across_journal_trim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("WEALL_MODE", "testnet")
    monkeypatch.setenv("WEALL_BFT_JOURNAL_MAX_EVENTS", "100")
    ex = _executor(tmp_path, "outbox-many", chain_id="outbox-many")

    expected = []
    for idx in range(300):
        payload = {"view": idx + 1, "signer": "@outbox-many", "block_id": f"b{idx}"}
        ex._bft_enqueue_outbound("vote", payload)
        expected.append({"kind": "vote", "payload": payload})

    for idx in range(250):
        ex._bft_journal.append("bft_view_advanced", view=10_000 + idx)

    assert ex.bft_pending_outbound_messages() == expected

    ex2 = _executor(tmp_path, "outbox-many", chain_id="outbox-many")
    assert ex2.bft_pending_outbound_messages() == expected


def test_bft_outbox_additive_migration_preserves_legacy_insertion_order(
    tmp_path: Path,
) -> None:
    path = tmp_path / "legacy-outbox.sqlite"
    with sqlite3.connect(path) as con:
        con.execute(
            """
            CREATE TABLE bft_outbox (
              outbound_key TEXT PRIMARY KEY,
              kind TEXT NOT NULL,
              payload_json TEXT NOT NULL,
              enqueued_ts_ms INTEGER NOT NULL,
              updated_ts_ms INTEGER NOT NULL
            );
            """
        )
        for key in ("z-first", "a-second", "m-third"):
            con.execute(
                """
                INSERT INTO bft_outbox(
                  outbound_key, kind, payload_json, enqueued_ts_ms, updated_ts_ms
                ) VALUES(?, 'vote', '{}', 1234, 1234);
                """,
                (key,),
            )
        con.commit()

    db = SqliteDB(path=str(path))
    db.init_schema()
    store = BftOutboxStore(db=db)

    migrated = store.pending()
    assert [item.key for item in migrated] == ["z-first", "a-second", "m-third"]
    assert [item.enqueue_seq for item in migrated] == [1, 2, 3]

    store.enqueue(key="after-migration", kind="vote", payload={"view": 4})
    after = store.pending()
    assert [item.key for item in after] == [
        "z-first",
        "a-second",
        "m-third",
        "after-migration",
    ]
    assert [item.enqueue_seq for item in after] == [1, 2, 3, 4]


def test_peer_security_transport_host_survives_source_port_reconnect(tmp_path: Path) -> None:
    path = tmp_path / "peer-security-reconnect.sqlite"
    policy = PeerPolicy(max_strikes=1, ban_cooldown_ms=60_000)

    node1 = NetNode(
        cfg=_cfg("node-1"),
        peer_policy=policy,
        transport=InMemoryTransport(),
        peer_security_store=PeerSecurityStore(db=SqliteDB(path=str(path))),
    )
    rec1 = node1._ensure_peer("tcp://203.0.113.7:42001")
    node1._strike(rec1, 1)
    assert node1.is_banned("tcp://203.0.113.7:42001") is True

    node2 = NetNode(
        cfg=_cfg("node-2"),
        peer_policy=policy,
        transport=InMemoryTransport(),
        peer_security_store=PeerSecurityStore(db=SqliteDB(path=str(path))),
    )
    rec2 = node2._ensure_peer("tls://203.0.113.7:42002")
    assert rec2.strikes == 1
    assert node2.is_banned("tls://203.0.113.7:42002") is True


def test_peer_security_authenticated_identity_does_not_share_penalties_across_addresses(
    tmp_path: Path,
) -> None:
    path = tmp_path / "peer-security-identity.sqlite"
    policy = PeerPolicy(max_strikes=1, ban_cooldown_ms=60_000)

    node1 = NetNode(
        cfg=_cfg("node-1"),
        peer_policy=policy,
        transport=InMemoryTransport(),
        peer_security_store=PeerSecurityStore(db=SqliteDB(path=str(path))),
    )
    rec1 = node1._ensure_peer("tcp://203.0.113.7:42001")
    rec1.identity_ok = True
    rec1.identity_account = "@validator"
    rec1.identity_pubkey = "pk"
    node1._bind_authenticated_peer_security(rec1)
    node1._strike(rec1, 1)

    node2 = NetNode(
        cfg=_cfg("node-2"),
        peer_policy=policy,
        transport=InMemoryTransport(),
        peer_security_store=PeerSecurityStore(db=SqliteDB(path=str(path))),
    )
    rec2 = node2._ensure_peer("tls://198.51.100.9:55000")
    rec2.identity_ok = True
    rec2.identity_account = "@validator"
    rec2.identity_pubkey = "pk"
    node2._bind_authenticated_peer_security(rec2)
    assert rec2.strikes == 0
    assert rec2.banned_until_ms == 0


def test_peer_security_stale_strikes_are_prunable_after_retention(tmp_path: Path) -> None:
    db = SqliteDB(path=str(tmp_path / "peer-security-prune.sqlite"))
    store = PeerSecurityStore(db=db)
    with db.write_tx() as con:
        for idx in range(50):
            con.execute(
                """
                INSERT INTO peer_security(peer_id, strikes, banned_until_ms, score, updated_ts_ms)
                VALUES(?, ?, ?, ?, ?)
                """,
                (f"identity-account:@peer{idx}", 1, 0, 0.0, 1),
            )
    deleted = store.prune_expired(now_ms=10_000, retention_ms=100, limit=100)
    assert deleted == 50
    with db.connection() as con:
        row = con.execute("SELECT COUNT(*) AS n FROM peer_security;").fetchone()
    assert int(row["n"]) == 0


def test_votecheck_concurrent_slot_acquisition_is_unique(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("WEALL_MODE", "testnet")
    monkeypatch.setenv("WEALL_BFT_VOTECHECK_MAX_CONCURRENT", "8")
    follower = _executor(tmp_path, "votecheck-slots", chain_id="votecheck-slots")
    barrier = threading.Barrier(8)

    def acquire_one(_idx: int) -> tuple[str, str]:
        barrier.wait(timeout=10)
        return follower._acquire_spec_exec_slot()

    with ThreadPoolExecutor(max_workers=8) as pool:
        slots = list(pool.map(acquire_one, range(8)))
    assert len(set(slots)) == 8
    for slot in slots:
        follower._release_spec_exec_slot(slot)
    assert len(follower._spec_exec_pool) == follower._max_spec_exec_pool


def test_production_helper_fast_path_fails_closed_until_bft_integration_ready(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_HELPER_MODE_ENABLED", "1")
    monkeypatch.setenv("WEALL_HELPER_FAST_PATH", "1")
    with pytest.raises(
        executor_module.ExecutorError,
        match="helper_fast_path_production_integration_not_ready",
    ):
        _executor(tmp_path, "helper-fast-prod", chain_id="helper-fast-prod")


def test_bft_outbox_resigned_vote_is_idempotent_but_semantic_change_collides(
    tmp_path: Path,
) -> None:
    store = BftOutboxStore(db=SqliteDB(path=str(tmp_path / "resigned-vote.sqlite")))
    key = "vote:7:@v2:block-7"
    vote = {
        "t": "VOTE",
        "chain_id": "chain-A",
        "view": 7,
        "block_id": "block-7",
        "block_hash": "hash-7",
        "parent_id": "block-6",
        "signer": "@v2",
        "pubkey": "pk-v2",
        "sig": "signature-a",
        "sig_profile": "pq-mldsa-v1",
        "validator_epoch": 3,
        "validator_set_hash": "set-3",
        "consensus_phase": "hotstuff",
    }
    store.enqueue(key=key, kind="vote", payload=vote)

    resigned = dict(vote)
    resigned["sig"] = "signature-b"
    store.enqueue(key=key, kind="vote", payload=resigned)

    pending = store.pending()
    assert len(pending) == 1
    assert pending[0].payload == vote

    changed_message = dict(resigned)
    changed_message["block_hash"] = "different-hash"
    with pytest.raises(BftOutboxStoreError, match="bft_outbox_key_collision"):
        store.enqueue(key=key, kind="vote", payload=changed_message)


def test_bft_outbox_resigned_timeout_is_idempotent_but_epoch_change_collides(
    tmp_path: Path,
) -> None:
    store = BftOutboxStore(db=SqliteDB(path=str(tmp_path / "resigned-timeout.sqlite")))
    key = "timeout:9:@v3:qc-8"
    timeout = {
        "t": "TIMEOUT",
        "chain_id": "chain-A",
        "view": 9,
        "high_qc_id": "qc-8",
        "signer": "@v3",
        "pubkey": "pk-v3",
        "sig": "signature-a",
        "sig_profile": "pq-mldsa-v1",
        "validator_epoch": 4,
        "validator_set_hash": "set-4",
        "consensus_phase": "hotstuff",
    }
    store.enqueue(key=key, kind="timeout", payload=timeout)

    resigned = dict(timeout)
    resigned["sig"] = "signature-b"
    store.enqueue(key=key, kind="timeout", payload=resigned)
    assert store.pending()[0].payload == timeout

    changed_epoch = dict(resigned)
    changed_epoch["validator_epoch"] = 5
    with pytest.raises(BftOutboxStoreError, match="bft_outbox_key_collision"):
        store.enqueue(key=key, kind="timeout", payload=changed_epoch)
