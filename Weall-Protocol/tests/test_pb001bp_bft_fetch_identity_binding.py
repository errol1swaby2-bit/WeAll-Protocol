from __future__ import annotations

from pathlib import Path

from weall.net.net_loop import NetLoopConfig, NetMeshLoop
from weall.runtime.block_hash import compute_block_hash
from weall.runtime.block_id import compute_block_id
from weall.runtime.executor import WeAllExecutor


def _canonical_block(
    *,
    chain_id: str,
    state_root: str,
    prev_block_id: str = "missing-parent",
    prev_block_hash: str = "11" * 32,
    height: int = 2,
    ts_ms: int = 2000,
    receipts_root: str = "22" * 32,
) -> dict:
    header = {
        "chain_id": chain_id,
        "height": int(height),
        "prev_block_hash": prev_block_hash,
        "block_ts_ms": int(ts_ms),
        "tx_ids": [],
        "receipts_root": receipts_root,
        "state_root": state_root,
    }
    block_hash = compute_block_hash(header=header)
    block_id = compute_block_id(
        chain_id=chain_id,
        height=int(height),
        prev_block_id=prev_block_id,
        prev_block_hash=prev_block_hash,
        ts_ms=int(ts_ms),
        tx_ids=[],
        receipts_root=receipts_root,
    )
    return {
        "block_id": block_id,
        "block_hash": block_hash,
        "height": int(height),
        "prev_block_id": prev_block_id,
        "block_ts_ms": int(ts_ms),
        "header": header,
        "txs": [],
        "receipts": [],
    }


def _executor(tmp_path: Path, *, chain_id: str) -> WeAllExecutor:
    return WeAllExecutor(
        db_path=str(tmp_path / "node.sqlite"),
        chain_id=chain_id,
        node_id="@node",
        tx_index_path="generated/tx_index.json",
    )


class _DummyNode:
    def __init__(self, chain_id: str) -> None:
        self.cfg = type(
            "Cfg", (), {"chain_id": chain_id, "schema_version": "1", "tx_index_hash": "0"}
        )()


def test_fetched_block_id_alias_cannot_poison_authentic_block(tmp_path: Path) -> None:
    chain_id = "pb001bp-id-alias"
    ex = _executor(tmp_path, chain_id=chain_id)
    authentic = _canonical_block(chain_id=chain_id, state_root="aa" * 32)
    forged = _canonical_block(chain_id=chain_id, state_root="bb" * 32)

    # The forged block has a perfectly self-consistent header/hash pair but borrows
    # the authentic block's content-derived ID. Canonical-hash-only validation is
    # therefore insufficient at this unauthenticated fetch boundary.
    forged["block_id"] = authentic["block_id"]
    forged_canonical_hash = forged["block_hash"]
    forged["block_hash"] = authentic["block_hash"]
    assert forged_canonical_hash != authentic["block_hash"]

    assert ex.bft_cache_remote_block(forged, expected_block_hash=authentic["block_hash"]) is False
    assert ex.bft_diagnostics()["pending_remote_blocks_count"] == 0

    assert ex.bft_cache_remote_block(authentic, expected_block_hash=authentic["block_hash"]) is True
    assert ex.bft_diagnostics()["pending_remote_blocks"] == [authentic["block_id"]]


def test_fetched_noncanonical_advertised_hash_is_rejected_without_poisoning(
    tmp_path: Path,
) -> None:
    chain_id = "pb001bp-hash-alias"
    ex = _executor(tmp_path, chain_id=chain_id)
    authentic = _canonical_block(chain_id=chain_id, state_root="aa" * 32)
    forged = dict(authentic)
    forged["block_hash"] = "ff" * 32

    assert ex.bft_cache_remote_block(forged, expected_block_hash=authentic["block_hash"]) is False
    assert ex.bft_diagnostics()["pending_remote_blocks_count"] == 0
    assert ex.bft_cache_remote_block(authentic, expected_block_hash=authentic["block_hash"]) is True


def test_restart_drops_prepatch_poisoned_pending_remote_block(tmp_path: Path) -> None:
    chain_id = "pb001bp-restart"
    ex = _executor(tmp_path, chain_id=chain_id)
    authentic = _canonical_block(chain_id=chain_id, state_root="aa" * 32)
    forged = _canonical_block(chain_id=chain_id, state_root="bb" * 32)
    forged["block_id"] = authentic["block_id"]
    forged["block_hash"] = authentic["block_hash"]

    # Model a row written by the vulnerable pre-patch fetch path. The new startup
    # path must not restore it into identity truth, even across a software upgrade.
    ex._persist_pending_bft_artifact(
        kind="pending_remote_block",
        block_id=str(authentic["block_id"]),
        payload=forged,
    )

    restarted = _executor(tmp_path, chain_id=chain_id)
    diag = restarted.bft_diagnostics()
    assert diag["pending_remote_blocks_count"] == 0
    assert diag["pending_remote_blocks"] == []

    with restarted._aux_db.connection() as con:
        row = con.execute(
            "SELECT COUNT(*) FROM bft_pending_artifacts "
            "WHERE kind='pending_remote_block' AND block_id=?;",
            (str(authentic["block_id"]),),
        ).fetchone()
    assert int(row[0]) == 0

    assert (
        restarted.bft_cache_remote_block(authentic, expected_block_hash=authentic["block_hash"])
        is True
    )


def test_valid_fetched_block_survives_restart_when_parent_is_missing(tmp_path: Path) -> None:
    chain_id = "pb001bp-valid-restart"
    ex = _executor(tmp_path, chain_id=chain_id)
    block = _canonical_block(chain_id=chain_id, state_root="aa" * 32)

    assert ex.bft_cache_remote_block(block, expected_block_hash=block["block_hash"]) is True
    assert ex.bft_diagnostics()["pending_remote_blocks"] == [block["block_id"]]

    restarted = _executor(tmp_path, chain_id=chain_id)
    assert restarted.bft_diagnostics()["pending_remote_blocks"] == [block["block_id"]]
    restored = restarted._bft_pending_block_json(str(block["block_id"]))
    assert isinstance(restored, dict)
    assert restored["block_hash"] == block["block_hash"]


def test_fetch_cache_requires_prior_expected_hash_anchor(tmp_path: Path) -> None:
    chain_id = "pb001bp-required-anchor"
    ex = _executor(tmp_path, chain_id=chain_id)
    authentic = _canonical_block(chain_id=chain_id, state_root="aa" * 32)

    assert ex.bft_cache_remote_block(authentic) is False
    assert ex.bft_diagnostics()["pending_remote_blocks_count"] == 0


def test_net_loop_cannot_hide_forged_header_behind_expected_advertised_hash(
    tmp_path: Path, monkeypatch
) -> None:
    chain_id = "pb001bp-net-loop"
    ex = _executor(tmp_path, chain_id=chain_id)
    authentic = _canonical_block(chain_id=chain_id, state_root="aa" * 32)
    forged = _canonical_block(chain_id=chain_id, state_root="bb" * 32)

    # Exact pre-patch wire exploit: the attacker borrows the requested block ID
    # and advertises the authentic expected hash, while returning a different
    # header/body whose canonical hash is not that expected hash.
    forged["block_id"] = authentic["block_id"]
    forged["block_hash"] = authentic["block_hash"]

    ex._put_pending_missing_qc(
        {
            "block_id": str(authentic["block_id"]),
            "block_hash": str(authentic["block_hash"]),
            "parent_id": "missing-parent",
            "view": 1,
        }
    )
    assert any(
        str(desc.get("block_id") or "") == str(authentic["block_id"])
        for desc in ex.bft_resolved_pending_fetch_request_descriptors()
    )

    loop = NetMeshLoop(
        executor=ex,
        mempool=object(),
        cfg=NetLoopConfig(
            enabled=False,
            bind_host="127.0.0.1",
            bind_port=30303,
            tick_ms=25,
            schema_version="1",
        ),
    )
    loop.node = _DummyNode(chain_id)
    loop._bft_enabled = True
    loop._bft_fetch_enabled = True
    loop._bft_fetch_sources = ["http://attacker"]
    loop._bft_fetch_interval_ms = 1
    loop._bft_fetch_cooldown_ms = 1
    loop._bft_fetch_batch = 8

    calls: list[str] = []

    def _fake_get(url: str, *, timeout_s: float = 2.0):
        calls.append(url)
        return {"ok": True, "block": dict(forged)}

    import weall.net.net_loop as net_loop_mod

    monkeypatch.setattr(net_loop_mod, "_http_get_json", _fake_get)
    loop._bft_fetch_tick()

    assert calls == [f"http://attacker/v1/state/block/{authentic['block_id']}"]
    assert ex.bft_diagnostics()["pending_remote_blocks_count"] == 0
    assert ex.bft_diagnostics()["pending_remote_blocks"] == []
    assert any(
        str(desc.get("block_id") or "") == str(authentic["block_id"])
        for desc in ex.bft_resolved_pending_fetch_request_descriptors()
    )
    assert (
        ex.bft_cache_remote_block(
            authentic,
            expected_block_hash=str(authentic["block_hash"]),
        )
        is True
    )
