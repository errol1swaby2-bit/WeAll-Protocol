from __future__ import annotations

from pathlib import Path

from weall.runtime.domain_dispatch import apply_tx
from weall.runtime.system_tx_engine import system_tx_emitter
from weall.runtime.tx_admission import TxEnvelope
from weall.tx.canon import load_tx_index_json


def _load_index():
    repo_root = Path(__file__).resolve().parents[1]
    canon_path = repo_root / "generated" / "tx_index.json"
    return load_tx_index_json(canon_path)


def test_epoch_rolls_over_after_blocks_per_epoch_finalizations() -> None:
    idx = _load_index()

    # Use a small blocks_per_epoch for a fast deterministic test.
    st = {
        "height": 0,
        "accounts": {
            "SYSTEM": {"nonce": 0, "poh_tier": 3, "banned": False, "locked": False, "reputation": 10},
        },
        "roles": {},
        "system_queue": [],
        # This unit test targets epoch queueing behavior, not finality security.
        # Finality attestation enforcement is enabled by default in production,
        # but we disable it here to keep the test focused + deterministic.
        "params": {"blocks_per_epoch": 3, "enforce_finality_attestations": False},
    }

    # Finalize 3 blocks => should roll from epoch 1 -> 2.
    for h in (1, 2, 3):
        bid = f"b{h}"
        apply_tx(
            st,
            TxEnvelope(
                tx_type="BLOCK_FINALIZE",
                signer="SYSTEM",
                nonce=h,
                payload={"block_id": bid, "height": h, "_due_height": h},
                sig="",
                # Canon: BLOCK_FINALIZE is receipt_only -> must carry a parent reference.
                parent=f"p:{h-1}",
                system=True,
            ),
        )

    # After finalizing height 1, epoch 1 open was queued (due height 2).
    # After finalizing height 3, epoch close/open was queued (due height 4).
    q = st.get("system_queue")
    assert isinstance(q, list)

    opens_due2 = [x for x in q if isinstance(x, dict) and x.get("tx_type") == "EPOCH_OPEN" and int(x.get("due_height", 0)) == 2]
    assert len(opens_due2) == 1

    closes_due4 = [x for x in q if isinstance(x, dict) and x.get("tx_type") == "EPOCH_CLOSE" and int(x.get("due_height", 0)) == 4]
    opens_due4 = [x for x in q if isinstance(x, dict) and x.get("tx_type") == "EPOCH_OPEN" and int(x.get("due_height", 0)) == 4]
    assert len(closes_due4) == 1
    assert len(opens_due4) == 1

    # Emit and apply the epoch 1 open receipt at height 2 (post phase)
    envs_h2 = system_tx_emitter(st, canon=idx, next_height=2, phase="post")
    assert "EPOCH_OPEN" in [e.tx_type for e in envs_h2]
    for env in envs_h2:
        apply_tx(st, env)

    # Emit and apply rollover receipts at height 4
    envs_h4 = system_tx_emitter(st, canon=idx, next_height=4, phase="post")
    types_h4 = [e.tx_type for e in envs_h4]
    assert "EPOCH_CLOSE" in types_h4
    assert "EPOCH_OPEN" in types_h4
    for env in envs_h4:
        apply_tx(st, env)

    c = st.get("consensus")
    assert isinstance(c, dict)
    ep = c.get("epochs")
    assert isinstance(ep, dict)
    assert int(ep.get("current", 0)) == 2
