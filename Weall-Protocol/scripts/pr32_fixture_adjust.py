from pathlib import Path

path = Path("tests/test_post31_closure_pack.py")
text = path.read_text(encoding="utf-8")

old_state = '''    chain_id = "post31-post-capacity"
    state = {
        "chain_id": chain_id,
        "height": 0,
        "tip": "",
        "tip_hash": "",
        "accounts": {},
        "system_queue": [],
        "consensus": {"epochs": {"current": 0, "events": []}},
    }
'''
new_state = '''    chain_id = "post31-post-capacity"
    state = {
        "chain_id": chain_id,
        "height": 0,
        "tip": "",
        "tip_hash": "",
        "accounts": {
            "@operator": {
                "nonce": 0,
                "poh_tier": 2,
                "banned": False,
                "locked": False,
                "reputation": 10,
            }
        },
        "roles": {
            "node_operators": {
                "by_id": {"@operator": {"account_id": "@operator", "enrolled": True}},
                "active_set": [],
            }
        },
        "system_queue": [],
        "consensus": {"epochs": {"current": 0, "events": []}},
    }
'''
if text.count(old_state) != 1:
    raise SystemExit(f"capacity state fixture match count={text.count(old_state)}")
text = text.replace(old_state, new_state, 1)

old_scheduler = '''        enqueue_system_tx(
            working,
            tx_type="EPOCH_OPEN",
            payload={"epoch": 1},
            due_height=int(next_height),
            signer="SYSTEM",
            once=True,
            parent=None,
            phase="post",
        )
'''
new_scheduler = '''        enqueue_system_tx(
            working,
            tx_type="ROLE_NODE_OPERATOR_ACTIVATE",
            payload={"account_id": "@operator"},
            due_height=int(next_height),
            signer="SYSTEM",
            once=True,
            parent=None,
            phase="post",
        )
'''
if text.count(old_scheduler) != 1:
    raise SystemExit(f"capacity scheduler fixture match count={text.count(old_scheduler)}")
text = text.replace(old_scheduler, new_scheduler, 1)

old_assert = '''    assert [str(tx.get("tx_type") or "") for tx in system_txs] == ["EPOCH_OPEN"]
'''
new_assert = '''    assert [str(tx.get("tx_type") or "") for tx in system_txs] == [
        "ROLE_NODE_OPERATOR_ACTIVATE"
    ]
'''
if text.count(old_assert) != 1:
    raise SystemExit(f"capacity assertion fixture match count={text.count(old_assert)}")
text = text.replace(old_assert, new_assert, 1)

path.write_text(text, encoding="utf-8")
