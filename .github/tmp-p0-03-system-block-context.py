from __future__ import annotations

from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, found {count}")
    return text.replace(old, new, 1)


root = Path(__file__).resolve().parents[1] / "Weall-Protocol"

block_admission = root / "src/weall/runtime/block_admission.py"
text = block_admission.read_text(encoding="utf-8")
old = '''            verdict: TxVerdict = admit_tx(
                ledger=ledger,
                tx=env,
                canon=tx_index,
                context="block" if bool(verify_signatures) else "local",
            )
'''
new = '''            # SYSTEM envelopes are intrinsically block-context protocol work.
            # ``verify_signatures`` controls ordinary unsigned local fixtures; it
            # must not downgrade SYSTEM-origin authority checks to local context.
            verdict: TxVerdict = admit_tx(
                ledger=ledger,
                tx=env,
                canon=tx_index,
                context="block",
            )
'''
text = replace_once(text, old, new, "system tx block admission context")
block_admission.write_text(text, encoding="utf-8")


test_path = root / "tests/test_priority0_system_signer_canon.py"
text = test_path.read_text(encoding="utf-8")
text = replace_once(
    text,
    '''from weall.runtime.domain_dispatch import ApplyError, apply_tx
from weall.runtime.tx_admission import admit_tx
from weall.runtime.tx_admission_types import TxEnvelope
''',
    '''from weall.ledger.state import LedgerView
from weall.runtime.block_admission import admit_block_txs
from weall.runtime.domain_dispatch import ApplyError, apply_tx
from weall.runtime.tx_admission import admit_tx
from weall.runtime.tx_admission_types import TxEnvelope
from weall.tx.canon import TxIndex
''',
    "system signer regression imports",
)
append = '''\n\ndef test_block_admission_keeps_system_origin_block_context_when_user_signatures_optional() -> None:\n    ledger_raw = _ledger(system_signer="SYSTEM")\n    ledger = LedgerView.from_ledger(ledger_raw)\n    canon = TxIndex.from_raw(\n        {\n            "tx": {\n                "POH_BOOTSTRAP_TIER2_GRANT": {\n                    "origin": "SYSTEM",\n                    "context": "block",\n                    "system_only": True,\n                }\n            }\n        }\n    )\n    env = TxEnvelope(\n        tx_type="POH_BOOTSTRAP_TIER2_GRANT",\n        signer="SYSTEM",\n        nonce=0,\n        system=True,\n        payload={"account_id": "alice"},\n    )\n\n    ok, block_reject, rejects = admit_block_txs(\n        [env],\n        ledger,\n        canon,\n        verify_signatures=False,\n    )\n\n    assert ok is True\n    assert block_reject is None\n    assert rejects == [None]\n'''
if "test_block_admission_keeps_system_origin_block_context_when_user_signatures_optional" in text:
    raise SystemExit("system signer regression test already present")
text = text.rstrip() + append + "\n"
test_path.write_text(text, encoding="utf-8")
