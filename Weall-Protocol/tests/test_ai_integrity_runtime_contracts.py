from __future__ import annotations

import ast
import importlib
import typing
from pathlib import Path

import pytest

from weall.net import codec
from weall.net.messages_parallel import (
    HelperExecCertificateMsg,
    HelperExecRejectMsg,
    HelperExecRequestMsg,
)
from weall.runtime import bft_artifact_cache, bft_outbound, bft_votecheck, diagnostics
from weall.runtime.helper_certificates import sign_helper_certificate
from weall.runtime.helper_dispatch import HelperCertificateStore
from weall.runtime.helper_receipts import sign_helper_receipt

REPO_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = REPO_ROOT / "src" / "weall"


def _module_name(path: Path) -> str:
    rel = path.relative_to(REPO_ROOT / "src").with_suffix("")
    parts = list(rel.parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def test_all_production_python_modules_import() -> None:
    failures: list[str] = []
    for path in sorted(SOURCE_ROOT.rglob("*.py")):
        module_name = _module_name(path)
        if not module_name:
            continue
        try:
            importlib.import_module(module_name)
        except Exception as exc:  # pragma: no cover - reported in aggregate below
            failures.append(f"{module_name}: {type(exc).__name__}: {exc}")
    assert failures == []


def test_network_codec_annotations_are_real_types() -> None:
    encode_hints = typing.get_type_hints(codec.encode_message)
    decode_hints = typing.get_type_hints(codec.decode_message)
    assert encode_hints["msg"] == codec.AnyWireMsg
    assert decode_hints["return"] == codec.AnyWireMsg

    for message_type in (
        HelperExecRequestMsg,
        HelperExecCertificateMsg,
        HelperExecRejectMsg,
    ):
        init_hints = typing.get_type_hints(message_type.__init__)
        assert init_hints["header"].__name__ == "WireHeader"


def test_extracted_runtime_annotations_resolve() -> None:
    targets = (
        bft_artifact_cache._bft_sender_budget_key,
        bft_outbound._bft_record_event,
        bft_votecheck._proposal_votecheck_static_ok,
        diagnostics.mempool,
        HelperCertificateStore.__init__,
    )
    for target in targets:
        typing.get_type_hints(target)


def test_parallel_execution_has_single_helper_delta_hash_validator() -> None:
    source = (SOURCE_ROOT / "runtime" / "parallel_execution.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    matches = [
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == "_helper_state_delta_hash_valid"
    ]
    assert len(matches) == 1


def test_removed_helper_receipt_shared_secret_mode_is_rejected_by_default() -> None:
    with pytest.raises(ValueError, match="shared-secret mode has been removed"):
        sign_helper_receipt(
            chain_id="c1",
            height=1,
            validator_epoch=1,
            validator_set_hash="vh",
            parent_block_id="p1",
            lane_id="L1",
            ordered_tx_ids=("t1",),
            input_state_hash="in",
            output_state_hash="out",
            helper_id="h1",
            receipt_secret="secret",
        )


def test_removed_helper_certificate_shared_secret_mode_is_rejected() -> None:
    with pytest.raises(ValueError, match="shared-secret mode has been removed"):
        sign_helper_certificate(
            chain_id="c1",
            height=1,
            validator_epoch=1,
            validator_set_hash="vh",
            parent_block_id="p1",
            lane_id="L1",
            helper_id="h1",
            lane_tx_ids=("t1",),
            descriptor_hash="d1",
            plan_id="plan-1",
            receipt_secret="secret",
        )
