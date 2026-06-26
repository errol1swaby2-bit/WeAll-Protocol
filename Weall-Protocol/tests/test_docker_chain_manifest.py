from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_dockerfile_copies_chain_manifests_into_image_batch267() -> None:
    text = (ROOT / "Dockerfile").read_text(encoding="utf-8")

    assert "COPY configs /app/configs" in text
    assert "COPY specs /app/specs" in text
    assert text.index("COPY specs /app/specs") < text.index("COPY configs /app/configs")


def test_quickstart_default_demo_manifest_is_container_relative_batch267() -> None:
    text = (ROOT / "scripts/quickstart_tester.sh").read_text(encoding="utf-8")

    assert 'DEMO_CHAIN_MANIFEST_REL="./configs/chains/weall-demo.json"' in text
    assert 'WEALL_CONTAINER_CHAIN_MANIFEST_PATH' in text
    assert 'export WEALL_CHAIN_MANIFEST_PATH="${WEALL_CONTAINER_CHAIN_MANIFEST_PATH:-${DEMO_CHAIN_MANIFEST_REL}}"' in text
    assert 'export WEALL_CHAIN_MANIFEST_PATH="${WEALL_CHAIN_MANIFEST_PATH:-${ROOT_DIR}/configs/chains/weall-demo.json}"' not in text


def test_quickstart_still_reads_host_manifest_for_chain_id_batch267() -> None:
    text = (ROOT / "scripts/quickstart_tester.sh").read_text(encoding="utf-8")

    assert 'host_chain_manifest_path="${ROOT_DIR}/configs/chains/weall-demo.json"' in text
    assert 'python3 -S - "${host_chain_manifest_path}"' in text
