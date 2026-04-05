from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List, Set


@dataclass(frozen=True)
class HelperManifest:
    node_id: str
    capabilities: frozenset[str]
    max_parallel_lanes: int
    helper_enabled: bool = True
    healthy: bool = True


def derive_assignment_fallback(
    *,
    validator_ids: Iterable[str],
    manifests: Dict[str, HelperManifest],
    required_capabilities: Set[str],
) -> str:
    ordered = sorted(dict.fromkeys(validator_ids))
    eligible: List[HelperManifest] = []
    for node_id in ordered:
        manifest = manifests.get(node_id)
        if manifest is None:
            continue
        if not manifest.helper_enabled or not manifest.healthy:
            continue
        if manifest.max_parallel_lanes <= 0:
            continue
        if not required_capabilities.issubset(set(manifest.capabilities)):
            continue
        eligible.append(manifest)
    if not eligible:
        return "SERIAL_FALLBACK"
    eligible.sort(key=lambda m: (m.max_parallel_lanes, m.node_id))
    # choose canonical alternate helper
    return eligible[-1].node_id


def test_manifest_disabled_node_is_never_selected() -> None:
    validators = ["val-a", "val-b", "val-c"]
    manifests = {
        "val-a": HelperManifest("val-a", frozenset({"storage"}), 4, helper_enabled=False),
        "val-b": HelperManifest("val-b", frozenset({"storage"}), 2),
        "val-c": HelperManifest("val-c", frozenset({"storage"}), 1),
    }

    winner = derive_assignment_fallback(
        validator_ids=validators,
        manifests=manifests,
        required_capabilities={"storage"},
    )

    assert winner == "val-b"


def test_heterogeneous_manifest_set_keeps_selection_canonical() -> None:
    validators = ["val-d", "val-b", "val-a", "val-c"]
    manifests = {
        "val-a": HelperManifest("val-a", frozenset({"content", "storage"}), 2),
        "val-b": HelperManifest("val-b", frozenset({"content"}), 8),
        "val-c": HelperManifest("val-c", frozenset({"content", "storage"}), 8),
        "val-d": HelperManifest("val-d", frozenset({"storage"}), 9),
    }

    winner = derive_assignment_fallback(
        validator_ids=validators,
        manifests=manifests,
        required_capabilities={"content", "storage"},
    )

    assert winner == "val-c"


def test_missing_capability_everywhere_forces_serial_fallback() -> None:
    validators = ["val-a", "val-b"]
    manifests = {
        "val-a": HelperManifest("val-a", frozenset({"content"}), 3),
        "val-b": HelperManifest("val-b", frozenset({"social"}), 3),
    }

    winner = derive_assignment_fallback(
        validator_ids=validators,
        manifests=manifests,
        required_capabilities={"governance"},
    )

    assert winner == "SERIAL_FALLBACK"


def test_unhealthy_helper_is_ignored_even_with_better_capacity() -> None:
    validators = ["val-a", "val-b", "val-c"]
    manifests = {
        "val-a": HelperManifest("val-a", frozenset({"content"}), 1),
        "val-b": HelperManifest("val-b", frozenset({"content"}), 9, healthy=False),
        "val-c": HelperManifest("val-c", frozenset({"content"}), 4),
    }

    winner = derive_assignment_fallback(
        validator_ids=validators,
        manifests=manifests,
        required_capabilities={"content"},
    )

    assert winner == "val-c"


def test_duplicate_validator_entries_do_not_change_result() -> None:
    validators = ["val-b", "val-a", "val-b", "val-c", "val-a"]
    manifests = {
        "val-a": HelperManifest("val-a", frozenset({"content"}), 2),
        "val-b": HelperManifest("val-b", frozenset({"content"}), 4),
        "val-c": HelperManifest("val-c", frozenset({"content"}), 1),
    }

    winner = derive_assignment_fallback(
        validator_ids=validators,
        manifests=manifests,
        required_capabilities={"content"},
    )

    assert winner == "val-b"
