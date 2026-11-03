from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


MODULE = Path(__file__).resolve().parents[1] / "scripts" / "two_pc_network_evidence.py"
spec = importlib.util.spec_from_file_location("two_pc_network_evidence", MODULE)
assert spec and spec.loader
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)

CHAIN = {
    "chain_id": "weall-reviewer-lan",
    "genesis_hash": "genesis-commitment-1",
    "tx_index_hash": "tx-index-commitment-1",
    "protocol_profile_hash": "profile-commitment-1",
}


def endpoint(peer: str, other: str, *, height: int = 5,
             root: str = "root-5", ready: bool = True,
             verified: bool = True) -> dict:
    return {
        "probes": {path: {"ok": True} for path in tool.CORE_PATHS},
        "chain": {
            **CHAIN,
            "status_ok": True,
            "readyz_ok": ready,
            "chain_identity_ok": True,
            "height": height,
            "state_root": root,
            "finalized_height": 4,
            "finalized_block_id": "final-4",
        },
        "network": {
            "available": True, "enabled": True,
            "peer_id": peer, "identity_pubkey": f"key-{peer}",
            "connected_peers": 1, "established_sessions": 1,
        },
        "peer_debug": {
            "available": True,
            "peers": [{
                "peer_id": other, "pubkey": f"key-{other}",
                "established": True, "identity_verified": verified, "connected": True,
            }],
        },
    }


def packets() -> tuple[dict, dict]:
    repo = {"commit": "a" * 40, "tree": "b" * 40, "tracked_tree_clean": True}
    a = {
        "schema": tool.SCHEMA, "machine_id": "laptop-A",
        "repository": dict(repo),
        "local": endpoint("peer-A", "peer-B"),
        "remote": endpoint("peer-B", "peer-A"),
    }
    b = {
        "schema": tool.SCHEMA, "machine_id": "pc-B",
        "repository": dict(repo),
        "local": endpoint("peer-B", "peer-A"),
        "remote": endpoint("peer-A", "peer-B"),
    }
    return a, b


class TwoPcNetworkEvidenceTests(unittest.TestCase):
    def test_loopback_can_be_local_but_not_remote(self) -> None:
        self.assertEqual(tool.parse_api_base("http://127.0.0.1:8000/", remote=False),
                         "http://127.0.0.1:8000")
        with self.assertRaisesRegex(ValueError, "remote_api_cannot_be_loopback"):
            tool.parse_api_base("http://127.0.0.1:8000", remote=True)
        with self.assertRaisesRegex(ValueError, "local_api_must_be_loopback"):
            tool.parse_api_base("http://192.168.1.50:8000", remote=False)

    def test_lan_requires_explicit_flag(self) -> None:
        with self.assertRaisesRegex(ValueError, "private_remote_api_requires_allow_lan"):
            tool.parse_api_base("http://192.168.1.70:8000", remote=True)
        self.assertEqual(
            tool.parse_api_base("http://192.168.1.70:8000", remote=True, allow_lan=True),
            "http://192.168.1.70:8000",
        )
        with self.assertRaisesRegex(ValueError, "public_remote_api_requires_https"):
            tool.parse_api_base("http://testnet.example.org", remote=True)
        self.assertEqual(tool.parse_api_base("https://testnet.example.org", remote=True),
                         "https://testnet.example.org")

    def test_special_addresses_and_credentials_rejected(self) -> None:
        for address in (
            "http://169.254.169.254", "https://0.0.0.0",
            "https://user:pass@testnet.example.org",
            "https://testnet.example.org/path",
            "https://testnet.example.org/?token=secret",
        ):
            with self.subTest(address=address), self.assertRaises(ValueError):
                tool.parse_api_base(address, remote=True, allow_lan=True)

    def test_projection_redacts_raw_backend_response(self) -> None:
        secret = "private-key-do-not-write-this"
        status = {"ok": True, **CHAIN, "private_key": secret}
        ready = {"ok": True, "authorization": secret}
        chain = {
            "ok": True, **CHAIN, "height": 2, "state_root": "root",
            "chain_manifest": {"genesis_hash": CHAIN["genesis_hash"]},
            "database_secret": secret,
        }
        net = {
            "ok": True, "enabled": True,
            "net": {
                "peer_id": "peer-A", "identity_pubkey": "key-peer-A",
                "private_key": secret, "counts": {"established_sessions": 1},
            },
        }
        projection = {
            "chain": tool._chain_facts(status, ready, chain),
            "network": tool._network_facts(net),
            "peer_debug": tool._peer_facts({"ok": True, "enabled": True,
                                           "peers": [{"peer_id": "peer-B",
                                                      "secret": secret}]}),
        }
        self.assertNotIn(secret, json.dumps(projection))

    def test_comparison_with_reciprocal_peer_evidence(self) -> None:
        a, b = packets()
        result = tool.compare_packets(a, b)
        self.assertTrue(result["bidirectional_api_preflight_pass"])
        self.assertTrue(result["verified_peer_adjacency_pass"])
        self.assertTrue(result["matching_state_root_snapshot_pass"])
        self.assertTrue(result["matching_finalized_checkpoint_pass"])
        self.assertFalse(result["full_networking_test_proven"])
        self.assertFalse(result["non_claims"]["live_poh_proven"])

    def test_missing_peer_debug_cannot_prove_mesh(self) -> None:
        a, b = packets()
        a["local"]["peer_debug"] = {"available": False, "peers": []}
        result = tool.compare_packets(a, b)
        self.assertTrue(result["bidirectional_api_preflight_pass"])
        self.assertFalse(result["verified_peer_adjacency_pass"])

    def test_peer_identity_must_be_verified_in_both_directions(self) -> None:
        a, b = packets()
        a["local"]["peer_debug"]["peers"][0]["identity_verified"] = False
        result = tool.compare_packets(a, b)
        self.assertFalse(result["verified_peer_adjacency_pass"])

    def test_unready_remote_node_fails_preflight(self) -> None:
        a, b = packets()
        a["remote"]["chain"]["readyz_ok"] = False
        result = tool.compare_packets(a, b)
        self.assertFalse(result["bidirectional_api_preflight_pass"])

    def test_cross_machine_commit_mismatch_fails(self) -> None:
        a, b = packets()
        b["repository"]["commit"] = "f" * 40
        result = tool.compare_packets(a, b)
        self.assertFalse(result["checks"]["same_exact_git_commit_and_tree"])
        self.assertFalse(result["bidirectional_api_preflight_pass"])

    def test_same_height_root_mismatch_never_converged(self) -> None:
        a, b = packets()
        b["local"]["chain"]["state_root"] = "different-root"
        result = tool.compare_packets(a, b)
        self.assertFalse(result["matching_state_root_snapshot_pass"])
        # API compatibility is separate from state-root convergence.
        self.assertTrue(result["bidirectional_api_preflight_pass"])

    def test_different_heights_are_not_comparable(self) -> None:
        a, b = packets()
        b["local"]["chain"]["height"] = 6
        result = tool.compare_packets(a, b)
        self.assertFalse(result["matching_state_root_snapshot_pass"])
        self.assertTrue(result["bidirectional_api_preflight_pass"])

    def test_same_peer_key_cannot_be_distinct_node(self) -> None:
        a, b = packets()
        b["local"]["network"]["peer_id"] = "peer-A"
        result = tool.compare_packets(a, b)
        self.assertFalse(result["checks"]["distinct_node_peer_ids"])
        self.assertFalse(result["bidirectional_api_preflight_pass"])

    def test_machine_labels_are_not_independent_hardware_proof(self) -> None:
        a, b = packets()
        b["machine_id"] = a["machine_id"]
        result = tool.compare_packets(a, b)
        self.assertFalse(result["bidirectional_api_preflight_pass"])
        self.assertFalse(result["non_claims"]["physical_machine_isolation_independently_verified"])

    def test_capture_projects_only_safe_api_fields(self) -> None:
        a, b = packets()
        with patch.object(tool, "_capture_endpoint", side_effect=[a["local"], b["local"]]), \
             patch.object(tool, "repo_identity", return_value=a["repository"]):
            report = tool.capture_machine(
                "machine-A", "http://127.0.0.1:8000", "http://192.168.1.15:8000",
                allow_lan=True, operator_peer_debug=True,
            )
        self.assertTrue(all(report["checks"].values()))
        self.assertTrue(report["read_only"])
        self.assertFalse(report["non_claims"]["live_poh_proven"])

    def test_file_is_written_and_comparison_cli_outputs_fail_closed(self) -> None:
        a, b = packets()
        b["local"]["chain"]["height"] = 8
        with tempfile.TemporaryDirectory() as tmp:
            left = str(Path(tmp) / "A.json")
            right = str(Path(tmp) / "B.json")
            output = str(Path(tmp) / "result.json")
            tool._write_packet(left, a)
            tool._write_packet(right, b)
            self.assertEqual(tool.main([
                "compare", "--a", left, "--b", right, "--out", output,
            ]), 0)
            self.assertEqual(tool.main([
                "compare", "--a", left, "--b", right, "--out", output,
                "--require-state",
            ]), 1)
            self.assertFalse(json.loads(Path(output).read_text())[
                "matching_state_root_snapshot_pass"])
            if os.name != "nt":
                self.assertEqual(Path(output).stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
