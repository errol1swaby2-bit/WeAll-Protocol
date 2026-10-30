"""Issue 68: deletion only in synthetic temporary devnet fixtures."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts/devnet_safe_paths.py"
RESET = ROOT / "scripts/devnet_reset_state.sh"
REHEARSAL = ROOT / "scripts/devnet_local_two_frontend_rehearsal.sh"
CONFIRM = "I_CONFIRM_DELETE_CUSTOM_DEVNET"


class DevnetDeleteBoundaries(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="weall-safe-reset-test-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.repo = self.root / "repo"
        (self.repo / "scripts").mkdir(parents=True)
        shutil.copyfile(HELPER, self.repo / "scripts/devnet_safe_paths.py")
        shutil.copyfile(RESET, self.repo / "scripts/devnet_reset_state.sh")
        self.target = self.repo / ".weall-devnet"
        self.protected = self.root / "NEVER_DELETE"
        self.protected.write_text("intact")

    def invoke(self, *args, env=None):
        variables = os.environ.copy()
        variables.pop("WEALL_DEVNET_RESET_ALLOWED_PARENT", None)
        variables.pop("WEALL_DEVNET_RESET_CONFIRM", None)
        if env:
            variables.update(env)
        return subprocess.run(
            [
                sys.executable,
                str(self.repo / "scripts/devnet_safe_paths.py"),
                *[str(x) for x in args],
            ],
            env=variables,
            capture_output=True,
            text=True,
            check=False,
        )

    def assert_protected(self):
        self.assertEqual(self.protected.read_text(), "intact")

    def test_default_reset_only_disposable_state(self):
        self.target.mkdir()
        (self.target / "test-ledger.db").write_text("discard")
        result = self.invoke("reset", self.target)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.target / "test-ledger.db").exists())
        self.assertTrue((self.target / "node1").is_dir())
        self.assertTrue((self.target / "node2").is_dir())
        self.assert_protected()

    def test_shell_reset_wrapper_uses_safe_helper(self):
        self.target.mkdir()
        (self.target / "test-ledger.db").write_text("discard")
        env = os.environ.copy()
        env["WEALL_DEVNET_DIR"] = str(self.target)
        result = subprocess.run(
            ["bash", str(self.repo / "scripts/devnet_reset_state.sh")],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("ok=true", result.stdout)
        self.assertFalse((self.target / "test-ledger.db").exists())
        self.assert_protected()

    def test_custom_reset_requires_both_exact_approval_fields(self):
        parent = self.root / "custom"
        parent.mkdir()
        target = parent / ".weall-devnet"
        target.mkdir()
        (target / "important.db").write_text("keep")
        cases = (
            {},
            {"WEALL_DEVNET_RESET_ALLOWED_PARENT": str(parent)},
            {"WEALL_DEVNET_RESET_CONFIRM": CONFIRM},
            {
                "WEALL_DEVNET_RESET_ALLOWED_PARENT": str(self.repo),
                "WEALL_DEVNET_RESET_CONFIRM": CONFIRM,
            },
        )
        for case in cases:
            with self.subTest(case=case):
                self.assertEqual(self.invoke("reset", target, env=case).returncode, 2)
                self.assertEqual((target / "important.db").read_text(), "keep")
        self.assertEqual(
            self.invoke(
                "reset",
                target,
                env={
                    "WEALL_DEVNET_RESET_ALLOWED_PARENT": str(parent),
                    "WEALL_DEVNET_RESET_CONFIRM": CONFIRM,
                },
            ).returncode,
            0,
        )
        self.assertFalse((target / "important.db").exists())
        self.assert_protected()

    def test_target_symlink_and_ancestor_symlink_refused(self):
        external = self.root / "external"
        external.mkdir()
        (external / "important").write_text("keep")
        self.target.symlink_to(external, target_is_directory=True)
        self.assertEqual(self.invoke("reset", self.target).returncode, 2)
        self.target.unlink()
        alias = self.root / "alias"
        alias.symlink_to(self.repo, target_is_directory=True)
        self.assertEqual(
            self.invoke(
                "reset",
                alias / ".weall-devnet",
                env={
                    "WEALL_DEVNET_RESET_ALLOWED_PARENT": str(alias),
                    "WEALL_DEVNET_RESET_CONFIRM": CONFIRM,
                },
            ).returncode,
            2,
        )
        self.assertEqual((external / "important").read_text(), "keep")
        self.assert_protected()

    def test_path_traversal_root_relative_wrong_name_denied(self):
        for candidate in (
            "/",
            "/home",
            ".",
            "../.weall-devnet",
            "",
            str(self.repo / ".." / ".weall-devnet"),
            str(self.repo / "other"),
        ):
            with self.subTest(path=candidate):
                self.assertEqual(self.invoke("reset", candidate).returncode, 2)
        self.assert_protected()

    def test_ipfs_must_be_direct_devnet_child(self):
        self.target.mkdir()
        partition = self.target / "ipfs_partition"
        self.assertEqual(self.invoke("check-ipfs", self.target, partition).returncode, 0)
        for candidate in (
            self.root / "unrelated_ipfs",
            self.repo / "ipfs",
            self.target,
            self.target / "nested" / "ipfs",
        ):
            with self.subTest(path=str(candidate)):
                self.assertEqual(self.invoke("check-ipfs", self.target, candidate).returncode, 2)
        self.assertFalse(partition.exists())
        self.assert_protected()

    def test_corrupt_blocks_fail_without_deleting_contents(self):
        self.target.mkdir()
        blocks = self.target / "ipfs_partition" / "blocks"
        blocks.mkdir(parents=True)
        (blocks / "important").write_text("preserve")
        self.assertEqual(self.invoke("check-ipfs", self.target, blocks.parent).returncode, 2)
        self.assertEqual((blocks / "important").read_text(), "preserve")
        (blocks / "SHARDING").write_text("sharded")
        self.assertEqual(self.invoke("check-ipfs", self.target, blocks.parent).returncode, 0)
        self.assert_protected()

    def test_ipfs_blocks_and_sharding_symlinks_refused(self):
        self.target.mkdir()
        partition = self.target / "ipfs"
        partition.mkdir()
        external = self.root / "external"
        external.mkdir()
        (external / "SHARDING").write_text("outside")
        (partition / "blocks").symlink_to(external, target_is_directory=True)
        self.assertEqual(self.invoke("check-ipfs", self.target, partition).returncode, 2)
        (partition / "blocks").unlink()
        (partition / "blocks").mkdir()
        (partition / "blocks" / "SHARDING").symlink_to(external / "SHARDING")
        self.assertEqual(self.invoke("check-ipfs", self.target, partition).returncode, 2)
        self.assertEqual((external / "SHARDING").read_text(), "outside")
        self.assert_protected()

    def test_check_devnet_is_read_only(self):
        self.target.mkdir()
        (self.target / "persisted.db").write_text("stay")
        self.assertEqual(self.invoke("check-devnet", self.target).returncode, 0)
        self.assertEqual((self.target / "persisted.db").read_text(), "stay")
        self.assert_protected()

    def test_rehearsal_removes_automatic_ipfs_deletion(self):
        content = REHEARSAL.read_text(encoding="utf-8")
        variable = "$" + "{IPFS_PARTITION_PATH}"
        devnet = "$" + "{DEVNET_DIR}"
        self.assertNotIn('rm -rf "' + variable + '"', content)
        self.assertIn('check-ipfs "' + devnet + '" "' + variable + '"', content)
        self.assertIn("Preserving the repository; no automatic deletion.", content)
        self.assertIn('check-devnet "' + devnet + '"', content)

    def test_shell_scripts_parse(self):
        self.assertTrue(shutil.rmtree.avoids_symlink_attacks)
        for script in (RESET, REHEARSAL):
            with self.subTest(script=str(script)):
                r = subprocess.run(["bash", "-n", str(script)], capture_output=True, text=True)
                self.assertEqual(r.returncode, 0, r.stderr)


if __name__ == "__main__":
    unittest.main()
