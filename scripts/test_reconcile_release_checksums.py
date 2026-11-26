#!/usr/bin/env python3
"""Unit tests for scripts/reconcile_release_checksums.py (P0-5 & P1-14 guards)."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "reconcile_release_checksums.py"


def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-W", "error", str(SCRIPT), *args],
        text=True,
        capture_output=True,
        check=False,
    )


def populate_dist(dist: Path, tag: str = "preview-cordis-test") -> None:
    (dist / f"pktpath-windows-x64-{tag}.zip").write_bytes(b"win-zip-bytes")
    (dist / f"pktpath-linux-x64-{tag}.tar.gz").write_bytes(b"linux-tar-bytes")
    (dist / "pktpath-android-arm64").write_bytes(b"android-elf")
    (dist / "pktpath-linux-x86_64").write_bytes(b"linux-x64-elf")
    (dist / "pktpath-linux-arm64").write_bytes(b"linux-arm64-elf")


class ReconcileReleaseChecksumsTests(unittest.TestCase):
    def test_fresh_release_returns_create_and_builds_complete_sums(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            dist = Path(td) / "dist"
            dist.mkdir()
            populate_dist(dist)

            r = run_cli(
                "check-existing",
                "--dist-dir", str(dist),
                "--release-exists", "false",
                "--event-name", "push",
                "--allow-existing-release", "false",
            )
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(r.stdout.strip(), "create")

            out = dist / "SHA256SUMS.txt"
            r2 = run_cli("build-sums", "--assets-dir", str(dist), "--out", str(out))
            self.assertEqual(r2.returncode, 0, r2.stderr)
            lines = out.read_text(encoding="ascii").strip().splitlines()
            self.assertEqual(len(lines), 5)
            names = [line.split("  ", 1)[1] for line in lines]
            self.assertEqual(
                names,
                [
                    "pktpath-android-arm64",
                    "pktpath-linux-arm64",
                    "pktpath-linux-x64-preview-cordis-test.tar.gz",
                    "pktpath-linux-x86_64",
                    "pktpath-windows-x64-preview-cordis-test.zip",
                ],
            )
            for line in lines:
                digest, name = line.split("  ", 1)
                self.assertEqual(digest, hashlib.sha256((dist / name).read_bytes()).hexdigest())

    def test_tag_push_skips_when_release_already_has_reviewed_assets(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            dist = root / "dist"
            dist.mkdir()
            populate_dist(dist, tag="preview-cordis-20261127-wave1")

            existing = root / "existing.json"
            existing.write_text(
                json.dumps(
                    {
                        "assets": [
                            {"name": "pktpath-windows-x64-cordis-wave1-4c89a054.zip", "size": 100},
                            {"name": "pktpath-linux-x64-cordis-wave1-4c89a054.tar.gz", "size": 200},
                            {"name": "SHA256SUMS.txt", "size": 50},
                        ]
                    }
                ),
                encoding="utf-8",
            )
            r = run_cli(
                "check-existing",
                "--dist-dir", str(dist),
                "--release-exists", "true",
                "--existing-assets-json", str(existing),
                "--event-name", "push",
                "--allow-existing-release", "false",
            )
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(r.stdout.strip(), "skip")
            self.assertIn("skipping automatic 'push' upload", r.stderr)

    def test_workflow_dispatch_fails_closed_without_allow_existing_release(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            dist = root / "dist"
            dist.mkdir()
            populate_dist(dist)
            existing = root / "existing.json"
            existing.write_text(
                json.dumps({"assets": [{"name": "pktpath-windows-x64-preview-cordis-test.zip"}]}),
                encoding="utf-8",
            )
            r = run_cli(
                "check-existing",
                "--dist-dir", str(dist),
                "--release-exists", "true",
                "--existing-assets-json", str(existing),
                "--event-name", "workflow_dispatch",
                "--allow-existing-release", "false",
            )
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("allow_existing_release=true", r.stderr)

    def test_conflicting_windows_zip_name_blocked_even_with_allow_existing(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            dist = root / "dist"
            dist.mkdir()
            populate_dist(dist, tag="preview-cordis-20261127-wave1")
            existing = root / "existing.json"
            existing.write_text(
                json.dumps(
                    {
                        "assets": [
                            {"name": "pktpath-windows-x64-cordis-wave1-4c89a054.zip"},
                            {"name": "SHA256SUMS.txt"},
                        ]
                    }
                ),
                encoding="utf-8",
            )
            r = run_cli(
                "check-existing",
                "--dist-dir", str(dist),
                "--release-exists", "true",
                "--existing-assets-json", str(existing),
                "--event-name", "workflow_dispatch",
                "--allow-existing-release", "true",
            )
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("Refusing to leave two Windows zips", r.stderr)

    def test_conflicting_linux_tarball_name_blocked_even_with_allow_existing(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            dist = root / "dist"
            dist.mkdir()
            populate_dist(dist, tag="preview-cordis-20261127-wave1")
            existing = root / "existing.json"
            existing.write_text(
                json.dumps(
                    {
                        "assets": [
                            {"name": "pktpath-linux-x64-cordis-wave1-4c89a054.tar.gz"},
                        ]
                    }
                ),
                encoding="utf-8",
            )
            r = run_cli(
                "check-existing",
                "--dist-dir", str(dist),
                "--release-exists", "true",
                "--existing-assets-json", str(existing),
                "--event-name", "workflow_dispatch",
                "--allow-existing-release", "true",
            )
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("Refusing to leave two Linux tarballs", r.stderr)

    def test_missing_linux_bundle_rejected_p1_14(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            dist = Path(td) / "dist"
            dist.mkdir()
            (dist / "pktpath-windows-x64-preview-test.zip").write_bytes(b"win")
            r = run_cli(
                "check-existing",
                "--dist-dir", str(dist),
                "--release-exists", "false",
                "--event-name", "push",
            )
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("missing Linux Studio bundle", r.stderr)

    def test_merge_reconciles_extra_existing_asset_and_verifies_sizes(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            all_dir = root / "all"
            all_dir.mkdir()
            populate_dist(all_dir, tag="preview-cordis-r2")
            (all_dir / "EXTRA-NOTES.txt").write_bytes(b"preserved-note")
            (all_dir / "SHA256SUMS.txt").write_bytes(b"stale-sums")

            post_assets = [
                {"name": p.name, "size": p.stat().st_size}
                for p in sorted(all_dir.iterdir())
            ]
            post_json = root / "post.json"
            post_json.write_text(json.dumps({"assets": post_assets}), encoding="utf-8")

            sums_out = root / "SHA256SUMS.txt"
            r = run_cli(
                "build-sums",
                "--assets-dir", str(all_dir),
                "--expected-assets-json", str(post_json),
                "--out", str(sums_out),
            )
            self.assertEqual(r.returncode, 0, r.stderr)
            lines = sums_out.read_text(encoding="ascii").strip().splitlines()
            names = [line.split("  ", 1)[1] for line in lines]
            self.assertIn("EXTRA-NOTES.txt", names)
            self.assertNotIn("SHA256SUMS.txt", names)
            self.assertEqual(len(lines), 6)

            # Corrupt size in post_json -> must fail closed.
            post_assets[0]["size"] += 1
            post_json.write_text(json.dumps({"assets": post_assets}), encoding="utf-8")
            r_bad = run_cli(
                "build-sums",
                "--assets-dir", str(all_dir),
                "--expected-assets-json", str(post_json),
                "--out", str(sums_out),
            )
            self.assertNotEqual(r_bad.returncode, 0)
            self.assertIn("size mismatch", r_bad.stderr)


if __name__ == "__main__":
    unittest.main()
