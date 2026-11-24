"""Validation and runtime tests for bundled external plugin examples."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
EXAMPLES_DIR = REPO_ROOT / "plugins" / "examples"


class TestExamplePlugins(unittest.TestCase):
    def test_all_example_manifests_valid_json(self) -> None:
        manifests = list(EXAMPLES_DIR.rglob("*.json"))
        self.assertGreaterEqual(len(manifests), 4)
        for mf in manifests:
            doc = json.loads(mf.read_text(encoding="utf-8"))
            self.assertIsInstance(doc, dict, f"{mf} must be a JSON object")
            self.assertTrue(doc.get("name"), f"{mf} missing name")

    def test_hello_ext_bundle_hook_analyze_and_export(self) -> None:
        hook = EXAMPLES_DIR / "hello-ext-bundle" / "hook.py"
        self.assertTrue(hook.is_file())

        overview = {
            "samples": [
                {"sample_id": 1, "comm": "ping", "proto": "icmp", "max_sojourn_us": 12000, "endpoint": "TX_OK", "path_sig": "ENTRY -> NETEM -> TX_OK"},
                {"sample_id": 2, "comm": "curl", "proto": "tcp", "max_sojourn_us": 800, "endpoint": "TX_OK", "path_sig": "ENTRY -> FQ_CODEL -> TX_OK"},
            ]
        }

        # 1. Analyze action
        req_an = {
            "action": "analyze",
            "plugin_id": "example.sla-auditor",
            "config": {"latency_budget_ms": 5.0},
            "overview": overview,
        }
        r1 = subprocess.run(
            [sys.executable, str(hook)],
            input=json.dumps(req_an),
            capture_output=True,
            text=True,
            check=True,
            timeout=15,
        )
        out_an = json.loads(r1.stdout)
        self.assertEqual(len(out_an["insights"]), 1)
        self.assertEqual(out_an["insights"][0]["sample_ids"], [1])
        self.assertEqual(len(out_an["kpis"]), 1)
        self.assertIn("50.0%", out_an["kpis"][0]["value"])

        # 2. Export action
        with tempfile.TemporaryDirectory() as td:
            out_md = Path(td) / "sla.md"
            req_ex = {
                "action": "export",
                "plugin_id": "example.sla-auditor",
                "session_id": "test_sess",
                "out_path": str(out_md),
                "config": {"latency_budget_ms": 5.0, "report_title": "CI SLA Test"},
                "overview": overview,
            }
            r2 = subprocess.run(
                [sys.executable, str(hook)],
                input=json.dumps(req_ex),
                capture_output=True,
                text=True,
                check=True,
                timeout=15,
            )
            out_ex = json.loads(r2.stdout)
            self.assertTrue(out_ex["ok"])
            self.assertTrue(out_md.is_file())
            txt = out_md.read_text(encoding="utf-8")
            self.assertIn("# CI SLA Test", txt)
            self.assertIn("50.00%", txt)


if __name__ == "__main__":
    unittest.main()
