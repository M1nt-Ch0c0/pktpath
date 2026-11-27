import hashlib
import json
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BIN_X86 = ROOT / "bin" / "pktpath-linux-x86_64"
PWRU_DIR = ROOT / "plugins" / "official" / "pktpath-pwru-probes"

VALID_GROUPS = {
    "core_drop",
    "egress_tc",
    "sock_app",
    "ingress_rx",
    "l3_route",
    "netfilter_nat",
    "tcp_diag",
    "drop_stack",
    "tcp_probe",
}


class TestWave3CliAndPwruPlugin(unittest.TestCase):
    def test_help_lists_wave3_flags(self):
        if not BIN_X86.exists():
            self.skipTest("bin/pktpath-linux-x86_64 not built")
        res = subprocess.run([str(BIN_X86), "--help"], capture_output=True, text=True)
        out = res.stdout + res.stderr
        self.assertIn("--probe-groups", out)
        self.assertIn("--preset", out)
        self.assertIn("--preset-label", out)

    def test_preset_and_probe_groups_mutually_exclusive(self):
        if not BIN_X86.exists():
            self.skipTest("bin/pktpath-linux-x86_64 not built")
        res = subprocess.run(
            [str(BIN_X86), "record", "--dev", "lo", "--scope", "tc-egress", "--out", "/tmp/w3-out", "--preset", "egress", "--probe-groups", "core_drop,egress_tc"],
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("mutually exclusive", res.stderr)

    def test_unknown_preset_rejected(self):
        if not BIN_X86.exists():
            self.skipTest("bin/pktpath-linux-x86_64 not built")
        res = subprocess.run(
            [str(BIN_X86), "record", "--dev", "lo", "--scope", "tc-egress", "--out", "/tmp/w3-out", "--preset", "nonexistent-preset"],
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("invalid --preset", res.stderr)

    def test_unknown_probe_group_rejected(self):
        if not BIN_X86.exists():
            self.skipTest("bin/pktpath-linux-x86_64 not built")
        res = subprocess.run(
            [str(BIN_X86), "record", "--dev", "lo", "--scope", "tc-egress", "--out", "/tmp/w3-out", "--probe-groups", "core_drop,bogus_group"],
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("invalid --probe-groups", res.stderr)

    def test_pwru_plugin_manifest_and_object_hashes(self):
        mp = PWRU_DIR / "manifest.json"
        self.assertTrue(mp.exists(), f"missing {mp}")
        m = json.loads(mp.read_text(encoding="utf-8"))
        self.assertEqual(m["id"], "pktpath.pwru-probes")
        kp = m["kernel_probes"]
        self.assertEqual(kp["abi_version"], 1)
        for arch in ("arm64", "x86_64"):
            obj_entry = kp["objects"][arch]
            obj_path = PWRU_DIR / obj_entry["path"]
            self.assertTrue(obj_path.exists(), f"missing {obj_path}")
            actual_sha = hashlib.sha256(obj_path.read_bytes()).hexdigest()
            self.assertEqual(actual_sha, obj_entry["sha256"], f"sha256 mismatch for {arch}")

        hooks = kp["hooks"]
        self.assertEqual(len(hooks), 19)
        for h in hooks:
            self.assertIn(h["group"], VALID_GROUPS)
            self.assertIn(h["type"], ("kprobe", "kretprobe", "tracepoint"))
            self.assertTrue(h["sec"])
            self.assertTrue(h["target"])
            self.assertTrue(h["id"])


    def test_self_check_json_contract(self):
        if not BIN_X86.exists():
            self.skipTest("bin/pktpath-linux-x86_64 not built")
        for flag in ("--self-check", "self-check"):
            res = subprocess.run([str(BIN_X86), flag], capture_output=True, text=True)
            self.assertEqual(res.returncode, 0, f"{flag} stderr={res.stderr}")
            data = json.loads(res.stdout)
            self.assertEqual(data["schema_version"], 1)
            self.assertIn(data["status"], ("ok", "degraded", "blocked"))
            self.assertIn("btf", data)
            self.assertIn("tcp_sock_fields", data["btf"])
            self.assertIn("sysctl", data)
            self.assertIn("probes", data)
            self.assertIsInstance(data["checks"], list)
            self.assertEqual(len(data["checks"]), 5)
            for chk in data["checks"]:
                self.assertIn(chk["level"], ("green", "yellow", "red"))

if __name__ == "__main__":
    unittest.main()
