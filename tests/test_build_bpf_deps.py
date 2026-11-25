"""Regression tests for scripts/build_bpf.py pyelftools install hints."""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
BUILD_BPF = REPO_ROOT / "scripts" / "build_bpf.py"
REQUIREMENTS_BUILD = REPO_ROOT / "requirements-build.txt"


def load_build_bpf():
    spec = importlib.util.spec_from_file_location("pktpath_build_bpf", BUILD_BPF)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {BUILD_BPF}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestMissingElftoolsClassification(unittest.TestCase):
    def setUp(self) -> None:
        self.mod = load_build_bpf()

    def test_missing_elftools_package_is_detected(self) -> None:
        for name in ("elftools", "elftools.elf", "elftools.elf.elffile"):
            exc = ModuleNotFoundError("No module named {!r}".format(name), name=name)
            self.assertTrue(
                self.mod.is_missing_elftools_module(exc),
                msg=name,
            )

    def test_other_module_not_found_is_not_rewritten(self) -> None:
        exc = ModuleNotFoundError(
            "No module named 'definitely_not_a_real_pktpath_dep'",
            name="definitely_not_a_real_pktpath_dep",
        )
        self.assertFalse(self.mod.is_missing_elftools_module(exc))

    def test_cannot_import_name_is_not_rewritten(self) -> None:
        exc = ImportError("cannot import name 'ELFFile'")
        self.assertFalse(self.mod.is_missing_elftools_module(exc))

    def test_plain_exception_is_not_rewritten(self) -> None:
        self.assertFalse(self.mod.is_missing_elftools_module(RuntimeError("boom")))


class TestMissingElftoolsMessage(unittest.TestCase):
    def setUp(self) -> None:
        self.mod = load_build_bpf()
        self.interpreter = "/tmp/fake-python"

    def test_existing_requirements_file_uses_real_path_and_venv(self) -> None:
        self.assertTrue(REQUIREMENTS_BUILD.is_file())
        msg = self.mod.format_missing_pyelftools_message(
            interpreter=self.interpreter,
            requirements_file=REQUIREMENTS_BUILD,
            windows=False,
        )
        real = str(REQUIREMENTS_BUILD.resolve())
        self.assertIn("error: pyelftools is not installed", msg)
        self.assertIn("interpreter: /tmp/fake-python", msg)
        self.assertIn(real, msg)
        self.assertIn('"/tmp/fake-python" -m venv .venv', msg)
        self.assertIn('"{0}/bin/python" -m pip install -r "{1}"'.format(".venv", real), msg)
        self.assertNotIn("--break-system-packages", msg)
        self.assertNotIn("sudo pip", msg)
        self.assertIn("PEP 668", msg)
        self.assertIn("not executed", msg.lower())
        self.assertIn("pyelftools==0.33", msg)

    def test_missing_requirements_file_does_not_invent_a_path(self) -> None:
        missing = REPO_ROOT / "definitely-not-requirements-build.txt"
        self.assertFalse(missing.exists())
        msg = self.mod.format_missing_pyelftools_message(
            interpreter=self.interpreter,
            requirements_file=missing,
            windows=False,
        )
        self.assertIn("has no requirements-build.txt", msg)
        self.assertNotIn(str(missing.resolve()), msg)
        self.assertNotIn("-r ", msg)
        self.assertIn('"/tmp/fake-python" -m venv .venv', msg)
        self.assertIn('pip install "pyelftools==0.33"', msg)
        self.assertNotIn("--break-system-packages", msg)

    def test_windows_shape_is_marked_untested_when_requested(self) -> None:
        msg = self.mod.format_missing_pyelftools_message(
            interpreter=r"C:\\Python\\python.exe",
            requirements_file=REQUIREMENTS_BUILD,
            windows=True,
        )
        self.assertIn(r".venv\Scripts\python.exe", msg)
        self.assertIn(r"scripts\build_bpf.py", msg)
        self.assertIn("not executed as a tested Windows matrix", msg)
        self.assertNotIn(".venv/bin/python", msg)


class TestBuildBpfEntrypoint(unittest.TestCase):
    def _run(self, env, cwd=None, extra_pythonpath=None):
        run_env = os.environ.copy()
        run_env["PYTHONNOUSERSITE"] = "1"
        # Drop inherited PYTHONPATH unless the test injects a fixture.
        run_env.pop("PYTHONPATH", None)
        if extra_pythonpath is not None:
            run_env["PYTHONPATH"] = extra_pythonpath
        run_env.update(env)
        return subprocess.run(
            [sys.executable, str(BUILD_BPF)],
            cwd=str(cwd or REPO_ROOT),
            capture_output=True,
            text=True,
            env=run_env,
            check=False,
        )

    def test_script_missing_elftools_prints_hint_without_traceback(self) -> None:
        # -S skips site-packages so this fails closed even when the runner
        # already has pyelftools installed (as a developer venv might).
        isolated = os.environ.copy()
        isolated["PYTHONNOUSERSITE"] = "1"
        isolated.pop("PYTHONPATH", None)
        proc = subprocess.run(
            [sys.executable, "-S", str(BUILD_BPF)],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            env=isolated,
            check=False,
        )
        self.assertEqual(proc.returncode, 1)
        self.assertNotIn("Traceback", proc.stderr)
        self.assertIn("error: pyelftools is not installed", proc.stderr)
        self.assertIn("interpreter:", proc.stderr)
        self.assertIn(sys.executable, proc.stderr)
        if REQUIREMENTS_BUILD.is_file():
            self.assertIn(str(REQUIREMENTS_BUILD.resolve()), proc.stderr)
            self.assertIn("-r ", proc.stderr)
        else:
            self.assertIn("has no requirements-build.txt", proc.stderr)
            self.assertIn("pyelftools==0.33", proc.stderr)
        self.assertNotIn("--break-system-packages", proc.stderr)

    def test_internal_import_error_is_not_masked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            pkg = Path(tmp) / "elftools" / "elf"
            pkg.mkdir(parents=True)
            (Path(tmp) / "elftools" / "__init__.py").write_text("", encoding="utf-8")
            (pkg / "__init__.py").write_text("", encoding="utf-8")
            (pkg / "elffile.py").write_text(
                "import definitely_not_a_real_pktpath_dep\n",
                encoding="utf-8",
            )
            env = os.environ.copy()
            env["PYTHONNOUSERSITE"] = "1"
            env["PYTHONPATH"] = tmp
            proc = subprocess.run(
                [sys.executable, str(BUILD_BPF)],
                cwd=str(REPO_ROOT),
                capture_output=True,
                text=True,
                env=env,
                check=False,
            )
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("Traceback", proc.stderr)
            self.assertIn("definitely_not_a_real_pktpath_dep", proc.stderr)
            self.assertNotIn("error: pyelftools is not installed", proc.stderr)


if __name__ == "__main__":
    unittest.main()
