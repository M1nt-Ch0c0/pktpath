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


def write_fixture(root: Path, files: dict[str, str]) -> None:
    for rel, content in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


class TestMissingElftoolsClassification(unittest.TestCase):
    def setUp(self) -> None:
        self.mod = load_build_bpf()

    def test_missing_top_level_elftools_package_is_detected(self) -> None:
        exc = ModuleNotFoundError("No module named 'elftools'", name="elftools")
        self.assertTrue(self.mod.is_missing_elftools_module(exc))

    def test_missing_elftools_submodule_is_not_rewritten(self) -> None:
        # Package is present but incomplete or internally broken.
        for name in (
            "elftools.elf",
            "elftools.elf.elffile",
            "elftools.missing_internal_review_fixture",
        ):
            exc = ModuleNotFoundError("No module named {!r}".format(name), name=name)
            self.assertFalse(self.mod.is_missing_elftools_module(exc), msg=name)

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
        self.assertNotIn("& \"/tmp/fake-python\"", msg)
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

    def test_windows_powershell_call_operator_is_present_and_untested(self) -> None:
        interpreter = r"C:\Python With Spaces\python.exe"
        msg = self.mod.format_missing_pyelftools_message(
            interpreter=interpreter,
            requirements_file=REQUIREMENTS_BUILD,
            windows=True,
        )
        self.assertIn('& "C:\\Python With Spaces\\python.exe" -m venv .venv', msg)
        self.assertIn(r'& ".venv\Scripts\python.exe" -m pip install -r', msg)
        self.assertIn(r'& ".venv\Scripts\python.exe" scripts\build_bpf.py', msg)
        self.assertIn("PowerShell", msg)
        self.assertIn("call operator", msg)
        self.assertIn("not executed on Windows", msg)
        self.assertNotIn(".venv/bin/python", msg)


class TestBuildBpfEntrypoint(unittest.TestCase):
    def _run(self, *, pythonpath=None, isolated_no_site=False):
        run_env = os.environ.copy()
        run_env["PYTHONNOUSERSITE"] = "1"
        run_env.pop("PYTHONPATH", None)
        if pythonpath is not None:
            run_env["PYTHONPATH"] = pythonpath
        cmd = [sys.executable]
        if isolated_no_site:
            cmd.append("-S")
        cmd.append(str(BUILD_BPF))
        return subprocess.run(
            cmd,
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            env=run_env,
            check=False,
        )

    def _run_fixture(self, files: dict[str, str]):
        with tempfile.TemporaryDirectory() as tmp:
            write_fixture(Path(tmp), files)
            return self._run(pythonpath=tmp), tmp

    def test_script_missing_elftools_prints_hint_without_traceback(self) -> None:
        # -S skips site-packages so this fails closed even when the runner
        # already has pyelftools installed (as a developer venv might).
        proc = self._run(isolated_no_site=True)
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

    def test_missing_elf_subpackage_keeps_traceback(self) -> None:
        # Yan PR3 counterexample 1: top-level elftools exists, elf subpackage does not.
        proc, _ = self._run_fixture({"elftools/__init__.py": ""})
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("Traceback", proc.stderr)
        self.assertTrue(
            "elftools.elf" in proc.stderr or "No module named 'elftools.elf'" in proc.stderr,
            proc.stderr,
        )
        self.assertNotIn("error: pyelftools is not installed", proc.stderr)

    def test_missing_internal_elftools_module_keeps_traceback(self) -> None:
        # Yan PR3 counterexample 2: package imports a missing elftools submodule.
        proc, _ = self._run_fixture(
            {
                "elftools/__init__.py": "",
                "elftools/elf/__init__.py": "",
                "elftools/elf/elffile.py": "import elftools.missing_internal_review_fixture\n",
            }
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("Traceback", proc.stderr)
        self.assertIn("elftools.missing_internal_review_fixture", proc.stderr)
        self.assertNotIn("error: pyelftools is not installed", proc.stderr)

    def test_external_transitive_import_error_is_not_masked(self) -> None:
        proc, _ = self._run_fixture(
            {
                "elftools/__init__.py": "",
                "elftools/elf/__init__.py": "",
                "elftools/elf/elffile.py": "import definitely_not_a_real_pktpath_dep\n",
            }
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("Traceback", proc.stderr)
        self.assertIn("definitely_not_a_real_pktpath_dep", proc.stderr)
        self.assertNotIn("error: pyelftools is not installed", proc.stderr)

    def test_plain_importerror_is_not_masked(self) -> None:
        proc, _ = self._run_fixture(
            {
                "elftools/__init__.py": "",
                "elftools/elf/__init__.py": "",
                "elftools/elf/elffile.py": "raise ImportError('broken install review fixture')\n",
            }
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("Traceback", proc.stderr)
        self.assertIn("broken install review fixture", proc.stderr)
        self.assertNotIn("error: pyelftools is not installed", proc.stderr)

    def test_missing_elffile_symbol_is_not_masked(self) -> None:
        proc, _ = self._run_fixture(
            {
                "elftools/__init__.py": "",
                "elftools/elf/__init__.py": "",
                "elftools/elf/elffile.py": "",
            }
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("Traceback", proc.stderr)
        self.assertIn("ELFFile", proc.stderr)
        self.assertNotIn("error: pyelftools is not installed", proc.stderr)

    def test_runtime_error_inside_package_is_not_masked(self) -> None:
        proc, _ = self._run_fixture(
            {
                "elftools/__init__.py": "",
                "elftools/elf/__init__.py": "",
                "elftools/elf/elffile.py": "raise RuntimeError('package runtime review fixture')\n",
            }
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("Traceback", proc.stderr)
        self.assertIn("package runtime review fixture", proc.stderr)
        self.assertNotIn("error: pyelftools is not installed", proc.stderr)


if __name__ == "__main__":
    unittest.main()
