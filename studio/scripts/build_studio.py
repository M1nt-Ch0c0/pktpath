#!/usr/bin/env python3
"""Windows desktop packaging script for PktPath Studio (no bundled ADB).

Stages `pktpath-android-arm64` into `studio/assets_stage/`, writes `manifest.json`
with exact SHA-256 digest, compiles `bin/pktpath-studio.exe` with
`-H=windowsgui -s -w` (zero black console window on Windows), verifies the PE
subsystem header, and cleans staged binary copies afterward.

System `adb` is discovered automatically at runtime and invoked strictly with
`HideWindow: true` + `CREATE_NO_WINDOW (0x08000000)`.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

IMAGE_SUBSYSTEM_WINDOWS_GUI = 2

SCRIPT_DIR = Path(__file__).resolve().parent
STUDIO_DIR = SCRIPT_DIR.parent
PKTPATH_DIR = STUDIO_DIR.parent
STAGE_DIR = STUDIO_DIR / "assets_stage"
DEFAULT_OUT = PKTPATH_DIR / "bin" / "pktpath-studio.exe"
DEFAULT_AGENT = PKTPATH_DIR / "bin" / "pktpath-android-arm64"


def sha256_file(path: Path) -> tuple[str, int]:
    h = hashlib.sha256()
    total = 0
    with path.open("rb") as fp:
        while True:
            chunk = fp.read(1 << 20)
            if not chunk:
                break
            h.update(chunk)
            total += len(chunk)
    return h.hexdigest(), total


def verify_pe_subsystem(exe_path: Path) -> int:
    with exe_path.open("rb") as fp:
        mz = fp.read(64)
        if len(mz) < 64 or mz[:2] != b"MZ":
            raise ValueError(f"{exe_path} is not a valid MZ/PE executable")
        (pe_offset,) = struct.unpack_from("<I", mz, 0x3C)
        fp.seek(pe_offset)
        pe_hdr = fp.read(4 + 20 + 96)
        if len(pe_hdr) < 4 + 20 + 70 or pe_hdr[:4] != b"PE\x00\x00":
            raise ValueError(f"{exe_path} missing PE\\0\\0 signature")
        (subsystem,) = struct.unpack_from("<H", pe_hdr, 24 + 68)
        return subsystem


def clean_staged_binaries(keep_placeholder: bool = True) -> None:
    STAGE_DIR.mkdir(parents=True, exist_ok=True)
    for item in STAGE_DIR.iterdir():
        if keep_placeholder and item.name == "keep.txt":
            continue
        if item.is_dir():
            shutil.rmtree(item)
        else:
            item.unlink()
    if keep_placeholder:
        keep = STAGE_DIR / "keep.txt"
        if not keep.exists():
            keep.write_text(
                "Placeholder for go:embed during go vet / go build.\n",
                encoding="utf-8",
            )


def stage_assets(agent_path: Path) -> dict:
    if not agent_path.is_file():
        raise FileNotFoundError(f"Android probe binary not found: {agent_path}")

    clean_staged_binaries(keep_placeholder=True)
    dst = STAGE_DIR / "pktpath-android-arm64"
    shutil.copy2(agent_path, dst)
    digest, size = sha256_file(dst)
    manifest = {
        "built_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "files": {
            "pktpath-android-arm64": {"size": size, "sha256": digest},
        },
    }
    (STAGE_DIR / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    return manifest


def build_studio(
    out_exe: Path,
    agent_path: Path,
    keep_staged: bool = False,
) -> dict:
    web_index = STUDIO_DIR / "web" / "index.html"
    if not web_index.is_file():
        raise FileNotFoundError(f"Frontend index.html missing: {web_index}")

    out_exe.parent.mkdir(parents=True, exist_ok=True)
    for stale in out_exe.parent.glob(f"{out_exe.name}.old*"):
        try:
            stale.unlink()
        except OSError:
            pass

    manifest = stage_assets(agent_path)

    tmp_exe = out_exe.with_name(out_exe.name + ".new")
    if tmp_exe.exists():
        tmp_exe.unlink()

    env = os.environ.copy()
    env["GOOS"] = "windows"
    env["GOARCH"] = "amd64"
    env["CGO_ENABLED"] = "0"

    cmd = [
        "go",
        "build",
        "-trimpath",
        "-ldflags=-H=windowsgui -s -w",
        "-o",
        str(tmp_exe),
        "./cmd/pktpath-studio",
    ]
    renamed_running: str | None = None
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(STUDIO_DIR),
            env=env,
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            raise RuntimeError(
                f"go build failed (rc={proc.returncode}):\n{proc.stdout}\n{proc.stderr}".strip()
            )
        subsystem = verify_pe_subsystem(tmp_exe)
        if subsystem != IMAGE_SUBSYSTEM_WINDOWS_GUI:
            raise RuntimeError(
                f"Expected PE subsystem {IMAGE_SUBSYSTEM_WINDOWS_GUI} (WINDOWS_GUI), got {subsystem}"
            )
        try:
            os.replace(tmp_exe, out_exe)
        except PermissionError:
            backup = out_exe.with_name(f"{out_exe.name}.old.{int(time.time())}")
            os.replace(out_exe, backup)
            renamed_running = str(backup)
            os.replace(tmp_exe, out_exe)
    finally:
        if tmp_exe.exists():
            try:
                tmp_exe.unlink()
            except OSError:
                pass
        if not keep_staged:
            clean_staged_binaries(keep_placeholder=True)

    exe_sha, exe_size = sha256_file(out_exe)
    result = {
        "ok": True,
        "exe_path": str(out_exe),
        "exe_size_bytes": exe_size,
        "exe_size_mib": round(exe_size / (1024 * 1024), 2),
        "exe_sha256": exe_sha,
        "pe_subsystem": IMAGE_SUBSYSTEM_WINDOWS_GUI,
        "adb_embedded": False,
        "embedded_files": manifest["files"],
    }
    if renamed_running:
        result["renamed_running_exe"] = renamed_running
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build PktPath Studio Windows GUI executable (system ADB, zero console flash)"
    )
    parser.add_argument("--out", default=str(DEFAULT_OUT), help="Output .exe path")
    parser.add_argument(
        "--agent",
        default=str(DEFAULT_AGENT),
        help="Path to compiled pktpath-android-arm64 binary",
    )
    parser.add_argument(
        "--keep-staged",
        action="store_true",
        help="Keep copied binaries in studio/assets_stage/ after build",
    )
    args = parser.parse_args(argv)

    summary = build_studio(
        out_exe=Path(args.out).resolve(),
        agent_path=Path(args.agent).resolve(),
        keep_staged=args.keep_staged,
    )
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
