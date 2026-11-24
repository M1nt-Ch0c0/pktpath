#!/usr/bin/env python3
"""Build script for pktpath v3 Android arm64 native device controller & recorder."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path


def find_ndk_clang() -> str:
    env_override = os.environ.get("PKTPATH_NDK_CLANG")
    if env_override and Path(env_override).exists():
        return env_override

    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        preferred = (
            Path(local_app_data)
            / "Android/Sdk/ndk/28.1.13356709/toolchains/llvm/prebuilt/windows-x86_64/bin/aarch64-linux-android28-clang.cmd"
        )
        if preferred.exists():
            return str(preferred)

        sdk_ndk = Path(local_app_data) / "Android/Sdk/ndk"
        if sdk_ndk.is_dir():
            matches = sorted(
                sdk_ndk.glob("*/toolchains/llvm/prebuilt/*/bin/aarch64-linux-android28-clang*"),
                reverse=True,
            )
            if matches:
                return str(matches[0])

    for env_key in ("ANDROID_NDK_HOME", "ANDROID_NDK_ROOT"):
        ndk_root = os.environ.get(env_key)
        if ndk_root and Path(ndk_root).is_dir():
            matches = sorted(
                Path(ndk_root).glob("toolchains/llvm/prebuilt/*/bin/aarch64-linux-android28-clang*")
            )
            if matches:
                return str(matches[0])

    which_clang = shutil.which("aarch64-linux-android28-clang")
    if which_clang:
        return which_clang

    raise FileNotFoundError(
        "Could not locate aarch64-linux-android28-clang(.cmd). "
        "Install Android NDK 28.1.13356709 or set PKTPATH_NDK_CLANG."
    )


def main() -> int:
    root_dir = Path(__file__).resolve().parent.parent
    device_dir = root_dir / "device"
    bin_dir = root_dir / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)

    out_bin = bin_dir / "pktpath-android-arm64"
    c_sources = sorted(str(p) for p in device_dir.glob("*.c"))
    if not c_sources:
        print(f"ERROR: no C source files found in {device_dir}", file=sys.stderr)
        return 1

    clang = find_ndk_clang()
    cmd = [
        clang,
        "-std=gnu11",
        "-O2",
        "-Wall",
        "-Werror",
        f"-I{root_dir / 'include'}",
        f"-I{root_dir / 'device'}",
        f"-I{root_dir / 'bpf'}",
        *c_sources,
        "-o",
        str(out_bin),
    ]

    print("Compiling:", " ".join(cmd))
    subprocess.run(cmd, check=True)
    size = out_bin.stat().st_size
    print(f"BUILD_OK: {out_bin} ({size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
