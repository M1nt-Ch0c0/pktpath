#!/usr/bin/env python3
"""Build script for pktpath native device collectors:
- bin/pktpath-android-arm64  (Android arm64 via Android NDK)
- bin/pktpath-linux-x86_64   (Linux x86_64 via native gcc/clang or WSL gcc)
- bin/pktpath-linux-arm64    (optional Linux arm64 via aarch64-linux-gnu-gcc if available)
"""

from __future__ import annotations

import argparse
import os
import platform
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
        "Install Android NDK or set PKTPATH_NDK_CLANG."
    )


def win_to_wsl_path(p: Path) -> str:
    s = str(p.resolve())
    if len(s) >= 2 and s[1] == ":":
        drive = s[0].lower()
        rest = s[2:].replace("\\", "/")
        return f"/mnt/{drive}{rest}"
    return s.replace("\\", "/")


def build_android_arm64(root_dir: Path, c_sources: list[Path], bin_dir: Path) -> Path:
    out_bin = bin_dir / "pktpath-android-arm64"
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
        *(str(p) for p in c_sources),
        "-o",
        str(out_bin),
    ]
    print("Compiling [android-arm64]:", " ".join(cmd))
    subprocess.run(cmd, check=True)
    print(f"BUILD_OK: {out_bin} ({out_bin.stat().st_size} bytes)")
    return out_bin


def build_linux_x86_64(root_dir: Path, c_sources: list[Path], bin_dir: Path, optional: bool = False) -> Path | None:
    out_bin = bin_dir / "pktpath-linux-x86_64"
    if platform.system() == "Linux":
        cc = shutil.which("gcc") or shutil.which("clang")
        if not cc:
            if optional:
                print("SKIP [linux-x86_64]: gcc/clang not found")
                return None
            raise FileNotFoundError("gcc or clang not found")
        cmd = [
            cc,
            "-std=gnu11",
            "-O2",
            "-Wall",
            "-Werror",
            "-Wno-format-truncation",
            f"-I{root_dir / 'include'}",
            f"-I{root_dir / 'device'}",
            f"-I{root_dir / 'bpf'}",
            *(str(p) for p in c_sources),
            "-o",
            str(out_bin),
        ]
        print("Compiling [linux-x86_64]:", " ".join(cmd))
        subprocess.run(cmd, check=True)
        print(f"BUILD_OK: {out_bin} ({out_bin.stat().st_size} bytes)")
        return out_bin

    # Windows host: compile via WSL gcc if available
    wsl = shutil.which("wsl")
    if not wsl:
        if optional:
            print("SKIP [linux-x86_64]: wsl.exe not found on Windows")
            return None
        raise FileNotFoundError("wsl.exe not found; cannot cross-compile linux-x86_64 on Windows")

    inc = win_to_wsl_path(root_dir / "include")
    dev = win_to_wsl_path(root_dir / "device")
    bpf = win_to_wsl_path(root_dir / "bpf")
    out_wsl = win_to_wsl_path(out_bin)
    srcs = [win_to_wsl_path(p) for p in c_sources]
    cmd = [
        wsl,
        "-e",
        "gcc",
        "-std=gnu11",
        "-O2",
        "-Wall",
        "-Werror",
        "-Wno-format-truncation",
        "-static",
        f"-I{inc}",
        f"-I{dev}",
        f"-I{bpf}",
        *srcs,
        "-o",
        out_wsl,
    ]
    print("Compiling [linux-x86_64 via WSL]:", " ".join(cmd))
    r = subprocess.run(cmd)
    if r.returncode != 0:
        # Retry dynamically linked if libc-static is unavailable
        cmd_dyn = [c for c in cmd if c != "-static"]
        r = subprocess.run(cmd_dyn)
    if r.returncode != 0:
        if optional:
            print("SKIP [linux-x86_64]: WSL gcc build failed")
            return None
        raise subprocess.CalledProcessError(r.returncode, cmd)
    print(f"BUILD_OK: {out_bin} ({out_bin.stat().st_size} bytes)")
    return out_bin


def build_linux_arm64(root_dir: Path, c_sources: list[Path], bin_dir: Path, optional: bool = True) -> Path | None:
    out_bin = bin_dir / "pktpath-linux-arm64"
    if platform.system() == "Linux":
        cc = shutil.which("aarch64-linux-gnu-gcc")
        if not cc:
            if optional:
                print("SKIP [linux-arm64]: aarch64-linux-gnu-gcc not found")
                return None
            raise FileNotFoundError("aarch64-linux-gnu-gcc not found")
        cmd = [
            cc,
            "-std=gnu11",
            "-O2",
            "-Wall",
            "-Werror",
            "-Wno-format-truncation",
            f"-I{root_dir / 'include'}",
            f"-I{root_dir / 'device'}",
            f"-I{root_dir / 'bpf'}",
            *(str(p) for p in c_sources),
            "-o",
            str(out_bin),
        ]
        subprocess.run(cmd, check=True)
        print(f"BUILD_OK: {out_bin} ({out_bin.stat().st_size} bytes)")
        return out_bin

    wsl = shutil.which("wsl")
    if wsl:
        chk = subprocess.run([wsl, "-e", "sh", "-c", "command -v aarch64-linux-gnu-gcc >/dev/null 2>&1"])
        if chk.returncode == 0:
            inc = win_to_wsl_path(root_dir / "include")
            dev = win_to_wsl_path(root_dir / "device")
            bpf = win_to_wsl_path(root_dir / "bpf")
            out_wsl = win_to_wsl_path(out_bin)
            srcs = [win_to_wsl_path(p) for p in c_sources]
            cmd = [
                wsl, "-e", "aarch64-linux-gnu-gcc",
                "-std=gnu11", "-O2", "-Wall", "-Werror",
                f"-I{inc}", f"-I{dev}", f"-I{bpf}", *srcs, "-o", out_wsl,
            ]
            subprocess.run(cmd, check=True)
            print(f"BUILD_OK: {out_bin} ({out_bin.stat().st_size} bytes)")
            return out_bin
    if optional:
        print("SKIP [linux-arm64]: aarch64-linux-gnu-gcc not installed (optional)")
        return None
    raise FileNotFoundError("aarch64-linux-gnu-gcc not installed")


def main() -> int:
    ap = argparse.ArgumentParser(description="Build pktpath native collectors")
    ap.add_argument(
        "--target",
        choices=["all", "android-arm64", "linux-x86_64", "linux-arm64"],
        default="all",
        help="Target collector binary to build (default: all)",
    )
    args = ap.parse_args()

    root_dir = Path(__file__).resolve().parent.parent
    device_dir = root_dir / "device"
    bin_dir = root_dir / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)

    c_sources = sorted(device_dir.glob("*.c"))
    if not c_sources:
        print(f"ERROR: no C source files found in {device_dir}", file=sys.stderr)
        return 1

    if args.target in ("all", "android-arm64"):
        build_android_arm64(root_dir, c_sources, bin_dir)
    if args.target in ("all", "linux-x86_64"):
        build_linux_x86_64(root_dir, c_sources, bin_dir, optional=(args.target == "all"))
    if args.target in ("all", "linux-arm64"):
        build_linux_arm64(root_dir, c_sources, bin_dir, optional=(args.target == "all"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
