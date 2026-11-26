#!/usr/bin/env python3
"""Assemble a self-contained PktPath Cordis preview bundle for a target OS.

Unified per-OS layout (same feature set across OSes):
  Windows (--os windows):
    pktpath-studio.exe
    node/node.exe
    node/LICENSE
    cordis-analyzer-host/  (plugin-runtime.mjs, cleanup-wait.mjs, host.mjs,
                            lifecycle.mjs, package.json, package-lock.json,
                            node_modules/)
    collectors/            (pktpath-android-arm64, optional linux collectors)
    start-studio.cmd       (fail-closed launcher; no PATH fallback)
    start-studio.ps1       (fail-closed launcher; no PATH fallback)
    MANIFEST.sha256

  Linux (--os linux):
    pktpath-studio
    node/bin/node
    node/LICENSE
    cordis-analyzer-host/
    collectors/
    start-studio.sh        (fail-closed launcher; no PATH fallback)
    MANIFEST.sha256

Does not push, tag, or publish.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import stat
import tarfile
import urllib.request
import zipfile
from pathlib import Path

NODE_VERSION = "v24.22.1"
OFFICIAL_NODE = {
    "windows": {
        "filename": f"node-{NODE_VERSION}-win-x64.zip",
        "url": f"https://nodejs.org/dist/{NODE_VERSION}/node-{NODE_VERSION}-win-x64.zip",
        "sha256": "d2046d28c2c3dcd211ac5145c0bf30e2047ef9dfb306693c8c6e2eccd8b95fa5",
        "node_member": f"node-{NODE_VERSION}-win-x64/node.exe",
        "license_member": f"node-{NODE_VERSION}-win-x64/LICENSE",
        "bundle_node_rel": "node/node.exe",
    },
    "linux": {
        "filename": f"node-{NODE_VERSION}-linux-x64.tar.xz",
        "url": f"https://nodejs.org/dist/{NODE_VERSION}/node-{NODE_VERSION}-linux-x64.tar.xz",
        "sha256": "6c172a9ab6718f7b801fb5a7bd486af2ee5e32758086a04b84fcce2aa77095e6",
        "node_member": f"node-{NODE_VERSION}-linux-x64/bin/node",
        "license_member": f"node-{NODE_VERSION}-linux-x64/LICENSE",
        "bundle_node_rel": "node/bin/node",
    },
}

HOST_REQUIRED_FILES = [
    "plugin-runtime.mjs",
    "cleanup-wait.mjs",
    "host.mjs",
    "lifecycle.mjs",
    "package.json",
    "package-lock.json",
]

START_STUDIO_CMD = """@echo off
setlocal EnableExtensions DisableDelayedExpansion
rem Fail-closed PktPath Studio launcher (Cordis default host).
rem Refuses to start if packaged Node, host, or @cordisjs/core is missing.
rem Never falls back to PATH Node.

set "HERE=%~dp0"
if "%HERE:~-1%"=="\\" set "HERE=%HERE:~0,-1%"

set "BIN=%HERE%\\pktpath-studio.exe"
set "NODE=%HERE%\\node\\node.exe"
set "HOSTJS=%HERE%\\cordis-analyzer-host\\plugin-runtime.mjs"
set "WAITJS=%HERE%\\cordis-analyzer-host\\cleanup-wait.mjs"

if not exist "%BIN%" (
  echo pktpath-studio.exe missing in bundle >&2
  exit /b 1
)
if not exist "%NODE%" (
  echo packaged Windows x64 Node missing ^(node\\node.exe^); no PATH fallback >&2
  exit /b 1
)
if not exist "%HOSTJS%" (
  echo packaged Cordis plugin runtime missing ^(cordis-analyzer-host\\plugin-runtime.mjs^) >&2
  exit /b 1
)
if not exist "%WAITJS%" (
  echo packaged Cordis cleanup-wait module missing ^(cordis-analyzer-host\\cleanup-wait.mjs^) >&2
  exit /b 1
)

pushd "%HERE%\\cordis-analyzer-host" >nul
"%NODE%" --input-type=module -e "await import('@cordisjs/core')"
set "IMPERR=%ERRORLEVEL%"
popd >nul
if not "%IMPERR%"=="0" (
  echo packaged Cordis host cannot import @cordisjs/core with packaged Node >&2
  exit /b 1
)

"%BIN%" --cordis-plugin-runtime "%HOSTJS%" --cordis-analyzer-node "%NODE%" %*
exit /b %ERRORLEVEL%
"""

START_STUDIO_PS1 = """# Fail-closed PktPath Studio launcher (Cordis default host).
# Refuses to start if packaged Node, host, or @cordisjs/core is missing.
# Never falls back to PATH Node.
$ErrorActionPreference = "Stop"
$here = $PSScriptRoot

function Fail([int]$code, [string]$message) {
    [Console]::Error.WriteLine($message)
    exit $code
}

$bin = Join-Path $here "pktpath-studio.exe"
$node = Join-Path $here "node\\node.exe"
$hostjs = Join-Path $here "cordis-analyzer-host\\plugin-runtime.mjs"
$waitjs = Join-Path $here "cordis-analyzer-host\\cleanup-wait.mjs"

if (-not (Test-Path -LiteralPath $bin -PathType Leaf)) {
    Fail 1 "pktpath-studio.exe missing in bundle"
}
if (-not (Test-Path -LiteralPath $node -PathType Leaf)) {
    Fail 1 "packaged Windows x64 Node missing (node\\node.exe); no PATH fallback"
}
if (-not (Test-Path -LiteralPath $hostjs -PathType Leaf)) {
    Fail 1 "packaged Cordis plugin runtime missing (cordis-analyzer-host\\plugin-runtime.mjs)"
}
if (-not (Test-Path -LiteralPath $waitjs -PathType Leaf)) {
    Fail 1 "packaged Cordis cleanup-wait module missing (cordis-analyzer-host\\cleanup-wait.mjs)"
}

$import = Start-Process -FilePath $node -ArgumentList @("--input-type=module", "-e", "await import('@cordisjs/core')") -WorkingDirectory (Join-Path $here "cordis-analyzer-host") -NoNewWindow -Wait -PassThru
if ($import.ExitCode -ne 0) {
    Fail 1 "packaged Cordis host cannot import @cordisjs/core with packaged Node"
}

$forward = @("--cordis-plugin-runtime", $hostjs, "--cordis-analyzer-node", $node) + $args
$proc = Start-Process -FilePath $bin -ArgumentList $forward -NoNewWindow -Wait -PassThru
exit $proc.ExitCode
"""

START_STUDIO_SH = """#!/usr/bin/env bash
# Fail-closed PktPath Studio launcher (Cordis default host).
# Refuses to start if packaged Node, host, or @cordisjs/core is missing.
# Never falls back to PATH Node.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$HERE/pktpath-studio"
NODE="$HERE/node/bin/node"
HOSTJS="$HERE/cordis-analyzer-host/plugin-runtime.mjs"
WAITJS="$HERE/cordis-analyzer-host/cleanup-wait.mjs"

if [[ ! -x "$BIN" ]]; then
  echo "pktpath-studio missing or not executable in bundle" >&2
  exit 1
fi
if [[ ! -x "$NODE" ]]; then
  echo "packaged Linux x64 Node missing (node/bin/node); no PATH fallback" >&2
  exit 1
fi
if [[ ! -f "$HOSTJS" || ! -f "$WAITJS" ]]; then
  echo "packaged Cordis host module missing" >&2
  exit 1
fi

(cd "$HERE/cordis-analyzer-host" && "$NODE" --input-type=module -e "await import('@cordisjs/core')") || {
  echo "packaged Cordis host cannot import @cordisjs/core with packaged Node" >&2
  exit 1
}

exec "$BIN" --cordis-plugin-runtime "$HOSTJS" --cordis-analyzer-node "$NODE" "$@"
"""


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fp:
        for chunk in iter(lambda: fp.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def ensure_node_archive(target_os: str, archive_arg: str | None, cache_dir: Path | None, download: bool) -> Path:
    spec = OFFICIAL_NODE[target_os]
    if archive_arg:
        archive = Path(archive_arg).resolve()
        if not archive.is_file():
            raise FileNotFoundError(f"Node archive not found: {archive}")
    else:
        if cache_dir is None:
            raise ValueError("Either --node-archive or --cache-dir with --download-node is required")
        cache_dir.mkdir(parents=True, exist_ok=True)
        archive = cache_dir / spec["filename"]
        if not archive.is_file():
            if not download:
                raise FileNotFoundError(f"Cached Node archive not found and --download-node not set: {archive}")
            tmp = archive.with_suffix(archive.suffix + ".part")
            urllib.request.urlretrieve(spec["url"], tmp)
            tmp.replace(archive)

    actual = sha256_file(archive)
    if actual != spec["sha256"]:
        raise ValueError(
            f"SHA-256 mismatch for {archive.name}: expected {spec['sha256']}, got {actual}"
        )
    return archive


def extract_node(target_os: str, archive: Path, bundle_dir: Path) -> None:
    spec = OFFICIAL_NODE[target_os]
    node_out = bundle_dir / spec["bundle_node_rel"]
    lic_out = bundle_dir / "node" / "LICENSE"
    node_out.parent.mkdir(parents=True, exist_ok=True)
    lic_out.parent.mkdir(parents=True, exist_ok=True)

    if target_os == "windows":
        with zipfile.ZipFile(archive) as zf:
            for member, dst in ((spec["node_member"], node_out), (spec["license_member"], lic_out)):
                with zf.open(member) as src, dst.open("wb") as out:
                    shutil.copyfileobj(src, out)
    else:
        with tarfile.open(archive, "r:xz") as tf:
            for member, dst in ((spec["node_member"], node_out), (spec["license_member"], lic_out)):
                f = tf.extractfile(member)
                if f is None:
                    raise FileNotFoundError(f"Missing {member} in {archive}")
                with f, dst.open("wb") as out:
                    shutil.copyfileobj(f, out)
        node_out.chmod(node_out.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def check_binary_magic(path: Path, target_os: str) -> None:
    with path.open("rb") as fp:
        head = fp.read(4)
    if target_os == "windows":
        if head[:2] != b"MZ":
            raise ValueError(f"Expected Windows PE (MZ) binary, got {head!r}: {path}")
    else:
        if head != b"\x7fELF":
            raise ValueError(f"Expected Linux ELF binary, got {head!r}: {path}")


def copy_cordis_host(host_dir: Path, dst_dir: Path) -> None:
    dst_dir.mkdir(parents=True, exist_ok=True)
    for name in HOST_REQUIRED_FILES:
        src = host_dir / name
        if not src.is_file():
            raise FileNotFoundError(f"Missing Cordis host file: {src}")
        shutil.copy2(src, dst_dir / name)

    nm_src = host_dir / "node_modules"
    cordis_pkg = nm_src / "@cordisjs" / "core" / "package.json"
    if not cordis_pkg.is_file():
        raise FileNotFoundError(
            f"Missing @cordisjs/core in {nm_src}; run 'npm ci --ignore-scripts --omit=dev' in {host_dir} first"
        )
    shutil.copytree(nm_src, dst_dir / "node_modules", symlinks=False)


def copy_collectors(collectors_dir: Path, dst_dir: Path) -> list[str]:
    dst_dir.mkdir(parents=True, exist_ok=True)
    copied: list[str] = []
    specs = [
        ("pktpath-android-arm64", True),
        ("pktpath-linux-x86_64", False),
        ("pktpath-linux-arm64", False),
    ]
    for name, required in specs:
        src = collectors_dir / name
        if not src.is_file():
            if required:
                raise FileNotFoundError(f"Required collector binary missing: {src}")
            continue
        shutil.copy2(src, dst_dir / name)
        copied.append(name)
    return copied


def write_launchers(target_os: str, bundle_dir: Path) -> None:
    if target_os == "windows":
        (bundle_dir / "start-studio.cmd").write_bytes(
            START_STUDIO_CMD.replace("\r\n", "\n").replace("\n", "\r\n").encode("utf-8")
        )
        (bundle_dir / "start-studio.ps1").write_bytes(
            START_STUDIO_PS1.replace("\r\n", "\n").replace("\n", "\r\n").encode("utf-8")
        )
    else:
        sh_path = bundle_dir / "start-studio.sh"
        sh_path.write_bytes(START_STUDIO_SH.replace("\r\n", "\n").encode("utf-8"))
        sh_path.chmod(sh_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def write_manifest(bundle_dir: Path) -> int:
    rows: list[str] = []
    for path in sorted(bundle_dir.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(bundle_dir).as_posix()
        if rel == "MANIFEST.sha256":
            continue
        rows.append(f"{sha256_file(path)}  {rel}")
    (bundle_dir / "MANIFEST.sha256").write_text("\n".join(rows) + "\n", encoding="utf-8")
    return len(rows)


def create_archive(target_os: str, bundle_dir: Path, out_dir: Path) -> Path:
    if target_os == "windows":
        archive_path = out_dir / f"{bundle_dir.name}.zip"
        if archive_path.exists():
            archive_path.unlink()
        with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
            for path in sorted(bundle_dir.rglob("*")):
                if not path.is_file():
                    continue
                arc = f"{bundle_dir.name}/{path.relative_to(bundle_dir).as_posix()}"
                info = zipfile.ZipInfo(arc, date_time=(2026, 11, 26, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                zf.writestr(info, path.read_bytes())
        return archive_path

    archive_path = out_dir / f"{bundle_dir.name}.tar.gz"
    if archive_path.exists():
        archive_path.unlink()
    with tarfile.open(archive_path, "w:gz") as tf:
        for path in sorted(bundle_dir.rglob("*")):
            if not path.is_file():
                continue
            arc = f"{bundle_dir.name}/{path.relative_to(bundle_dir).as_posix()}"
            tf.add(path, arcname=arc, recursive=False)
    return archive_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Assemble PktPath Cordis preview bundle")
    parser.add_argument("--os", dest="target_os", choices=["windows", "linux"], default="windows")
    parser.add_argument("--studio-bin", required=True, help="Compiled pktpath-studio(.exe) binary")
    parser.add_argument("--collectors-dir", required=True, help="Directory with compiled collector binaries")
    parser.add_argument("--host-dir", default="studio/cordis-analyzer-host", help="Cordis host directory with node_modules")
    parser.add_argument("--node-archive", default=None, help="Path to pre-downloaded official Node archive")
    parser.add_argument("--cache-dir", default=None, help="Cache directory for official Node archive")
    parser.add_argument("--download-node", action="store_true", help="Download official Node archive if missing from cache")
    parser.add_argument("--out-dir", required=True, help="Output directory for bundle folder and archive")
    parser.add_argument("--bundle-name", required=True, help="Bundle directory and archive stem name")
    parser.add_argument("--keep-dir", action="store_true", help="Keep unpacked bundle directory beside archive")
    args = parser.parse_args(argv)

    studio_bin = Path(args.studio_bin).resolve()
    collectors_dir = Path(args.collectors_dir).resolve()
    host_dir = Path(args.host_dir).resolve()
    out_dir = Path(args.out_dir).resolve()
    cache_dir = Path(args.cache_dir).resolve() if args.cache_dir else None

    if not studio_bin.is_file():
        raise FileNotFoundError(f"Studio binary not found: {studio_bin}")
    check_binary_magic(studio_bin, args.target_os)

    node_archive = ensure_node_archive(args.target_os, args.node_archive, cache_dir, args.download_node)

    out_dir.mkdir(parents=True, exist_ok=True)
    bundle_dir = out_dir / args.bundle_name
    if bundle_dir.exists():
        shutil.rmtree(bundle_dir)
    bundle_dir.mkdir(parents=True, exist_ok=True)

    dst_studio = bundle_dir / ("pktpath-studio.exe" if args.target_os == "windows" else "pktpath-studio")
    shutil.copy2(studio_bin, dst_studio)
    if args.target_os == "linux":
        dst_studio.chmod(dst_studio.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    extract_node(args.target_os, node_archive, bundle_dir)
    check_binary_magic(bundle_dir / OFFICIAL_NODE[args.target_os]["bundle_node_rel"], args.target_os)
    copy_cordis_host(host_dir, bundle_dir / "cordis-analyzer-host")
    copied_collectors = copy_collectors(collectors_dir, bundle_dir / "collectors")
    write_launchers(args.target_os, bundle_dir)
    file_count = write_manifest(bundle_dir)
    archive_path = create_archive(args.target_os, bundle_dir, out_dir)

    if not args.keep_dir:
        shutil.rmtree(bundle_dir)

    summary = {
        "ok": True,
        "target_os": args.target_os,
        "node_version": NODE_VERSION,
        "node_archive_sha256": OFFICIAL_NODE[args.target_os]["sha256"],
        "collectors": copied_collectors,
        "manifest_entries": file_count,
        "archive_path": str(archive_path),
        "archive_size_bytes": archive_path.stat().st_size,
        "archive_sha256": sha256_file(archive_path),
    }
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
