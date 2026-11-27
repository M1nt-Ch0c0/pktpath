#!/usr/bin/env python3
"""Assemble a self-contained pure-Cordis PktPath Studio preview bundle for a target OS.

Aligned with WAVE1-CONTRACT.md (zero Go Studio binary, zero pktpath-studio.exe):
  Windows (--os windows):
    pktpath-windows-x64-<tag>/
      node/node.exe
      node/LICENSE
      studio-cordis/
        package.json
        package-lock.json
        node_modules/          (@cordisjs/core + cosmokit, no symlinks)
        src/                   (.ts files executed directly by Node v24.22.1)
        web/                   (static frontend assets)
      collectors/
        android-arm64/pktpath  (required ELF binary)
        linux-x86_64/pktpath   (optional ELF binary)
        linux-arm64/pktpath    (optional ELF binary)
      start-studio.cmd         (fail-closed launcher; no PATH fallback)
      start-studio.ps1         (fail-closed launcher; no PATH fallback)
      LICENSE                  (repository root LICENSE)
      LICENSES/
        PKTPATH-LICENSE.txt
        NODE-LICENSE.txt
        THIRD-PARTY-NOTICES.txt
        third-party/<pkg>-LICENSE.txt
      MANIFEST.sha256

  Linux (--os linux):
    Same layout with node/bin/node, start-studio.sh, and stop-studio.sh.

Does not push, tag, or publish.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import shutil
import stat
import subprocess
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
        "node_sha256": "d702daa815eabbff763c7d3808e235cf031cf2ca70211b56847bc72f51e240e5",
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

START_STUDIO_CMD = r"""@echo off
setlocal EnableExtensions DisableDelayedExpansion
rem Primary double-click launcher for PktPath Studio (pure Cordis Node v24.22.1).
rem Extract the full zip archive before running; do not run directly from a zip preview.
rem Refuses to start if packaged Node, studio-cordis, or @cordisjs/core is missing.
rem Never falls back to PATH Node.

set "HERE=%~dp0"
if "%HERE:~-1%"=="\" set "HERE=%HERE:~0,-1%"

set "NODE=%HERE%\node\node.exe"
set "APPDIR=%HERE%\studio-cordis"
set "ENTRY=%APPDIR%\src\main.ts"
set "WEBIDX=%APPDIR%\web\index.html"
set "CORDISPKG=%APPDIR%\node_modules\@cordisjs\core\package.json"
set "COLLECTORS=%HERE%\collectors"
set "ANDROID_BIN=%COLLECTORS%\android-arm64\pktpath"

if not exist "%NODE%" (
  echo packaged Windows x64 Node missing ^(node\node.exe^); no PATH fallback >&2
  exit /b 1
)
if not exist "%ENTRY%" (
  echo packaged Cordis entry missing ^(studio-cordis\src\main.ts^) >&2
  exit /b 1
)
if not exist "%WEBIDX%" (
  echo packaged Studio web assets missing ^(studio-cordis\web\index.html^) >&2
  exit /b 1
)
if not exist "%CORDISPKG%" (
  echo packaged @cordisjs/core missing ^(studio-cordis\node_modules\@cordisjs\core\package.json^) >&2
  exit /b 1
)
if not exist "%ANDROID_BIN%" (
  echo packaged Android collector missing ^(collectors\android-arm64\pktpath^) >&2
  exit /b 1
)

pushd "%APPDIR%" >nul
"%NODE%" --input-type=module -e "await import('@cordisjs/core')"
set "IMPERR=%ERRORLEVEL%"
popd >nul
if not "%IMPERR%"=="0" (
  echo packaged Cordis runtime cannot import @cordisjs/core with packaged Node >&2
  exit /b 1
)

set "PKTPATH_CORDIS_NODE=%NODE%"
"%NODE%" "%ENTRY%" --collectors-dir "%COLLECTORS%" %*
exit /b %ERRORLEVEL%
"""

START_STUDIO_PS1 = r"""# Fail-closed PktPath Studio launcher (pure Cordis Node v24.22.1).
# Extract the full zip archive before running; double-click entry is start-studio.cmd.
# Under Restricted execution policy, run:
#   powershell -NoProfile -ExecutionPolicy Bypass -File ".\start-studio.ps1"
# Refuses to start if packaged Node, studio-cordis, or @cordisjs/core is missing.
# Never falls back to PATH Node.
$ErrorActionPreference = "Stop"
$here = $PSScriptRoot

function Fail([int]$code, [string]$message) {
    [Console]::Error.WriteLine($message)
    exit $code
}

$node = Join-Path $here "node\node.exe"
$appDir = Join-Path $here "studio-cordis"
$entry = Join-Path $appDir "src\main.ts"
$webIdx = Join-Path $appDir "web\index.html"
$cordisPkg = Join-Path $appDir "node_modules\@cordisjs\core\package.json"
$collectors = Join-Path $here "collectors"
$androidBin = Join-Path $collectors "android-arm64\pktpath"

if (-not (Test-Path -LiteralPath $node -PathType Leaf)) {
    Fail 1 "packaged Windows x64 Node missing (node\node.exe); no PATH fallback"
}
if (-not (Test-Path -LiteralPath $entry -PathType Leaf)) {
    Fail 1 "packaged Cordis entry missing (studio-cordis\src\main.ts)"
}
if (-not (Test-Path -LiteralPath $webIdx -PathType Leaf)) {
    Fail 1 "packaged Studio web assets missing (studio-cordis\web\index.html)"
}
if (-not (Test-Path -LiteralPath $cordisPkg -PathType Leaf)) {
    Fail 1 "packaged @cordisjs/core missing (studio-cordis\node_modules\@cordisjs\core\package.json)"
}
if (-not (Test-Path -LiteralPath $androidBin -PathType Leaf)) {
    Fail 1 "packaged Android collector missing (collectors\android-arm64\pktpath)"
}

Push-Location -LiteralPath $appDir
try {
    & $node --input-type=module -e "await import('@cordisjs/core')"
    $impCode = $LASTEXITCODE
} finally {
    Pop-Location
}
if ($impCode -ne 0) {
    Fail 1 "packaged Cordis runtime cannot import @cordisjs/core with packaged Node"
}

$env:PKTPATH_CORDIS_NODE = $node
$launchArgs = @($entry, "--collectors-dir", $collectors) + $args
& $node @launchArgs
exit $LASTEXITCODE
"""

START_STUDIO_SH = r"""#!/usr/bin/env bash
# Fail-closed PktPath Studio launcher (pure Cordis Node v24.22.1).
# Refuses to start if packaged Node, studio-cordis, or @cordisjs/core is missing.
# Never falls back to PATH Node.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NODE="$HERE/node/bin/node"
APPDIR="$HERE/studio-cordis"
ENTRY="$APPDIR/src/main.ts"
WEBIDX="$APPDIR/web/index.html"
CORDISPKG="$APPDIR/node_modules/@cordisjs/core/package.json"
COLLECTORS="$HERE/collectors"
ANDROID_BIN="$COLLECTORS/android-arm64/pktpath"

if [[ ! -x "$NODE" ]]; then
  echo "packaged Linux x64 Node missing (node/bin/node); no PATH fallback" >&2
  exit 1
fi
if [[ ! -f "$ENTRY" ]]; then
  echo "packaged Cordis entry missing (studio-cordis/src/main.ts)" >&2
  exit 1
fi
if [[ ! -f "$WEBIDX" ]]; then
  echo "packaged Studio web assets missing (studio-cordis/web/index.html)" >&2
  exit 1
fi
if [[ ! -f "$CORDISPKG" ]]; then
  echo "packaged @cordisjs/core missing (studio-cordis/node_modules/@cordisjs/core/package.json)" >&2
  exit 1
fi
if [[ ! -f "$ANDROID_BIN" ]]; then
  echo "packaged Android collector missing (collectors/android-arm64/pktpath)" >&2
  exit 1
fi

(cd "$APPDIR" && "$NODE" --input-type=module -e "await import('@cordisjs/core')") || {
  echo "packaged Cordis runtime cannot import @cordisjs/core with packaged Node" >&2
  exit 1
}

export PKTPATH_CORDIS_NODE="$NODE"
exec "$NODE" "$ENTRY" --collectors-dir "$COLLECTORS" "$@"
"""


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fp:
        for chunk in iter(lambda: fp.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def ensure_node_archive(
    target_os: str, archive_arg: str | None, cache_dir: Path | None, download: bool
) -> Path:
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
                raise FileNotFoundError(
                    f"Cached Node archive not found and --download-node not set: {archive}"
                )
            tmp = archive.with_suffix(archive.suffix + ".part")
            try:
                urllib.request.urlretrieve(spec["url"], tmp)
                actual_tmp = sha256_file(tmp)
                if actual_tmp != spec["sha256"]:
                    tmp.unlink(missing_ok=True)
                    raise ValueError(
                        f"SHA-256 mismatch for downloaded {archive.name}: expected {spec['sha256']}, got {actual_tmp}"
                    )
                tmp.replace(archive)
            except Exception:
                tmp.unlink(missing_ok=True)
                raise

    actual = sha256_file(archive)
    if actual != spec["sha256"]:
        raise ValueError(
            f"SHA-256 mismatch for {archive.name}: expected {spec['sha256']}, got {actual}"
        )
    return archive


def extract_node(target_os: str, archive: Path, bundle_dir: Path) -> Path:
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

    check_binary_magic(node_out, target_os)
    expected_node_sha = spec.get("node_sha256")
    if expected_node_sha:
        actual_node_sha = sha256_file(node_out)
        if actual_node_sha != expected_node_sha:
            raise ValueError(
                f"SHA-256 mismatch for extracted {node_out.name}: expected {expected_node_sha}, got {actual_node_sha}"
            )
    return lic_out


def check_binary_magic(path: Path, target_os: str) -> None:
    with path.open("rb") as fp:
        head = fp.read(4)
    if target_os == "windows":
        if head[:2] != b"MZ":
            raise ValueError(f"Expected Windows PE (MZ) binary, got {head!r}: {path}")
    else:
        if head != b"\x7fELF":
            raise ValueError(f"Expected Linux ELF binary, got {head!r}: {path}")


def _matches_any(name: str, patterns: tuple[str, ...]) -> bool:
    return any(fnmatch.fnmatch(name, pat) for pat in patterns)


def assert_no_symlinks(root: Path, ignore_patterns: tuple[str, ...] = ()) -> None:
    if root.is_symlink():
        raise ValueError(f"Symlink forbidden in preview bundle source: {root}")
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dp = Path(dirpath)
        kept_dirs: list[str] = []
        for d in dirnames:
            if _matches_any(d, ignore_patterns):
                continue
            cand = dp / d
            if cand.is_symlink():
                raise ValueError(f"Symlink forbidden in preview bundle source: {cand}")
            kept_dirs.append(d)
        dirnames[:] = kept_dirs
        for f in filenames:
            if _matches_any(f, ignore_patterns):
                continue
            cand = dp / f
            if cand.is_symlink():
                raise ValueError(f"Symlink forbidden in preview bundle source: {cand}")


def copy_cordis_studio(studio_dir: Path, dst_dir: Path) -> None:
    if studio_dir.is_symlink():
        raise ValueError(f"Symlink forbidden in preview bundle source: {studio_dir}")
    dst_dir.mkdir(parents=True, exist_ok=True)
    for req_file in ("package.json", "package-lock.json"):
        src = studio_dir / req_file
        if src.is_symlink():
            raise ValueError(f"Symlink forbidden in preview bundle source: {src}")
        if not src.is_file():
            raise FileNotFoundError(f"Missing required studio-cordis file: {src}")
        shutil.copy2(src, dst_dir / req_file)

    src_ignore = ("*.test.ts", "*.test.mjs", "__tests__")
    src_dir = studio_dir / "src"
    assert_no_symlinks(src_dir, ignore_patterns=src_ignore)
    if not (src_dir / "main.ts").is_file():
        raise FileNotFoundError(f"Missing required Cordis entry: {src_dir / 'main.ts'}")
    shutil.copytree(
        src_dir,
        dst_dir / "src",
        symlinks=False,
        ignore=shutil.ignore_patterns(*src_ignore),
    )

    web_dir = studio_dir / "web"
    assert_no_symlinks(web_dir)
    if not (web_dir / "index.html").is_file():
        raise FileNotFoundError(f"Missing required web entry: {web_dir / 'index.html'}")
    shutil.copytree(web_dir, dst_dir / "web", symlinks=False)

    nm_ignore = (".bin", ".package-lock.json")
    nm_src = studio_dir / "node_modules"
    assert_no_symlinks(nm_src, ignore_patterns=nm_ignore)
    cordis_pkg = nm_src / "@cordisjs" / "core" / "package.json"
    if not cordis_pkg.is_file():
        raise FileNotFoundError(
            f"Missing @cordisjs/core in {nm_src}; run 'npm ci --ignore-scripts --omit=dev' in {studio_dir} first"
        )
    shutil.copytree(
        nm_src,
        dst_dir / "node_modules",
        symlinks=False,
        ignore=shutil.ignore_patterns(*nm_ignore),
    )


def copy_collectors(collectors_dir: Path, dst_dir: Path) -> list[str]:
    dst_dir.mkdir(parents=True, exist_ok=True)
    copied: list[str] = []
    specs = [
        ("android-arm64/pktpath", ("android-arm64/pktpath", "pktpath-android-arm64"), True),
        ("linux-x86_64/pktpath", ("linux-x86_64/pktpath", "pktpath-linux-x86_64"), False),
        ("linux-arm64/pktpath", ("linux-arm64/pktpath", "pktpath-linux-arm64"), False),
    ]
    for dst_rel, src_candidates, required in specs:
        found: Path | None = None
        for cand in src_candidates:
            p = collectors_dir / cand
            if p.is_file():
                found = p
                break
        if found is None:
            if required:
                raise FileNotFoundError(
                    f"Required collector binary missing in {collectors_dir}: tried {src_candidates}"
                )
            continue
        check_binary_magic(found, "linux")
        out_path = dst_dir / dst_rel
        out_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(found, out_path)
        out_path.chmod(out_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        copied.append(dst_rel)
    return copied


def iter_node_packages(node_modules_dir: Path) -> list[Path]:
    pkgs: list[Path] = []
    if not node_modules_dir.is_dir():
        return pkgs
    for entry in sorted(node_modules_dir.iterdir()):
        if entry.name.startswith("."):
            continue
        if entry.name.startswith("@") and entry.is_dir():
            for scoped in sorted(entry.iterdir()):
                if (scoped / "package.json").is_file():
                    pkgs.append(scoped)
        elif (entry / "package.json").is_file():
            pkgs.append(entry)
    return pkgs


def find_license_file(pkg_dir: Path) -> Path | None:
    preferred = (
        "LICENSE",
        "LICENSE.md",
        "LICENSE.txt",
        "LICENCE",
        "LICENCE.md",
        "LICENCE.txt",
        "NOTICE",
        "NOTICE.txt",
    )
    by_lower = {p.name.lower(): p for p in pkg_dir.iterdir() if p.is_file()}
    for name in preferred:
        if name.lower() in by_lower:
            return by_lower[name.lower()]
    return None


def collect_licenses(
    repo_license: Path,
    node_license: Path,
    node_modules_dir: Path,
    bundle_dir: Path,
) -> list[dict[str, str]]:
    if not repo_license.is_file():
        raise FileNotFoundError(f"Repository root LICENSE not found: {repo_license}")
    if not node_license.is_file():
        raise FileNotFoundError(f"Bundled Node LICENSE not found: {node_license}")

    shutil.copy2(repo_license, bundle_dir / "LICENSE")
    licenses_dir = bundle_dir / "LICENSES"
    third_party_dir = licenses_dir / "third-party"
    third_party_dir.mkdir(parents=True, exist_ok=True)

    shutil.copy2(repo_license, licenses_dir / "PKTPATH-LICENSE.txt")
    shutil.copy2(node_license, licenses_dir / "NODE-LICENSE.txt")

    records: list[dict[str, str]] = [
        {
            "name": "PktPath",
            "version": "wave1",
            "license": "See PKTPATH-LICENSE.txt",
            "file": "LICENSES/PKTPATH-LICENSE.txt",
        },
        {
            "name": "Node.js",
            "version": NODE_VERSION,
            "license": "MIT (and bundled dependencies; see NODE-LICENSE.txt)",
            "file": "LICENSES/NODE-LICENSE.txt",
        },
    ]

    for pkg_dir in iter_node_packages(node_modules_dir):
        meta = json.loads((pkg_dir / "package.json").read_text(encoding="utf-8"))
        name = str(meta.get("name") or pkg_dir.name)
        version = str(meta.get("version") or "unknown")
        spdx = str(meta.get("license") or "UNKNOWN")
        safe_name = name.lstrip("@").replace("/", "__")
        lic_src = find_license_file(pkg_dir)
        if lic_src is not None:
            dst_name = f"{safe_name}-LICENSE.txt"
            shutil.copy2(lic_src, third_party_dir / dst_name)
            lic_ref = f"LICENSES/third-party/{dst_name}"
        else:
            lic_ref = f"(declared in studio-cordis/node_modules/{name}/package.json: {spdx})"
        records.append(
            {
                "name": name,
                "version": version,
                "license": spdx,
                "file": lic_ref,
            }
        )

    lines = [
        "PktPath Studio (Pure Cordis) - Third-Party Licenses & Notices",
        "=============================================================",
        "",
    ]
    for rec in records:
        lines.append(f"- {rec['name']} ({rec['version']})")
        lines.append(f"  License: {rec['license']}")
        lines.append(f"  Text:    {rec['file']}")
    lines.append("")
    (licenses_dir / "THIRD-PARTY-NOTICES.txt").write_text("\n".join(lines), encoding="utf-8")
    return records


def write_launchers(target_os: str, bundle_dir: Path, launchers_dir: Path | None) -> list[str]:
    written: list[str] = []
    if target_os == "windows":
        targets: list[tuple[str, str | None, bool]] = [
            ("start-studio.cmd", START_STUDIO_CMD, True),
            ("start-studio.ps1", START_STUDIO_PS1, True),
            ("stop-studio.cmd", None, True),
            ("stop-studio.ps1", None, True),
        ]
    else:
        targets = [
            ("start-studio.sh", START_STUDIO_SH, False),
            ("stop-studio.sh", None, False),
        ]

    for filename, fallback_text, crlf in targets:
        override = (launchers_dir / filename) if launchers_dir is not None else None
        if override is not None and override.is_symlink():
            raise ValueError(f"Symlink launcher forbidden: {override}")
        source_has_bom = False
        if override is not None and override.is_file():
            raw = override.read_bytes()
            if raw.startswith(b"\xef\xbb\xbf"):
                source_has_bom = True
                raw = raw[3:]
            content = raw.decode("utf-8")
        elif fallback_text is not None:
            content = fallback_text
        else:
            continue
        normalized = content.replace("\r\n", "\n")
        if crlf:
            normalized = normalized.replace("\n", "\r\n")
        data = normalized.encode("utf-8")
        # PowerShell 5.1 on Chinese Windows (CP936) needs a UTF-8 BOM to parse
        # Chinese strings correctly. Preserve a source BOM, and always emit one
        # for .ps1 so packaged launchers stay consistent with studio-cordis/scripts.
        if filename.endswith(".ps1") or source_has_bom:
            if not data.startswith(b"\xef\xbb\xbf"):
                data = b"\xef\xbb\xbf" + data
        dst = bundle_dir / filename
        dst.write_bytes(data)
        if not crlf:
            dst.chmod(dst.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        written.append(filename)
    return written


def copy_tray_exe(tray_exe: Path, bundle_dir: Path) -> str:
    if tray_exe.is_symlink():
        raise ValueError(f"Symlink tray executable forbidden: {tray_exe}")
    if not tray_exe.is_file():
        raise FileNotFoundError(f"Tray executable not found: {tray_exe}")
    header = tray_exe.read_bytes()[:2]
    if header != b"MZ":
        raise ValueError(f"Tray executable is not a valid Windows PE binary (missing MZ header): {tray_exe}")
    dst = bundle_dir / "PktPathStudio.exe"
    shutil.copy2(tray_exe, dst)
    return dst.name


def pack_nsis_installer(
    bundle_dir: Path,
    out_dir: Path,
    bundle_name: str,
    nsis_script: Path,
    makensis_bin: str | None,
    app_version: str,
) -> Path:
    if nsis_script.is_symlink():
        raise ValueError(f"Symlink NSIS script forbidden: {nsis_script}")
    if not nsis_script.is_file():
        raise FileNotFoundError(f"NSIS script not found: {nsis_script}")
    exe = makensis_bin or shutil.which("makensis")
    if not exe:
        raise FileNotFoundError("makensis not found in PATH; install NSIS or pass --makensis")

    out_exe = (out_dir / f"{bundle_name}.exe").resolve()
    if out_exe.exists():
        out_exe.unlink()

    flag_prefix = "/" if os.name == "nt" else "-"
    cmd = [
        exe,
        f"{flag_prefix}V3",
        f"{flag_prefix}DSTAGING_DIR={bundle_dir.resolve()}",
        f"{flag_prefix}DOUT_FILE={out_exe}",
        f"{flag_prefix}DAPP_VERSION={app_version}",
        str(nsis_script.resolve()),
    ]
    proc = subprocess.run(cmd, text=True, capture_output=True, check=False)
    if proc.returncode != 0:
        raise RuntimeError(
            f"makensis failed (exit {proc.returncode}):\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
        )
    if not out_exe.is_file():
        raise FileNotFoundError(f"makensis succeeded but did not produce expected installer: {out_exe}")
    if out_exe.read_bytes()[:2] != b"MZ":
        raise ValueError(f"Generated installer is not a valid PE executable: {out_exe}")
    return out_exe


def write_manifest(bundle_dir: Path) -> int:
    entries: list[str] = []
    for path in sorted(p for p in bundle_dir.rglob("*") if p.is_file() or p.is_symlink()):
        if path.is_symlink():
            raise ValueError(f"Symlink forbidden in preview bundle: {path}")
        rel = path.relative_to(bundle_dir).as_posix()
        if rel == "MANIFEST.sha256":
            continue
        entries.append(f"{sha256_file(path)}  {rel}")
    (bundle_dir / "MANIFEST.sha256").write_text("\n".join(entries) + "\n", encoding="utf-8")
    return len(entries)


def pack_bundle(target_os: str, bundle_dir: Path, out_dir: Path, bundle_name: str) -> Path:
    if target_os == "windows":
        archive_path = out_dir / f"{bundle_name}.zip"
        if archive_path.exists():
            archive_path.unlink()
        with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
            for path in sorted(p for p in bundle_dir.rglob("*") if p.is_file()):
                arcname = f"{bundle_name}/{path.relative_to(bundle_dir).as_posix()}"
                zf.write(path, arcname)
        return archive_path

    archive_path = out_dir / f"{bundle_name}.tar.gz"
    if archive_path.exists():
        archive_path.unlink()
    with tarfile.open(archive_path, "w:gz") as tf:
        tf.add(bundle_dir, arcname=bundle_name)
    return archive_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Package a self-contained pure-Cordis PktPath preview bundle (no Go binary)"
    )
    parser.add_argument("--os", dest="target_os", choices=("windows", "linux"), required=True)
    parser.add_argument(
        "--studio-dir",
        default="studio-cordis",
        help="Path to studio-cordis/ directory (with node_modules installed)",
    )
    parser.add_argument(
        "--collectors-dir",
        required=True,
        help="Directory containing collector ELF binaries (android-arm64/pktpath or pktpath-android-arm64)",
    )
    parser.add_argument(
        "--repo-license",
        default="LICENSE",
        help="Path to repository root LICENSE file",
    )
    parser.add_argument(
        "--launchers-dir",
        default=None,
        help="Optional directory containing start-studio.{cmd,ps1,sh} overrides (e.g. studio-cordis/scripts)",
    )
    parser.add_argument("--node-archive", default=None, help="Pre-downloaded official Node archive")
    parser.add_argument("--cache-dir", default=None, help="Directory for caching official Node archive")
    parser.add_argument("--download-node", action="store_true", help="Download official Node if not cached")
    parser.add_argument("--out-dir", required=True, help="Output directory for the packaged archive")
    parser.add_argument("--bundle-name", required=True, help="Top-level directory and archive stem")
    parser.add_argument(
        "--windows-format",
        choices=("zip", "installer"),
        default="zip",
        help="Windows output format: 'installer' (NSIS Setup.exe with PktPathStudio.exe) or legacy 'zip'",
    )
    parser.add_argument(
        "--tray-exe",
        default=None,
        help="Path to compiled PktPathStudio.exe (required when --windows-format installer)",
    )
    parser.add_argument(
        "--nsis-script",
        default=None,
        help="Path to NSIS .nsi script (required when --windows-format installer)",
    )
    parser.add_argument("--makensis", default=None, help="Optional path to makensis binary")
    parser.add_argument(
        "--app-version",
        default=None,
        help="Version string passed as APP_VERSION to makensis (defaults to --bundle-name)",
    )
    parser.add_argument("--keep-dir", action="store_true", help="Keep unpacked staging directory")
    args = parser.parse_args(argv)

    if args.windows_format == "installer":
        if args.target_os != "windows":
            parser.error("--windows-format installer is only valid with --os windows")
        if not args.tray_exe or not args.nsis_script:
            parser.error("--windows-format installer requires both --tray-exe and --nsis-script")

    studio_dir = Path(args.studio_dir).resolve()
    collectors_dir = Path(args.collectors_dir).resolve()
    repo_license = Path(args.repo_license).resolve()
    launchers_dir = Path(args.launchers_dir).resolve() if args.launchers_dir else None
    out_dir = Path(args.out_dir).resolve()
    cache_dir = Path(args.cache_dir).resolve() if args.cache_dir else None

    archive_src = ensure_node_archive(args.target_os, args.node_archive, cache_dir, args.download_node)

    out_dir.mkdir(parents=True, exist_ok=True)
    bundle_dir = out_dir / args.bundle_name
    if bundle_dir.exists():
        shutil.rmtree(bundle_dir)
    bundle_dir.mkdir(parents=True)

    node_license = extract_node(args.target_os, archive_src, bundle_dir)
    copy_cordis_studio(studio_dir, bundle_dir / "studio-cordis")
    copied_collectors = copy_collectors(collectors_dir, bundle_dir / "collectors")
    licenses = collect_licenses(
        repo_license, node_license, bundle_dir / "studio-cordis" / "node_modules", bundle_dir
    )
    tray_exe_sha256: str | None = None
    if args.target_os == "windows" and args.windows_format == "installer":
        tray_path = Path(args.tray_exe).resolve()
        tray_name = copy_tray_exe(tray_path, bundle_dir)
        tray_exe_sha256 = sha256_file(bundle_dir / tray_name)
        launchers = [tray_name]
    else:
        launchers = write_launchers(args.target_os, bundle_dir, launchers_dir)

    manifest_count = write_manifest(bundle_dir)

    if args.target_os == "windows" and args.windows_format == "installer":
        archive_path = pack_nsis_installer(
            bundle_dir,
            out_dir,
            args.bundle_name,
            Path(args.nsis_script).resolve(),
            args.makensis,
            args.app_version or args.bundle_name,
        )
    else:
        archive_path = pack_bundle(args.target_os, bundle_dir, out_dir, args.bundle_name)

    if not args.keep_dir:
        shutil.rmtree(bundle_dir)

    summary = {
        "ok": True,
        "target_os": args.target_os,
        "windows_format": args.windows_format if args.target_os == "windows" else None,
        "node_version": NODE_VERSION,
        "node_archive_sha256": OFFICIAL_NODE[args.target_os]["sha256"],
        "collectors": copied_collectors,
        "launchers": launchers,
        "tray_exe_sha256": tray_exe_sha256,
        "licensed_components": len(licenses),
        "manifest_entries": manifest_count,
        "archive_path": str(archive_path),
        "archive_size_bytes": archive_path.stat().st_size,
        "archive_sha256": sha256_file(archive_path),
    }
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
