#!/usr/bin/env python3
"""Guard and reconcile GitHub Pre-release assets and SHA256SUMS.txt.

Addresses two release-integrity invariants:
  1. Never silently upload a second differently-named Windows/Linux Studio bundle
     onto an existing GitHub Release or overwrite an existing SHA256SUMS.txt with
     a partial checksum list.
  2. Always generate a single complete SHA256SUMS.txt covering every non-checksum
     asset actually present on the Release page (Windows zip + Linux tar.gz +
     standalone collectors + any preserved release assets).

Stdlib only; does not invoke git/gh itself.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import sys
from pathlib import Path

CHECKSUM_FILENAME = "SHA256SUMS.txt"
WINDOWS_BUNDLE_GLOB = "pktpath-windows-x64-*.zip"
LINUX_BUNDLE_GLOB = "pktpath-linux-x64-*.tar.gz"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def list_dist_files(dist_dir: Path) -> list[Path]:
    if not dist_dir.is_dir():
        raise SystemExit(f"error: assets directory does not exist: {dist_dir}")
    files: list[Path] = []
    for entry in sorted(dist_dir.iterdir(), key=lambda p: p.name):
        if entry.name == CHECKSUM_FILENAME:
            continue
        if entry.is_symlink():
            raise SystemExit(f"error: refusing symlink in assets directory: {entry}")
        if not entry.is_file():
            raise SystemExit(f"error: unexpected non-file entry in assets directory: {entry}")
        files.append(entry)
    return files


def load_release_assets(json_path: Path) -> list[dict]:
    data = json.loads(json_path.read_text(encoding="utf-8"))
    if isinstance(data, dict) and "assets" in data:
        assets = data["assets"]
    elif isinstance(data, list):
        assets = data
    else:
        raise SystemExit(f"error: unexpected assets JSON structure in {json_path}")
    if not isinstance(assets, list):
        raise SystemExit(f"error: assets field is not a list in {json_path}")
    return assets


def validate_platform_bundles(names: list[str], *, require_both: bool) -> tuple[list[str], list[str]]:
    win = sorted(n for n in names if fnmatch.fnmatch(n, WINDOWS_BUNDLE_GLOB))
    lin = sorted(n for n in names if fnmatch.fnmatch(n, LINUX_BUNDLE_GLOB))
    if len(win) > 1:
        raise SystemExit(f"error: multiple Windows Studio bundles in dist: {win}")
    if len(lin) > 1:
        raise SystemExit(f"error: multiple Linux Studio bundles in dist: {lin}")
    if require_both:
        if not win:
            raise SystemExit(f"error: missing Windows Studio bundle matching {WINDOWS_BUNDLE_GLOB}")
        if not lin:
            raise SystemExit(f"error: missing Linux Studio bundle matching {LINUX_BUNDLE_GLOB}")
    return win, lin


def cmd_check_existing(args: argparse.Namespace) -> int:
    dist_files = list_dist_files(Path(args.dist_dir))
    if not dist_files:
        raise SystemExit(f"error: no release assets found in {args.dist_dir}")
    dist_names = [p.name for p in dist_files]
    new_win, new_lin = validate_platform_bundles(
        dist_names, require_both=not args.allow_partial_dist
    )

    if args.release_exists != "true":
        print("create")
        return 0

    if not args.existing_assets_json:
        raise SystemExit("error: --existing-assets-json is required when --release-exists=true")
    existing_assets = load_release_assets(Path(args.existing_assets_json))
    existing_non_sums = sorted(
        a["name"]
        for a in existing_assets
        if isinstance(a, dict) and a.get("name") and a["name"] != CHECKSUM_FILENAME
    )

    if not existing_non_sums:
        print("merge")
        return 0

    allow_existing = args.allow_existing_release.lower() == "true"
    if args.event_name != "workflow_dispatch":
        print(
            f"notice: release already exists with {len(existing_non_sums)} asset(s) "
            f"({', '.join(existing_non_sums)}); skipping automatic '{args.event_name}' upload "
            "to avoid duplicate bundles or clobbering reviewed SHA256SUMS.txt. "
            "Use workflow_dispatch with allow_existing_release=true to intentionally update.",
            file=sys.stderr,
        )
        print("skip")
        return 0

    if not allow_existing:
        raise SystemExit(
            f"error: release already exists with {len(existing_non_sums)} asset(s) "
            f"({', '.join(existing_non_sums)}). Refusing to overwrite or append without "
            "workflow_dispatch input allow_existing_release=true."
        )

    existing_win = sorted(
        n for n in existing_non_sums if fnmatch.fnmatch(n, WINDOWS_BUNDLE_GLOB)
    )
    existing_lin = sorted(
        n for n in existing_non_sums if fnmatch.fnmatch(n, LINUX_BUNDLE_GLOB)
    )

    for old in existing_win:
        if old not in new_win:
            raise SystemExit(
                f"error: existing release already has Windows Studio bundle '{old}', "
                f"which conflicts with new bundle {new_win}. Refusing to leave two Windows "
                "zips on the same Release."
            )
    for old in existing_lin:
        if old not in new_lin:
            raise SystemExit(
                f"error: existing release already has Linux Studio bundle '{old}', "
                f"which conflicts with new bundle {new_lin}. Refusing to leave two Linux "
                "tarballs on the same Release."
            )

    print("merge")
    return 0


def cmd_build_sums(args: argparse.Namespace) -> int:
    assets_dir = Path(args.assets_dir)
    files = list_dist_files(assets_dir)
    if not files:
        raise SystemExit(f"error: no assets to hash in {assets_dir}")

    local_by_name = {p.name: p for p in files}
    validate_platform_bundles(
        list(local_by_name.keys()), require_both=not args.allow_partial_dist
    )

    if args.expected_assets_json:
        expected_assets = load_release_assets(Path(args.expected_assets_json))
        expected_sizes: dict[str, int | None] = {}
        for asset in expected_assets:
            name = asset.get("name")
            if not name or name == CHECKSUM_FILENAME:
                continue
            expected_sizes[name] = asset.get("size")

        expected_names = set(expected_sizes.keys())
        local_names = set(local_by_name.keys())
        missing = sorted(expected_names - local_names)
        extra = sorted(local_names - expected_names)
        if missing or extra:
            raise SystemExit(
                f"error: asset mismatch while building {CHECKSUM_FILENAME}: "
                f"missing={missing}, extra={extra}"
            )
        for name, expected_size in expected_sizes.items():
            if isinstance(expected_size, int):
                actual_size = local_by_name[name].stat().st_size
                if actual_size != expected_size:
                    raise SystemExit(
                        f"error: size mismatch for '{name}': local={actual_size}, "
                        f"release={expected_size}"
                    )

    lines = [f"{sha256_file(local_by_name[name])}  {name}" for name in sorted(local_by_name)]
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines) + "\n", encoding="ascii")
    print(f"wrote {len(lines)} checksum entries to {out_path}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_check = sub.add_parser("check-existing", help="Decide create/merge/skip or fail closed.")
    p_check.add_argument("--dist-dir", required=True)
    p_check.add_argument("--release-exists", choices=("true", "false"), required=True)
    p_check.add_argument("--existing-assets-json", default="")
    p_check.add_argument("--event-name", required=True)
    p_check.add_argument("--allow-existing-release", default="false")
    p_check.add_argument("--allow-partial-dist", action="store_true")
    p_check.set_defaults(func=cmd_check_existing)

    p_sums = sub.add_parser("build-sums", help="Generate complete SHA256SUMS.txt.")
    p_sums.add_argument("--assets-dir", required=True)
    p_sums.add_argument("--expected-assets-json", default="")
    p_sums.add_argument("--out", required=True)
    p_sums.add_argument("--allow-partial-dist", action="store_true")
    p_sums.set_defaults(func=cmd_build_sums)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
