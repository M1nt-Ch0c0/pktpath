#!/usr/bin/env python3
"""Minimal PE32+ header / section inspector (no third-party deps)."""

from __future__ import annotations

import argparse
import struct
from pathlib import Path

MACHINE_AMD64 = 0x8664
SUBSYSTEM_WINDOWS_GUI = 2
SUBSYSTEM_WINDOWS_CUI = 3


def parse_pe(path: Path) -> dict:
    data = path.read_bytes()
    if data[:2] != b"MZ":
        raise ValueError(f"{path} is not a DOS/PE image")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew : e_lfanew + 4] != b"PE\0\0":
        raise ValueError("missing PE signature")
    machine, nsec, ts, _, _, opt_size, chars = struct.unpack_from("<HHIIIHH", data, e_lfanew + 4)
    opt_off = e_lfanew + 24
    magic = struct.unpack_from("<H", data, opt_off)[0]
    if magic == 0x20B:  # PE32+
        subsystem = struct.unpack_from("<H", data, opt_off + 68)[0]
        pe_format = "PE32+"
    elif magic == 0x10B:  # PE32
        subsystem = struct.unpack_from("<H", data, opt_off + 68)[0]
        pe_format = "PE32"
    else:
        raise ValueError(f"unknown optional magic 0x{magic:x}")
    sec_off = opt_off + opt_size
    sections = []
    for i in range(nsec):
        off = sec_off + 40 * i
        name = data[off : off + 8].split(b"\x00", 1)[0].decode("ascii", "replace")
        vsize, vaddr, raw_size, ptr_raw = struct.unpack_from("<IIII", data, off + 8)
        sections.append({"name": name, "vsize": vsize, "raw_size": raw_size, "ptr": ptr_raw})
    return {
        "path": str(path),
        "size": len(data),
        "format": pe_format,
        "machine": machine,
        "subsystem": subsystem,
        "sections": sections,
        "characteristics": chars,
    }


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("pe", type=Path)
    p.add_argument("--expect-amd64", action="store_true")
    p.add_argument("--expect-gui", action="store_true")
    p.add_argument("--expect-section", action="append", default=[])
    args = p.parse_args()
    info = parse_pe(args.pe)
    print(f"{info['path']}: {info['format']} machine=0x{info['machine']:04x} "
          f"subsystem={info['subsystem']} size={info['size']}")
    for s in info["sections"]:
        print(f"  {s['name']:8s} vsize={s['vsize']} raw={s['raw_size']}")
    if args.expect_amd64 and info["machine"] != MACHINE_AMD64:
        raise SystemExit(f"machine 0x{info['machine']:04x}, expected 0x8664")
    if args.expect_gui and info["subsystem"] != SUBSYSTEM_WINDOWS_GUI:
        raise SystemExit(f"subsystem {info['subsystem']}, expected 2 (WINDOWS_GUI)")
    names = {s["name"] for s in info["sections"]}
    for want in args.expect_section:
        if want not in names:
            raise SystemExit(f"missing section {want}; have {sorted(names)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
