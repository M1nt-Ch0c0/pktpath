#!/usr/bin/env python3
"""Build a COFF x64 .syso resource object for go build (windows/amd64).

Embeds:
  - RT_GROUP_ICON ID=1  (LoadIconW(hInstance, MAKEINTRESOURCE(1)))
  - RT_ICON IDs 1..N    (one per ICO frame)
  - RT_VERSION ID=1     (optional VERSIONINFO)

The output filename rsrc_windows_amd64.syso is automatically picked up by
`GOOS=windows GOARCH=amd64 go build` with zero CGO / zero third-party tools.
"""

from __future__ import annotations

import argparse
import struct
import time
from pathlib import Path


RT_ICON = 3
RT_GROUP_ICON = 14
RT_VERSION = 16

IMAGE_FILE_MACHINE_AMD64 = 0x8664
IMAGE_SYM_CLASS_STATIC = 3
IMAGE_REL_AMD64_ADDR32NB = 3
IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
IMAGE_SCN_MEM_READ = 0x40000000

LANG_NEUTRAL = 0


def repo_root_from_here() -> Path:
    return Path(__file__).resolve().parents[3]


# ---------------------------------------------------------------------------
# ICO -> resource blobs
# ---------------------------------------------------------------------------

def parse_ico_images(data: bytes) -> list[dict]:
    reserved, typ, count = struct.unpack("<HHH", data[:6])
    if reserved != 0 or typ != 1 or count < 1:
        raise ValueError("invalid ICO header")
    images = []
    for i in range(count):
        off = 6 + 16 * i
        w, h, colors, reserved2, planes, bpp, size, image_off = struct.unpack("<BBBBHHII", data[off : off + 16])
        blob = data[image_off : image_off + size]
        width = 256 if w == 0 else w
        height = 256 if h == 0 else h
        if blob.startswith(b"\x89PNG"):
            planes = planes or 1
            bpp = bpp or 32
        else:
            if len(blob) < 16:
                raise ValueError("truncated DIB")
            _, bi_w, bi_h, bi_planes, bi_bpp = struct.unpack("<IIIHH", blob[:16])
            width = bi_w
            height = bi_h // 2 if bi_h >= 2 else bi_h
            planes, bpp = bi_planes, bi_bpp
        images.append(
            {
                "width": width,
                "height": height,
                "colors": colors,
                "planes": planes or 1,
                "bpp": bpp or 32,
                "data": blob,
            }
        )
    return images


def build_grp_icon(images: list[dict], first_id: int = 1) -> bytes:
    # GRPICONDIR + GRPICONDIRENTRY (id instead of offset)
    out = struct.pack("<HHH", 0, 1, len(images))
    for i, img in enumerate(images):
        w = 0 if img["width"] >= 256 else img["width"]
        h = 0 if img["height"] >= 256 else img["height"]
        out += struct.pack(
            "<BBBBHHIH",
            w,
            h,
            img["colors"] if img["colors"] < 256 else 0,
            0,
            img["planes"],
            img["bpp"],
            len(img["data"]),
            first_id + i,
        )
    return out


# ---------------------------------------------------------------------------
# VERSIONINFO
# ---------------------------------------------------------------------------

def _utf16z(s: str) -> bytes:
    return s.encode("utf-16le") + b"\x00\x00"


def _pad4(b: bytes) -> bytes:
    return b + (b"\x00" * ((4 - (len(b) % 4)) % 4))


def _block(key: str, value: bytes, value_is_text: bool, children: bytes, value_length_words: int | None = None) -> bytes:
    """Build a padded version-info block. wLength covers the unpadded body;
    the returned bytes are padded to 4 so a sibling can follow."""
    typ = 1 if value_is_text else 0
    if value_is_text:
        # wValueLength is in 16-bit words, including the terminating NUL
        w_value_length = (len(value) // 2) if value_length_words is None else value_length_words
    else:
        w_value_length = len(value) if value_length_words is None else value_length_words
    header = struct.pack("<HH", 0, w_value_length)  # length filled later
    header += struct.pack("<H", typ)
    body = header + _utf16z(key)
    body = _pad4(body)
    if value:
        body += value
        if children:
            body = _pad4(body)
    body += children
    # wLength is the unpadded size of this block
    length = len(body)
    body = struct.pack("<H", length) + body[2:]
    return _pad4(body)


def _string_entry(key: str, value: str) -> bytes:
    val = _utf16z(value)
    return _block(key, val, True, b"")


def build_versioninfo(
    file_version: tuple[int, int, int, int] = (0, 0, 0, 0),
    product_version_string: str = "0.0.0-preview",
    file_version_string: str | None = None,
) -> bytes:
    if file_version_string is None:
        file_version_string = ".".join(str(x) for x in file_version)

    ms = (file_version[0] << 16) | (file_version[1] & 0xFFFF)
    ls = (file_version[2] << 16) | (file_version[3] & 0xFFFF)
    fixed = struct.pack(
        "<13I",
        0xFEEF04BD,
        0x00010000,
        ms,
        ls,
        ms,
        ls,
        0x3F,
        0,
        0x00040004,
        1,
        0,
        0,
        0,
    )
    assert len(fixed) == 52

    strings = b"".join(
        [
            _string_entry("CompanyName", "PktPath"),
            _string_entry("FileDescription", "PktPath Studio"),
            _string_entry("FileVersion", file_version_string),
            _string_entry("InternalName", "PktPathStudio"),
            _string_entry("LegalCopyright", "Copyright The PktPath Authors. Licensed under the Apache License 2.0."),
            _string_entry("OriginalFilename", "PktPathStudio.exe"),
            _string_entry("ProductName", "PktPath Studio"),
            _string_entry("ProductVersion", product_version_string),
        ]
    )
    # 040904B0 = Unicode, US English
    string_table = _block("040904B0", b"", True, strings)
    string_file_info = _block("StringFileInfo", b"", True, string_table)

    # Translation: lang 0x0409, codepage 0x04B0
    translation = struct.pack("<HH", 0x0409, 0x04B0)
    var = _block("Translation", translation, False, b"")
    var_file_info = _block("VarFileInfo", b"", True, var)

    # Root: wValueLength of VS_FIXEDFILEINFO is 52 bytes (binary)
    root = _block("VS_VERSION_INFO", fixed, False, string_file_info + var_file_info, value_length_words=52)
    # The root should not need trailing padding for the resource payload itself;
    # include whatever we built (already padded). That's fine for RT_VERSION.
    return root


# ---------------------------------------------------------------------------
# .rsrc section builder
# ---------------------------------------------------------------------------

class ResDir:
    def __init__(self):
        # type_id -> name_id -> lang -> data
        self.items: dict[int, dict[int, dict[int, bytes]]] = {}

    def add(self, typ: int, name: int, lang: int, data: bytes) -> None:
        self.items.setdefault(typ, {}).setdefault(name, {})[lang] = data

    def build(self) -> tuple[bytes, list[int]]:
        # Precompute sizes
        types = sorted(self.items)
        # We'll assign offsets in a first pass.
        # Layout:
        #   root dir + entries
        #   for each type: dir + entries
        #   for each name: dir + entries
        #   all IMAGE_RESOURCE_DATA_ENTRY (16 bytes)  -- reloc targets
        #   all data blobs, 4-aligned

        def dir_size(n_entries: int) -> int:
            return 16 + 8 * n_entries

        n_leaves = 0
        type_dirs = []
        for typ in types:
            names = sorted(self.items[typ])
            name_list = []
            for name in names:
                langs = sorted(self.items[typ][name])
                name_list.append((name, langs))
                n_leaves += len(langs)
            type_dirs.append((typ, name_list))

        offset = 0
        root_off = offset
        offset += dir_size(len(types))
        type_off = {}
        for typ, name_list in type_dirs:
            type_off[typ] = offset
            offset += dir_size(len(name_list))
        name_off = {}
        for typ, name_list in type_dirs:
            for name, langs in name_list:
                name_off[(typ, name)] = offset
                offset += dir_size(len(langs))
        # data entries
        leaf_off = {}
        for typ, name_list in type_dirs:
            for name, langs in name_list:
                for lang in langs:
                    leaf_off[(typ, name, lang)] = offset
                    offset += 16
        # data blobs
        data_off = {}
        for typ, name_list in type_dirs:
            for name, langs in name_list:
                for lang in langs:
                    offset = (offset + 3) & ~3
                    data_off[(typ, name, lang)] = offset
                    offset += len(self.items[typ][name][lang])
        total = (offset + 3) & ~3
        buf = bytearray(total)
        relocs: list[int] = []

        def write_dir(at: int, ids: list[int], child_off_fn):
            # Characteristics, TimeDateStamp, Major, Minor, Named, Id
            struct.pack_into("<IIHHHH", buf, at, 0, 0, 0, 0, 0, len(ids))
            ent = at + 16
            for i, ident in enumerate(ids):
                child = child_off_fn(ident)
                # High bit set: child is a subdirectory (always, at type/name levels)
                struct.pack_into("<II", buf, ent + 8 * i, ident, 0x80000000 | child)

        def write_lang_dir(at: int, langs: list[int], typ: int, name: int):
            struct.pack_into("<IIHHHH", buf, at, 0, 0, 0, 0, 0, len(langs))
            ent = at + 16
            for i, lang in enumerate(langs):
                # High bit clear: points at IMAGE_RESOURCE_DATA_ENTRY
                struct.pack_into("<II", buf, ent + 8 * i, lang, leaf_off[(typ, name, lang)])

        write_dir(root_off, types, lambda typ: type_off[typ])
        for typ, name_list in type_dirs:
            names = [n for n, _ in name_list]
            write_dir(type_off[typ], names, lambda name, typ=typ: name_off[(typ, name)])
            for name, langs in name_list:
                write_lang_dir(name_off[(typ, name)], langs, typ, name)
                for lang in langs:
                    doff = data_off[(typ, name, lang)]
                    data = self.items[typ][name][lang]
                    # OffsetToData is a section-relative value; a ADDR32NB reloc
                    # will turn it into an RVA at link time.
                    struct.pack_into("<IIII", buf, leaf_off[(typ, name, lang)], doff, len(data), 0, 0)
                    relocs.append(leaf_off[(typ, name, lang)])  # offset of OffsetToData
                    buf[doff : doff + len(data)] = data

        return bytes(buf), relocs


# ---------------------------------------------------------------------------
# COFF x64 object writer
# ---------------------------------------------------------------------------

def build_coff_amd64(section_data: bytes, relocs: list[int], timestamp: int = 0) -> bytes:
    # Pad section raw data to 2-byte? 4-byte alignment is plenty for object files.
    raw = section_data
    if len(raw) % 4:
        raw = raw + b"\x00" * (4 - (len(raw) % 4))

    nreloc = len(relocs)
    nsymbols = 2  # section + aux

    # Layout:
    #   FILE_HEADER (20)
    #   SECTION_HEADER (40)
    #   section raw
    #   relocations (10 * n)
    #   symbols (18 * 2)
    #   string table (4)
    file_hdr_size = 20
    sec_hdr_size = 40
    ptr_raw = file_hdr_size + sec_hdr_size
    ptr_rel = ptr_raw + len(raw)
    ptr_sym = ptr_rel + 10 * nreloc

    file_hdr = struct.pack(
        "<HHIIIHH",
        IMAGE_FILE_MACHINE_AMD64,
        1,  # NumberOfSections
        timestamp,
        ptr_sym,
        nsymbols,
        0,  # SizeOfOptionalHeader
        0,  # Characteristics
    )
    assert len(file_hdr) == 20

    characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ
    name = b".rsrc" + b"\x00\x00\x00"
    sec_hdr = name + struct.pack(
        "<IIIIIIHHI",
        len(section_data),  # VirtualSize
        0,  # VirtualAddress
        len(raw),  # SizeOfRawData
        ptr_raw,  # PointerToRawData
        ptr_rel,  # PointerToRelocations
        0,  # PointerToLinenumbers
        nreloc,
        0,  # NumberOfLinenumbers
        characteristics,
    )
    assert len(sec_hdr) == 40

    rel_bytes = b"".join(struct.pack("<IIH", off, 0, IMAGE_REL_AMD64_ADDR32NB) for off in relocs)

    # Symbol 0: .rsrc STATIC, aux=1
    # Name 8 bytes, Value 4, SectionNumber 2, Type 2, StorageClass 1, NumberOfAux 1
    sym0 = b".rsrc\x00\x00\x00" + struct.pack("<IHHBB", 0, 1, 0, IMAGE_SYM_CLASS_STATIC, 1)
    assert len(sym0) == 18
    # Aux section symbol
    # Length 4, NumberOfRelocations 2, NumberOfLinenumbers 2, Checksum 4, Number 2, Selection 1, pad 3
    aux = struct.pack("<IHHIHBBBH", len(section_data), nreloc, 0, 0, 0, 0, 0, 0, 0)
    # That's 4+2+2+4+2+1+1+1+2 = 19? Let me count carefully.
    # Standard IMAGE_AUX_SYMBOL for section:
    #   DWORD Length
    #   WORD NumberOfRelocations
    #   WORD NumberOfLinenumbers
    #   DWORD CheckSum
    #   SHORT Number
    #   BYTE Selection
    #   BYTE bReserved
    #   SHORT HighNumber
    # = 4+2+2+4+2+1+1+2 = 18
    aux = struct.pack("<IHHIhBBh", len(section_data), nreloc, 0, 0, 0, 0, 0, 0)
    assert len(aux) == 18

    string_table = struct.pack("<I", 4)  # size includes itself; no extra strings

    return file_hdr + sec_hdr + raw + rel_bytes + sym0 + aux + string_table


def parse_coff_header(data: bytes) -> dict:
    if len(data) < 20:
        raise ValueError("COFF too short")
    machine, nsec, ts, ptr_sym, nsym, opt, chars = struct.unpack("<HHIIIHH", data[:20])
    if machine != IMAGE_FILE_MACHINE_AMD64:
        raise ValueError(f"unexpected machine 0x{machine:04x}")
    if nsec < 1:
        raise ValueError("no sections")
    name = data[20:28].split(b"\x00", 1)[0].decode("ascii", "replace")
    vsize, vaddr, raw_size, ptr_raw, ptr_rel, ptr_line, nrel, nline, chars = struct.unpack(
        "<IIIIIIHHI", data[28:60]
    )
    if name != ".rsrc":
        raise ValueError(f"first section is {name!r}, expected .rsrc")
    if ptr_raw + raw_size > len(data):
        raise ValueError("section data out of range")
    return {
        "machine": machine,
        "sections": nsec,
        "symbols": nsym,
        "section": name,
        "virtual_size": vsize,
        "raw_size": raw_size,
        "relocs": nrel,
    }


def build_syso(ico_path: Path, version_string: str = "0.0.0-preview") -> bytes:
    images = parse_ico_images(ico_path.read_bytes())
    if not images:
        raise ValueError("ICO contains no frames")
    res = ResDir()
    for i, img in enumerate(images):
        res.add(RT_ICON, 1 + i, LANG_NEUTRAL, img["data"])
    res.add(RT_GROUP_ICON, 1, LANG_NEUTRAL, build_grp_icon(images, first_id=1))
    res.add(RT_VERSION, 1, LANG_NEUTRAL, build_versioninfo(product_version_string=version_string))
    section, relocs = res.build()
    return build_coff_amd64(section, relocs, timestamp=0)


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate rsrc_windows_amd64.syso")
    parser.add_argument("--root", type=Path, default=None)
    parser.add_argument("--ico", type=Path, default=None)
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument("--version", default="0.0.0-preview")
    parser.add_argument("--verify", type=Path, default=None)
    args = parser.parse_args()

    if args.verify:
        info = parse_coff_header(args.verify.read_bytes())
        print(
            f"OK: {args.verify} machine=0x{info['machine']:04x} "
            f"section={info['section']} raw={info['raw_size']} relocs={info['relocs']}"
        )
        return 0

    root = args.root.resolve() if args.root else repo_root_from_here()
    ico = args.ico if args.ico else root / "packaging" / "windows" / "assets" / "pktpath-studio.ico"
    out = args.output if args.output else root / "packaging" / "windows" / "tray" / "rsrc_windows_amd64.syso"
    if not ico.is_file():
        raise SystemExit(f"ICO not found: {ico} (run gen_icon.py first)")
    data = build_syso(ico, version_string=args.version)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(data)
    info = parse_coff_header(data)
    print(f"wrote {out} ({len(data)} bytes)")
    print(
        f"  machine=0x{info['machine']:04x} section={info['section']} "
        f"raw={info['raw_size']} relocs={info['relocs']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
