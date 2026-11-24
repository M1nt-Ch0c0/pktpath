"""Privacy redactor using keyed SHA-256 truncation (`pktpath redact` & `export --redact`).

Implements `详细设计.md` v3 §6.3:
- Anonymizes IPv4/IPv6 addresses, TCP/UDP ports, and Linux/Android UIDs deterministically
  within a redaction run via keyed HMAC-SHA256 / SHA-256 truncation
- Rewrites both `SUMMARY` TLV fields (`src_ip`, `dst_ip`, `src_port`, `dst_port`, `uid`)
  AND embedded `hdr_bytes` (`0x0319`) L3/L4 headers (plus zeroing any L4 payload bytes)
- Re-emits CRC32-valid `.pktb` blocks, `manifest.json`, and `dict.json` into `<out_dir>`
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import shutil
import struct
from pathlib import Path
from typing import Any

from .wire import (
    TLV_SUM_DST_IP,
    TLV_SUM_DST_PORT,
    TLV_SUM_HDR_BYTES,
    TLV_SUM_LINKTYPE,
    TLV_SUM_SRC_IP,
    TLV_SUM_SRC_PORT,
    TLV_SUM_UID,
    DecodedEvent,
    EventKind,
    LinkType,
    encode_block,
    encode_event,
    load_session,
)


class Redactor:
    """Deterministic per-run keyed SHA-256 anonymizer for IPs, ports, UIDs, and packet headers."""

    def __init__(self, key: bytes | str | None = None) -> None:
        if key is None:
            self._key = os.urandom(32)
        elif isinstance(key, str):
            self._key = hashlib.sha256(key.encode("utf-8")).digest()
        else:
            self._key = hashlib.sha256(bytes(key)).digest()

    def _prf(self, domain: bytes, data: bytes) -> bytes:
        return hmac.new(self._key, domain + b":" + data, hashlib.sha256).digest()

    def redact_ip_bytes(self, ip_bytes: bytes) -> bytes:
        if len(ip_bytes) == 4:
            digest = self._prf(b"ipv4", ip_bytes)
            # Map into 100.64.0.0/10-like or general non-reserved space while guaranteeing != input
            out = bytearray(digest[:4])
            if out[0] in (0, 127) or out[0] >= 224:
                out[0] = 10
            candidate = bytes(out)
            if candidate == ip_bytes:
                out[3] ^= 0x01
                candidate = bytes(out)
            return candidate

        if len(ip_bytes) == 16:
            digest = self._prf(b"ipv6", ip_bytes)
            out = bytearray(16)
            out[0] = 0xFD  # ULA fd00::/8
            out[1:16] = digest[:15]
            candidate = bytes(out)
            if candidate == ip_bytes:
                out[15] ^= 0x01
                candidate = bytes(out)
            return candidate

        return ip_bytes

    def redact_ip_str(self, ip_str: str) -> str:
        ip_obj = ipaddress.ip_address(ip_str)
        red_bytes = self.redact_ip_bytes(ip_obj.packed)
        return str(ipaddress.ip_address(red_bytes))

    def redact_port(self, port: int) -> int:
        p = port & 0xFFFF
        if p == 0:
            return 0
        digest = self._prf(b"port", struct.pack("<H", p))
        val = 1024 + (int.from_bytes(digest[:2], "little") % 64511)
        if val == p:
            val = 1024 + ((val - 1024 + 1) % 64511)
        return val

    def redact_uid(self, uid: int) -> int:
        u = uid & 0xFFFFFFFF
        if u == 0xFFFFFFFF:
            return u
        digest = self._prf(b"uid", struct.pack("<I", u))
        val = 100_000 + (int.from_bytes(digest[:4], "little") % 800_000)
        if val == u:
            val += 1
        return val

    def redact_hdr_bytes(self, hdr_bytes: bytes, linktype: int = int(LinkType.ETHERNET)) -> bytes:
        """Anonymize MACs, IPv4/IPv6 addresses, TCP/UDP ports, and zero L4 payload in `hdr_bytes`."""
        buf = bytearray(hdr_bytes)
        n = len(buf)
        pos = 0
        ethertype: int | None = None

        if linktype == int(LinkType.ETHERNET):
            if n < 14:
                return bytes(buf)
            # Anonymize dst/src MAC lower 3 bytes while keeping unicast/multicast bit
            dst_hash = self._prf(b"mac", bytes(buf[0:6]))
            src_hash = self._prf(b"mac", bytes(buf[6:12]))
            buf[0] = (buf[0] & 0x01) | 0x02  # locally administered bit
            buf[1:6] = dst_hash[:5]
            buf[6] = (buf[6] & 0x01) | 0x02
            buf[7:12] = src_hash[:5]
            (ethertype,) = struct.unpack_from("!H", buf, 12)
            pos = 14
            while ethertype in (0x8100, 0x88A8, 0x9100) and pos + 4 <= n:
                (ethertype,) = struct.unpack_from("!H", buf, pos + 2)
                pos += 4
        elif linktype == int(LinkType.RAW_IP):
            if n >= 1:
                ver = (buf[0] >> 4) & 0x0F
                ethertype = 0x0800 if ver == 4 else (0x86DD if ver == 6 else None)

        l4_proto: int | None = None
        frag_off = 0

        if ethertype == 0x0800 and pos + 20 <= n:
            ihl = (buf[pos] & 0x0F) * 4
            if ihl >= 20 and pos + ihl <= n:
                l4_proto = buf[pos + 9]
                (frag_field,) = struct.unpack_from("!H", buf, pos + 6)
                frag_off = (frag_field & 0x1FFF) * 8
                buf[pos + 12 : pos + 16] = self.redact_ip_bytes(bytes(buf[pos + 12 : pos + 16]))
                buf[pos + 16 : pos + 20] = self.redact_ip_bytes(bytes(buf[pos + 16 : pos + 20]))
                # Zero IPv4 header checksum after address redaction
                buf[pos + 10 : pos + 12] = b"\x00\x00"
                pos += ihl
        elif ethertype == 0x86DD and pos + 40 <= n:
            nxt = buf[pos + 6]
            buf[pos + 8 : pos + 24] = self.redact_ip_bytes(bytes(buf[pos + 8 : pos + 24]))
            buf[pos + 24 : pos + 40] = self.redact_ip_bytes(bytes(buf[pos + 24 : pos + 40]))
            pos += 40
            while nxt in (0, 43, 44, 60) and pos + 8 <= n:
                if nxt == 44:
                    nxt_hdr = buf[pos]
                    (frag_off_m,) = struct.unpack_from("!H", buf, pos + 2)
                    frag_off = frag_off_m & 0xFFF8
                    nxt = nxt_hdr
                    pos += 8
                else:
                    nxt_hdr = buf[pos]
                    hlen = (buf[pos + 1] + 1) * 8
                    if hlen <= 0 or pos + hlen > n:
                        break
                    nxt = nxt_hdr
                    pos += hlen
            l4_proto = nxt

        if l4_proto is not None and frag_off == 0:
            if l4_proto == 6 and pos + 4 <= n:  # TCP
                sp, dp = struct.unpack_from("!HH", buf, pos)
                struct.pack_into("!HH", buf, pos, self.redact_port(sp), self.redact_port(dp))
                if pos + 18 <= n:
                    buf[pos + 16 : pos + 18] = b"\x00\x00"  # zero TCP checksum
                doff = ((buf[pos + 12] >> 4) & 0x0F) * 4 if pos + 13 <= n else 20
                payload_start = pos + max(20, doff)
                if payload_start < n:
                    buf[payload_start:n] = b"\x00" * (n - payload_start)
            elif l4_proto == 17 and pos + 4 <= n:  # UDP
                sp, dp = struct.unpack_from("!HH", buf, pos)
                struct.pack_into("!HH", buf, pos, self.redact_port(sp), self.redact_port(dp))
                if pos + 8 <= n:
                    buf[pos + 6 : pos + 8] = b"\x00\x00"  # zero UDP checksum
                payload_start = pos + 8
                if payload_start < n:
                    buf[payload_start:n] = b"\x00" * (n - payload_start)

        return bytes(buf)

    def redact_event(self, ev: DecodedEvent, default_linktype: int = int(LinkType.ETHERNET)) -> DecodedEvent:
        """Return a redacted copy of `DecodedEvent` with updated `raw_tlvs` and `fields`."""
        if ev.kind != int(EventKind.SUMMARY):
            return ev

        ltype = int(ev.get("linktype", default_linktype) or default_linktype)
        new_raw_tlvs: list[tuple[int, bytes]] = []
        new_fields = dict(ev.fields)

        for tag, val in ev.raw_tlvs:
            base_tag = tag & 0x7FFF
            if base_tag == TLV_SUM_SRC_IP and len(val) in (4, 16):
                rval = self.redact_ip_bytes(val)
                new_raw_tlvs.append((tag, rval))
                new_fields["src_ip_raw"] = rval
                new_fields["src_ip"] = str(ipaddress.ip_address(rval))
            elif base_tag == TLV_SUM_DST_IP and len(val) in (4, 16):
                rval = self.redact_ip_bytes(val)
                new_raw_tlvs.append((tag, rval))
                new_fields["dst_ip_raw"] = rval
                new_fields["dst_ip"] = str(ipaddress.ip_address(rval))
            elif base_tag == TLV_SUM_SRC_PORT and len(val) == 2:
                (p,) = struct.unpack("<H", val)
                rp = self.redact_port(p)
                new_raw_tlvs.append((tag, struct.pack("<H", rp)))
                new_fields["src_port"] = rp
            elif base_tag == TLV_SUM_DST_PORT and len(val) == 2:
                (p,) = struct.unpack("<H", val)
                rp = self.redact_port(p)
                new_raw_tlvs.append((tag, struct.pack("<H", rp)))
                new_fields["dst_port"] = rp
            elif base_tag == TLV_SUM_UID and len(val) == 4:
                (u,) = struct.unpack("<I", val)
                ru = self.redact_uid(u)
                new_raw_tlvs.append((tag, struct.pack("<I", ru)))
                new_fields["uid"] = ru
            elif base_tag == TLV_SUM_HDR_BYTES:
                rhdr = self.redact_hdr_bytes(val, linktype=ltype)
                new_raw_tlvs.append((tag, rhdr))
                new_fields["hdr_bytes"] = rhdr
            else:
                new_raw_tlvs.append((tag, val))

        return DecodedEvent(
            total_len=ev.total_len,
            kind=ev.kind,
            object_type=ev.object_type,
            evidence_level=ev.evidence_level,
            site_dict_idx=ev.site_dict_idx,
            cpu=ev.cpu,
            flags=ev.flags,
            seq=ev.seq,
            ts_ns=ev.ts_ns,
            object_id=ev.object_id,
            producer_type=ev.producer_type,
            epoch=ev.epoch,
            block_no=ev.block_no,
            fields=new_fields,
            raw_tlvs=new_raw_tlvs,
            unknown_optional_tlvs=list(ev.unknown_optional_tlvs),
            unknown_must_tlvs=list(ev.unknown_must_tlvs),
        )


def redact_session(
    in_dir: str | os.PathLike[str],
    out_dir: str | os.PathLike[str],
    *,
    key: bytes | str | None = None,
) -> dict[str, Any]:
    """Read session in `in_dir`, anonymize IPs/ports/UIDs/headers, and write valid `out_dir`."""
    src_path = Path(in_dir).resolve()
    dst_path = Path(out_dir).resolve()
    if src_path == dst_path:
        raise ValueError("--out directory must be distinct from input session directory")

    loaded = load_session(src_path)
    redactor = Redactor(key=key)
    dst_path.mkdir(parents=True, exist_ok=True)

    # Redact manifest filter metadata if any sensitive fields exist
    red_manifest = json.loads(json.dumps(loaded.manifest))
    red_manifest["redacted"] = True
    red_manifest["redaction_scheme"] = "hmac-sha256-trunc-v1"
    if isinstance(red_manifest.get("filters"), dict):
        flt = red_manifest["filters"]
        for ip_k in ("src_ip", "dst_ip"):
            if flt.get(ip_k):
                try:
                    flt[ip_k] = redactor.redact_ip_str(str(flt[ip_k]).split("/")[0])
                except ValueError:
                    pass
        for port_k in ("src_port", "dst_port"):
            if flt.get(port_k) is not None:
                flt[port_k] = redactor.redact_port(int(flt[port_k]))
        if flt.get("uid") is not None:
            flt["uid"] = redactor.redact_uid(int(flt["uid"]))

    (dst_path / "manifest.json").write_text(
        json.dumps(red_manifest, indent=2), encoding="utf-8"
    )
    if (src_path / "dict.json").is_file():
        shutil.copyfile(src_path / "dict.json", dst_path / "dict.json")
    else:
        (dst_path / "dict.json").write_text(
            json.dumps(loaded.dictionary, indent=2), encoding="utf-8"
        )

    # Lookup device default linktypes from dict.json
    dev_linktypes: dict[int, int] = {}
    for ep in loaded.dictionary.get("topology_epochs", []):
        for dev in ep.get("devices", []):
            if "ifindex" in dev and "linktype" in dev:
                dev_linktypes[int(dev["ifindex"])] = int(dev["linktype"])

    redacted_summary_count = 0
    written_blocks = 0

    for idx, blk in enumerate(loaded.blocks):
        if blk.meta_payload is not None:
            payload = json.dumps(blk.meta_payload).encode("utf-8")
        else:
            ev_blobs: list[bytes] = []
            for ev in blk.events:
                if ev.kind == int(EventKind.SUMMARY):
                    ifidx = int(ev.get("ifindex", 0) or 0)
                    def_lt = dev_linktypes.get(ifidx, int(LinkType.ETHERNET))
                    rev = redactor.redact_event(ev, default_linktype=def_lt)
                    redacted_summary_count += 1
                    ev_blobs.append(encode_event(rev))
                else:
                    ev_blobs.append(encode_event(ev))
            payload = b"".join(ev_blobs)

        # Preserve uncompressed valid block (clear ZSTD bit since we re-emit raw TLV bytes)
        new_hdr = blk.header.__class__(
            magic=blk.header.magic,
            major=blk.header.major,
            minor=blk.header.minor,
            block_type=blk.header.block_type,
            producer_type=blk.header.producer_type,
            flags=blk.header.flags & ~0x01,
            payload_len=len(payload),
            epoch=blk.header.epoch,
            block_no=blk.header.block_no,
            reserved=blk.header.reserved,
            session_uuid=blk.header.session_uuid,
            min_ts_ns=blk.header.min_ts_ns,
            max_ts_ns=blk.header.max_ts_ns,
        )
        out_name = blk.source_file if blk.source_file else f"block_{idx:06d}.pktb"
        raw_blk = encode_block(new_hdr, payload)
        (dst_path / out_name).write_bytes(raw_blk)
        written_blocks += 1

    return {
        "in_dir": str(src_path),
        "out_dir": str(dst_path),
        "blocks_written": written_blocks,
        "summaries_redacted": redacted_summary_count,
    }
