"""External `.pcap` and `.pcapng` parser & Level-3 annotation matcher.

Implements `详细设计.md` v3 §5.5:
- Parses classic `.pcap` (LE/BE, microsecond & nanosecond magics) and `.pcapng`
  (SHB, IDB with `if_tsresol`, EPB with `epb_flags`, SPB)
- Dissects Ethernet (`LINKTYPE_ETHERNET=1` + 802.1Q/ad VLAN), Raw IP (`101`/`228`/`229`),
  Linux cooked `SLL` (`113`) and `SLL2` (`276`)
- Matches candidates by direction, 5-tuple, TCP seq range, frame/IP length, and
  calibrated `CLOCK_REALTIME` window
- Explicitly detects `xmit_one` `NETDEV_TX_BUSY` duplicate frames and GSO/GRO super-frames
- Strictly attaches ONLY as `EvidenceLevel.ANNOTATION (3)` — NEVER creates identity edges!
"""

from __future__ import annotations

import ipaddress
import os
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

from .reconstruct import NETDEV_TX_BUSY, BranchPath, ReconstructedSession
from .wire import Dir, EvidenceLevel, Stage

# Link-layer header types
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LINUX_SLL = 113
LINKTYPE_IPV4 = 228
LINKTYPE_IPV6 = 229
LINKTYPE_LINUX_SLL2 = 276

# Classic pcap magic numbers (read as raw 4 bytes)
_PCAP_MAGICS: dict[bytes, tuple[str, int]] = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000),  # LE microsecond -> *1000 for ns
    b"\xa1\xb2\xc3\xd4": (">", 1_000),  # BE microsecond -> *1000 for ns
    b"\x4d\x3c\xb2\xa1": ("<", 1),      # LE nanosecond
    b"\xa1\xb2\x3c\x4d": (">", 1),      # BE nanosecond
}

# pcapng block types
_PCAPNG_SHB = 0x0A0D0D0A
_PCAPNG_IDB = 0x00000001
_PCAPNG_SPB = 0x00000003
_PCAPNG_EPB = 0x00000006


@dataclass(frozen=True)
class PcapPacket:
    frame_index: int
    realtime_ns: int
    captured_len: int
    orig_len: int
    linktype: int
    direction: int | None  # Dir.RX (0), Dir.TX (1), or None if unknown
    ifindex: int | None
    ip_version: int | None
    ip_total_len: int | None
    ip_id: int | None
    frag_offset: int
    is_fragment: bool
    l4_proto: int | None
    src_ip: str | None
    dst_ip: str | None
    src_port: int | None
    dst_port: int | None
    tcp_seq: int | None
    tcp_seq_end: int | None
    tcp_flags: int | None
    tcp_payload_len: int | None
    raw_bytes: bytes


@dataclass(frozen=True)
class TcpdumpCandidate:
    frame_index: int
    realtime_ns: int
    est_boottime_ns: int
    delta_from_xmit_ns: int
    clock_err_ns: int
    evidence_level: int  # Always EvidenceLevel.ANNOTATION (3)
    match_kind: str      # "EXACT_CANDIDATE", "AMBIGUOUS_MULTI_CANDIDATE", "XMIT_BUSY_DUPLICATE", "GSO_GRO_SUPERFRAME", "GSO_SEGMENT_FRAME"
    is_busy_duplicate: bool
    is_superframe: bool
    is_gso_segment: bool
    attempt_index: int | None
    orig_len: int
    ip_total_len: int | None
    src_ip: str | None
    dst_ip: str | None
    src_port: int | None
    dst_port: int | None
    tcp_seq: int | None
    tcp_seq_end: int | None
    ip_id: int | None
    note: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "frame_index": self.frame_index,
            "realtime_ns": self.realtime_ns,
            "est_boottime_ns": self.est_boottime_ns,
            "delta_from_xmit_ns": self.delta_from_xmit_ns,
            "clock_err_ns": self.clock_err_ns,
            "evidence_level": self.evidence_level,
            "evidence_level_name": "ANNOTATION",
            "match_kind": self.match_kind,
            "is_busy_duplicate": self.is_busy_duplicate,
            "is_superframe": self.is_superframe,
            "is_gso_segment": self.is_gso_segment,
            "attempt_index": self.attempt_index,
            "orig_len": self.orig_len,
            "ip_total_len": self.ip_total_len,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "tcp_seq": self.tcp_seq,
            "tcp_seq_end": self.tcp_seq_end,
            "ip_id": self.ip_id,
            "note": self.note,
        }


# ============================================================================
# 1. L2 / L3 / L4 Packet Dissector
# ============================================================================


def _dissect_frame(
    frame_index: int,
    realtime_ns: int,
    orig_len: int,
    linktype: int,
    raw: bytes,
    *,
    epb_direction: int | None = None,
) -> PcapPacket:
    n = len(raw)
    pos = 0
    ethertype: int | None = None
    direction = epb_direction
    ifindex: int | None = None

    if linktype == LINKTYPE_ETHERNET:
        if n >= 14:
            (ethertype,) = struct.unpack_from("!H", raw, 12)
            pos = 14
            # Unwrap 802.1Q / 802.1ad VLAN tags
            while ethertype in (0x8100, 0x88A8, 0x9100) and pos + 4 <= n:
                (ethertype,) = struct.unpack_from("!H", raw, pos + 2)
                pos += 4
    elif linktype in (LINKTYPE_RAW, LINKTYPE_IPV4, LINKTYPE_IPV6):
        if n >= 1:
            ver = (raw[0] >> 4) & 0x0F
            if ver == 4:
                ethertype = 0x0800
            elif ver == 6:
                ethertype = 0x86DD
    elif linktype == LINKTYPE_LINUX_SLL:
        if n >= 16:
            pkttype, _hatype, _halen = struct.unpack_from("!HHH", raw, 0)
            (ethertype,) = struct.unpack_from("!H", raw, 14)
            pos = 16
            if pkttype == 4:
                direction = int(Dir.TX)
            elif pkttype in (0, 1, 2):
                direction = int(Dir.RX)
    elif linktype == LINKTYPE_LINUX_SLL2:
        if n >= 20:
            (ethertype,) = struct.unpack_from("!H", raw, 0)
            (ifindex,) = struct.unpack_from("!I", raw, 4)
            pkttype = raw[10]
            pos = 20
            if pkttype == 4:
                direction = int(Dir.TX)
            elif pkttype in (0, 1, 2):
                direction = int(Dir.RX)

    ip_version: int | None = None
    ip_total_len: int | None = None
    ip_id: int | None = None
    frag_offset = 0
    is_fragment = False
    l4_proto: int | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    l4_payload_expected: int | None = None

    if ethertype == 0x0800 and pos + 20 <= n:
        vihl = raw[pos]
        if (vihl >> 4) == 4:
            ihl = (vihl & 0x0F) * 4
            if ihl >= 20 and pos + ihl <= n:
                ip_version = 4
                (_tos, tot_len, ident, frag_field, _ttl, proto, _csum, sip_b, dip_b) = (
                    struct.unpack_from("!BHHHBBH4s4s", raw, pos + 1)
                )
                # If TSO left ip_tot_len==0 in captured outgoing header, fall back to orig_len - pos
                ip_total_len = tot_len if tot_len > 0 else max(0, orig_len - pos)
                ip_id = ident
                frag_offset = (frag_field & 0x1FFF) * 8
                mf_flag = bool(frag_field & 0x2000)
                is_fragment = mf_flag or (frag_offset > 0)
                l4_proto = proto
                src_ip = str(ipaddress.IPv4Address(sip_b))
                dst_ip = str(ipaddress.IPv4Address(dip_b))
                l4_payload_expected = max(0, ip_total_len - ihl)
                pos += ihl

    elif ethertype == 0x86DD and pos + 40 <= n:
        vtcfl, plen, nxt, _hlim, sip_b, dip_b = struct.unpack_from(
            "!IHBB16s16s", raw, pos
        )
        if (vtcfl >> 28) == 6:
            ip_version = 6
            eff_plen = plen if plen > 0 else max(0, orig_len - pos - 40)
            ip_total_len = 40 + eff_plen
            src_ip = str(ipaddress.IPv6Address(sip_b))
            dst_ip = str(ipaddress.IPv6Address(dip_b))
            pos += 40
            ext_consumed = 0
            # Walk standard IPv6 extension headers
            while nxt in (0, 43, 44, 60) and pos + 8 <= n:
                if nxt == 44:  # Fragment header
                    nxt_hdr, _res, frag_off_m, ident32 = struct.unpack_from("!BBHI", raw, pos)
                    frag_offset = frag_off_m & 0xFFF8
                    is_fragment = bool(frag_off_m & 0x0001) or (frag_offset > 0)
                    ip_id = ident32 & 0xFFFF
                    nxt = nxt_hdr
                    pos += 8
                    ext_consumed += 8
                else:
                    nxt_hdr = raw[pos]
                    hdr_len = (raw[pos + 1] + 1) * 8
                    if hdr_len <= 0 or pos + hdr_len > n:
                        break
                    nxt = nxt_hdr
                    pos += hdr_len
                    ext_consumed += hdr_len
            l4_proto = nxt
            l4_payload_expected = max(0, eff_plen - ext_consumed)

    src_port: int | None = None
    dst_port: int | None = None
    tcp_seq: int | None = None
    tcp_seq_end: int | None = None
    tcp_flags: int | None = None
    tcp_payload_len: int | None = None

    if ip_version is not None and frag_offset == 0 and l4_proto is not None:
        if l4_proto == 6 and pos + 14 <= n:  # TCP
            src_port, dst_port, seq_no, _ack_no, doff_byte, flags_byte = struct.unpack_from(
                "!HHIIBB", raw, pos
            )
            tcp_hdr_len = ((doff_byte >> 4) & 0x0F) * 4
            if tcp_hdr_len < 20:
                tcp_hdr_len = 20
            tcp_seq = seq_no
            tcp_flags = flags_byte
            if l4_payload_expected is not None:
                tcp_payload_len = max(0, l4_payload_expected - tcp_hdr_len)
                tcp_seq_end = (tcp_seq + tcp_payload_len) & 0xFFFFFFFF
        elif l4_proto == 17 and pos + 8 <= n:  # UDP
            src_port, dst_port, _udp_len, _udp_csum = struct.unpack_from("!HHHH", raw, pos)

    return PcapPacket(
        frame_index=frame_index,
        realtime_ns=realtime_ns,
        captured_len=n,
        orig_len=orig_len,
        linktype=linktype,
        direction=direction,
        ifindex=ifindex,
        ip_version=ip_version,
        ip_total_len=ip_total_len,
        ip_id=ip_id,
        frag_offset=frag_offset,
        is_fragment=is_fragment,
        l4_proto=l4_proto,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        tcp_seq=tcp_seq,
        tcp_seq_end=tcp_seq_end,
        tcp_flags=tcp_flags,
        tcp_payload_len=tcp_payload_len,
        raw_bytes=raw,
    )


# ============================================================================
# 2. Classic `.pcap` & `.pcapng` File Readers
# ============================================================================


def _parse_classic_pcap(data: bytes) -> list[PcapPacket]:
    if len(data) < 24:
        raise ValueError("Truncated classic pcap global header (< 24 bytes)")
    magic_bytes = data[:4]
    endian, subsec_to_ns = _PCAP_MAGICS[magic_bytes]
    _ver_maj, _ver_min, _thiszone, _sigfigs, _snaplen, linktype = struct.unpack_from(
        f"{endian}HHiIII", data, 4
    )
    pos = 24
    idx = 0
    packets: list[PcapPacket] = []
    rec_fmt = f"{endian}IIII"
    while pos + 16 <= len(data):
        ts_sec, ts_subsec, incl_len, orig_len = struct.unpack_from(rec_fmt, data, pos)
        pos += 16
        if pos + incl_len > len(data):
            break
        raw = data[pos : pos + incl_len]
        pos += incl_len
        idx += 1
        rt_ns = ts_sec * 1_000_000_000 + ts_subsec * subsec_to_ns
        packets.append(_dissect_frame(idx, rt_ns, orig_len, linktype, raw))
    return packets


def _decode_pcapng_tsresol(tsresol_byte: int) -> tuple[int, int]:
    """Return `(numerator_ns, denominator)` to convert 64-bit pcapng timestamp into ns."""
    if tsresol_byte & 0x80:
        power = tsresol_byte & 0x7F
        return 1_000_000_000, 1 << power
    power = tsresol_byte & 0x7F
    if power <= 9:
        return 10 ** (9 - power), 1
    return 1, 10 ** (power - 9)


def _parse_pcapng(data: bytes) -> list[PcapPacket]:
    pos = 0
    n = len(data)
    endian = "<"
    # Per-section interface list: [(linktype, num_ns, den_ns)]
    interfaces: list[tuple[int, int, int]] = []
    packets: list[PcapPacket] = []
    frame_idx = 0

    while pos + 12 <= n:
        # Peek block type; SHB determines byte order via magic at pos + 8
        (btype_le,) = struct.unpack_from("<I", data, pos)
        if btype_le == _PCAPNG_SHB:
            if pos + 16 > n:
                break
            (bom_le,) = struct.unpack_from("<I", data, pos + 8)
            if bom_le == 0x1A2B3C4D:
                endian = "<"
            elif bom_le == 0x4D3C2B1A:
                endian = ">"
            else:
                raise ValueError(f"Invalid pcapng SHB byte-order magic: 0x{bom_le:08x}")
            interfaces = []

        btype, btotal_len = struct.unpack_from(f"{endian}II", data, pos)
        if btotal_len < 12 or pos + btotal_len > n:
            break

        body_start = pos + 8
        body_end = pos + btotal_len - 4

        if btype == _PCAPNG_IDB and body_start + 8 <= body_end:
            linktype, _reserved, _snaplen = struct.unpack_from(
                f"{endian}HHI", data, body_start
            )
            num_ns, den_ns = 1_000, 1  # Default pcapng resolution is 10^-6 s (1 µs)
            opt_pos = body_start + 8
            while opt_pos + 4 <= body_end:
                opt_code, opt_len = struct.unpack_from(f"{endian}HH", data, opt_pos)
                opt_pos += 4
                if opt_code == 0:
                    break
                if opt_code == 9 and opt_len >= 1 and opt_pos < body_end:
                    num_ns, den_ns = _decode_pcapng_tsresol(data[opt_pos])
                padded = (opt_len + 3) & ~3
                opt_pos += padded
            interfaces.append((linktype, num_ns, den_ns))

        elif btype == _PCAPNG_EPB and body_start + 20 <= body_end:
            if_id, ts_high, ts_low, cap_len, orig_len = struct.unpack_from(
                f"{endian}IIIII", data, body_start
            )
            pkt_start = body_start + 20
            if pkt_start + cap_len <= body_end:
                raw = data[pkt_start : pkt_start + cap_len]
                opt_pos = pkt_start + ((cap_len + 3) & ~3)
                epb_dir: int | None = None
                while opt_pos + 4 <= body_end:
                    opt_code, opt_len = struct.unpack_from(f"{endian}HH", data, opt_pos)
                    opt_pos += 4
                    if opt_code == 0:
                        break
                    if opt_code == 2 and opt_len >= 4 and opt_pos + 4 <= body_end:
                        (epb_flags,) = struct.unpack_from(f"{endian}I", data, opt_pos)
                        dir_bits = epb_flags & 0x03
                        if dir_bits == 1:
                            epb_dir = int(Dir.RX)
                        elif dir_bits == 2:
                            epb_dir = int(Dir.TX)
                    opt_pos += (opt_len + 3) & ~3

                if if_id < len(interfaces):
                    ltype, num_ns, den_ns = interfaces[if_id]
                else:
                    ltype, num_ns, den_ns = LINKTYPE_ETHERNET, 1_000, 1
                ts64 = ((ts_high & 0xFFFFFFFF) << 32) | (ts_low & 0xFFFFFFFF)
                rt_ns = (ts64 * num_ns) // den_ns
                frame_idx += 1
                packets.append(
                    _dissect_frame(frame_idx, rt_ns, orig_len, ltype, raw, epb_direction=epb_dir)
                )

        elif btype == _PCAPNG_SPB and body_start + 4 <= body_end:
            (orig_len,) = struct.unpack_from(f"{endian}I", data, body_start)
            raw = data[body_start + 4 : body_end]
            ltype = interfaces[0][0] if interfaces else LINKTYPE_ETHERNET
            frame_idx += 1
            packets.append(_dissect_frame(frame_idx, 0, orig_len, ltype, raw))

        pos += btotal_len

    return packets


def parse_capture_file(capture_path: str | os.PathLike[str]) -> list[PcapPacket]:
    """Parse classic `.pcap` or `.pcapng` capture into `PcapPacket` records."""
    path = Path(capture_path)
    data = path.read_bytes()
    if len(data) < 4:
        raise ValueError(f"Capture file too small ({len(data)} B): {path}")
    magic = data[:4]
    if magic in _PCAP_MAGICS:
        return _parse_classic_pcap(data)
    (btype_le,) = struct.unpack_from("<I", data, 0)
    if btype_le == _PCAPNG_SHB:
        return _parse_pcapng(data)
    raise ValueError(f"Unrecognized capture magic 0x{magic.hex()} in {path}")


# ============================================================================
# 3. Candidate Matching & Annotation Attachment (Level 3 ONLY)
# ============================================================================


def _tcp_seq_le(a: int, b: int) -> bool:
    """Modulo-2^32 TCP sequence comparison `a <= b`."""
    return ((b - a) & 0xFFFFFFFF) < 0x80000000


def _tcp_ranges_overlap(
    s1: int, e1: int, s2: int, e2: int
) -> bool:
    if s1 == s2:
        return True
    if e1 == s1:
        return _tcp_seq_le(s2, s1) and _tcp_seq_le(s1, e2)
    if e2 == s2:
        return _tcp_seq_le(s1, s2) and _tcp_seq_le(s2, e1)
    # Non-empty ranges [s1, e1) and [s2, e2) overlap iff s1 < e2 and s2 < e1
    return (
        _tcp_seq_le(s1, e2)
        and s1 != e2
        and _tcp_seq_le(s2, e1)
        and s2 != e1
    )


def _match_branch_against_packets(
    session: ReconstructedSession,
    branch: BranchPath,
    packets: Sequence[PcapPacket],
    *,
    window_margin_ns: int,
) -> list[TcpdumpCandidate]:
    if not branch.summaries:
        return []

    rt_start, err_start, is_cal = session.calibrate_boottime_to_realtime(branch.start_ts_ns)
    rt_end, err_end, _ = session.calibrate_boottime_to_realtime(branch.end_ts_ns)
    err_ns = max(err_start, err_end)
    win_lo = rt_start - err_ns - window_margin_ns
    win_hi = rt_end + err_ns + window_margin_ns

    xmit_steps = [
        st for st in branch.steps if int(st.get("stage", 0) or 0) == int(Stage.XMIT_START)
    ]
    had_busy_retry = branch.requeue_count > 0 or len(xmit_steps) > 1 or any(
        int(st.get("stage", 0) or 0) == int(Stage.XMIT_RET)
        and st.get("raw_ret") is not None
        and int(st["raw_ret"]) == NETDEV_TX_BUSY
        for st in branch.steps
    )
    anchor_bt_ns = xmit_steps[-1].ts_ns if xmit_steps else branch.end_ts_ns
    anchor_rt_ns, _, _ = session.calibrate_boottime_to_realtime(anchor_bt_ns)

    raw_hits: list[tuple[PcapPacket, bool, bool]] = []
    seen_frames: set[int] = set()

    for pkt in packets:
        if pkt.frame_index in seen_frames:
            continue
        if pkt.realtime_ns > 0 and not (win_lo <= pkt.realtime_ns <= win_hi):
            continue

        for summ in branch.summaries:
            s_dir = summ.get("dir")
            if (
                pkt.direction is not None
                and s_dir is not None
                and int(s_dir) in (int(Dir.RX), int(Dir.TX))
                and pkt.direction != int(s_dir)
            ):
                continue

            s_ipver = summ.get("ip_version")
            s_proto = summ.get("l4_proto")
            s_sip = summ.get("src_ip")
            s_dip = summ.get("dst_ip")
            if s_ipver is not None and pkt.ip_version != int(s_ipver):
                continue
            if s_proto is not None and pkt.l4_proto != int(s_proto):
                continue
            if s_sip is not None and pkt.src_ip != s_sip:
                continue
            if s_dip is not None and pkt.dst_ip != s_dip:
                continue

            s_sport = summ.get("src_port")
            s_dport = summ.get("dst_port")
            if s_proto in (6, 17):
                if s_sport is not None and pkt.src_port != int(s_sport):
                    continue
                if s_dport is not None and pkt.dst_port != int(s_dport):
                    continue

            s_len = int(summ.get("pkt_len", 0) or 0)
            is_superframe = False
            is_gso_seg = False

            if s_proto == 6 and summ.get("tcp_seq") is not None and pkt.tcp_seq is not None:
                b_seq = int(summ["tcp_seq"])
                b_end = int(summ.get("tcp_seq_end", b_seq) or b_seq)
                p_seq = pkt.tcp_seq
                p_end = pkt.tcp_seq_end if pkt.tcp_seq_end is not None else p_seq
                if not _tcp_ranges_overlap(b_seq, b_end, p_seq, p_end):
                    continue

                b_span = (b_end - b_seq) & 0xFFFFFFFF
                p_span = (p_end - p_seq) & 0xFFFFFFFF
                if p_span > b_span and b_span > 0:
                    is_superframe = True
                elif b_span > p_span and p_span > 0:
                    is_gso_seg = True

            if s_len > 0 and pkt.ip_total_len is not None:
                if pkt.ip_total_len > s_len + 32:
                    is_superframe = True
                elif s_len > pkt.orig_len + 32:
                    is_gso_seg = True

            seen_frames.add(pkt.frame_index)
            raw_hits.append((pkt, is_superframe, is_gso_seg))
            break

    candidates: list[TcpdumpCandidate] = []
    multi = len(raw_hits) > 1

    for idx, (pkt, is_super, is_gso_seg) in enumerate(raw_hits, start=1):
        est_bt_ns = anchor_bt_ns + (pkt.realtime_ns - anchor_rt_ns) if is_cal or pkt.realtime_ns > 0 else anchor_bt_ns
        delta_ns = pkt.realtime_ns - anchor_rt_ns if pkt.realtime_ns > 0 else 0

        is_busy_dup = bool(had_busy_retry and multi and not is_gso_seg)
        if is_busy_dup:
            mkind = "XMIT_BUSY_DUPLICATE"
            note = (
                f"xmit_one()/dev_queue_xmit_nit() BUSY 重试产生第 {idx}/{len(raw_hits)} 条外部抓包副本 "
                "(仅作辅助旁注，不新建对象身份)"
            )
        elif is_super:
            mkind = "GSO_GRO_SUPERFRAME"
            note = "外部 pcap 捕获到 GSO/GRO 聚合超大帧 (仅作辅助旁注)"
        elif is_gso_seg:
            mkind = "GSO_SEGMENT_FRAME"
            note = "外部 pcap 捕获到分段后子帧 (仅作辅助旁注)"
        elif multi:
            mkind = "AMBIGUOUS_MULTI_CANDIDATE"
            note = f"同五元组/序号存在 {len(raw_hits)} 个候选帧 (#{idx}/{len(raw_hits)}，仅作辅助旁注，不反向连边)"
        else:
            mkind = "EXACT_CANDIDATE"
            note = "外部 tcpdump 候选匹配 (仅作辅助旁注)"

        candidates.append(
            TcpdumpCandidate(
                frame_index=pkt.frame_index,
                realtime_ns=pkt.realtime_ns,
                est_boottime_ns=est_bt_ns,
                delta_from_xmit_ns=delta_ns,
                clock_err_ns=err_ns,
                evidence_level=int(EvidenceLevel.ANNOTATION),
                match_kind=mkind,
                is_busy_duplicate=is_busy_dup,
                is_superframe=is_super,
                is_gso_segment=is_gso_seg,
                attempt_index=idx if is_busy_dup else None,
                orig_len=pkt.orig_len,
                ip_total_len=pkt.ip_total_len,
                src_ip=pkt.src_ip,
                dst_ip=pkt.dst_ip,
                src_port=pkt.src_port,
                dst_port=pkt.dst_port,
                tcp_seq=pkt.tcp_seq,
                tcp_seq_end=pkt.tcp_seq_end,
                ip_id=pkt.ip_id,
                note=note,
            )
        )

    return candidates


def attach_tcpdump_candidates(
    session: ReconstructedSession,
    capture_or_packets: str | os.PathLike[str] | Sequence[PcapPacket],
    *,
    window_margin_ns: int = 50_000_000,
) -> list[TcpdumpCandidate]:
    """Attach external tcpdump matches strictly as `EvidenceLevel.ANNOTATION (3)`.

    Guarantees:
    - Never creates `RelationEdge` or `ObjectNode` entries
    - Never alters `branch.complete` or `branch.completeness`
    """
    packets = (
        parse_capture_file(capture_or_packets)
        if isinstance(capture_or_packets, (str, os.PathLike))
        else list(capture_or_packets)
    )

    all_attached: list[TcpdumpCandidate] = []
    for branch in session.branches:
        cands = _match_branch_against_packets(
            session, branch, packets, window_margin_ns=window_margin_ns
        )
        branch.tcpdump_annotations = cands
        all_attached.extend(cands)
    return all_attached
