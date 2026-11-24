"""Standard multi-interface `.pcapng` exporter (`pktpath export --format pcapng`).

Implements `详细设计.md` v3 §5.4:
- Section Header Block (SHB, `0x0A0D0D0A`, LE `0x1A2B3C4D`, v1.0)
- Distinct Interface Description Block (IDB, `0x00000001`) per unique
  `(netns_inum, ifindex, dev_gen, stage, linktype)` tuple with nanosecond `if_tsresol=9`
- Enhanced Packet Block (EPB, `0x00000006`) with `opt_comment` carrying
  `event_id`, `object_id`, `evidence_level`, `snaplen`, and `clock_err_ns`
- Cleanly handles metadata-only sessions (`--capture-hdr 0`) by writing a valid SHB
  and reporting `0` packet-header blocks exported without crashing
"""

from __future__ import annotations

import os
import struct
from pathlib import Path
from typing import Any

from .reconstruct import EVIDENCE_LABELS_ZH, STAGE_NAMES, ObjectNode, ReconstructedSession, reconstruct_session
from .redact import Redactor
from .wire import DecodedEvent, Dir, EvidenceLevel, LinkType, Stage

SHB_TYPE = 0x0A0D0D0A
IDB_TYPE = 0x00000001
EPB_TYPE = 0x00000006
PCAPNG_BOM_LE = 0x1A2B3C4D

OPT_ENDOFOPT = 0
OPT_COMMENT = 1

SHB_USERAPPL = 4

IF_NAME = 2
IF_DESCRIPTION = 3
IF_TSRESOL = 9

EPB_FLAGS = 2


def _pad4(data: bytes) -> bytes:
    rem = len(data) % 4
    return data if rem == 0 else data + (b"\x00" * (4 - rem))


def _pack_opt(code: int, val: bytes) -> bytes:
    return struct.pack("<HH", code & 0xFFFF, len(val)) + _pad4(val)


def _pack_options(opts: list[tuple[int, bytes]]) -> bytes:
    if not opts:
        return b""
    chunks = [_pack_opt(c, v) for c, v in opts]
    chunks.append(struct.pack("<HH", OPT_ENDOFOPT, 0))
    return b"".join(chunks)


def _wrap_block(block_type: int, body: bytes) -> bytes:
    padded_body = _pad4(body)
    total_len = 12 + len(padded_body)
    return (
        struct.pack("<II", block_type & 0xFFFFFFFF, total_len)
        + padded_body
        + struct.pack("<I", total_len)
    )


def _build_shb(session: ReconstructedSession, *, redacted: bool) -> bytes:
    comment = (
        f"session_uuid={session.loaded.session_uuid_str} "
        f"scope={session.manifest.get('scope', 'tc-egress')} "
        f"clock_domain={session.manifest.get('clock_domain', 'CLOCK_BOOTTIME')} "
        f"redacted={str(redacted).lower()}"
    ).encode("utf-8")
    opts = _pack_options(
        [
            (OPT_COMMENT, comment),
            (SHB_USERAPPL, b"pktpath-v3"),
        ]
    )
    # byte_order_magic(4) + major(2) + minor(2) + section_length(8, -1 = unspecified)
    body = struct.pack("<IHHq", PCAPNG_BOM_LE, 1, 0, -1) + opts
    return _wrap_block(SHB_TYPE, body)


def _build_idb(
    *,
    dev_name: str,
    netns_inum: int,
    ifindex: int,
    dev_gen: int,
    stage: int,
    linktype: int,
    snaplen: int = 262144,
) -> bytes:
    stage_name = STAGE_NAMES.get(stage, f"STAGE_{stage}")
    if_name = f"{dev_name}@ns{netns_inum}:gen{dev_gen}:{stage_name}".encode("utf-8")
    if_desc = (
        f"netns={netns_inum} ifindex={ifindex} dev_gen={dev_gen} stage={stage_name}({stage}) linktype={linktype}"
    ).encode("utf-8")
    opts = _pack_options(
        [
            (IF_NAME, if_name),
            (IF_DESCRIPTION, if_desc),
            (IF_TSRESOL, b"\x09"),  # 10^-9 s = 1 nanosecond resolution
        ]
    )
    body = struct.pack("<HHI", linktype & 0xFFFF, 0, snaplen & 0xFFFFFFFF) + opts
    return _wrap_block(IDB_TYPE, body)


def _build_epb(
    *,
    interface_id: int,
    ts_ns: int,
    pkt_bytes: bytes,
    orig_len: int,
    direction: int | None,
    comment_str: str,
) -> bytes:
    ts_u64 = max(0, ts_ns) & 0xFFFFFFFFFFFFFFFF
    ts_high = (ts_u64 >> 32) & 0xFFFFFFFF
    ts_low = ts_u64 & 0xFFFFFFFF
    cap_len = len(pkt_bytes)
    eff_orig_len = max(cap_len, orig_len)

    opt_list: list[tuple[int, bytes]] = [(OPT_COMMENT, comment_str.encode("utf-8"))]
    if direction == int(Dir.RX):
        opt_list.append((EPB_FLAGS, struct.pack("<I", 1)))  # inbound
    elif direction == int(Dir.TX):
        opt_list.append((EPB_FLAGS, struct.pack("<I", 2)))  # outbound

    opts = _pack_options(opt_list)
    body = (
        struct.pack("<IIIII", interface_id, ts_high, ts_low, cap_len, eff_orig_len)
        + _pad4(pkt_bytes)
        + opts
    )
    return _wrap_block(EPB_TYPE, body)


def _infer_summary_hook_context(
    session: ReconstructedSession,
    obj: ObjectNode,
    summ: DecodedEvent,
) -> tuple[int, int, int, int, int]:
    """Resolve `(netns_inum, ifindex, dev_gen, stage, linktype)` for a `SUMMARY` event."""
    ifindex = int(summ.get("ifindex", 0) or 0)
    site = session.resolve_site(summ.site_dict_idx)
    stage = int(site["stage"]) if site and site.get("stage") is not None else int(Stage.ENTRY)

    # Match nearest step on the same object to obtain exact (netns_inum, dev_gen, stage)
    best_step: DecodedEvent | None = None
    best_dist: int | None = None
    for st in obj.steps:
        dist = abs(st.ts_ns - summ.ts_ns)
        if best_dist is None or dist < best_dist:
            best_dist = dist
            best_step = st

    default_netns = 0
    epochs = session.dictionary.get("topology_epochs", [])
    if epochs and epochs[0].get("netns_inum") is not None:
        default_netns = int(epochs[0]["netns_inum"])

    netns_inum = int(best_step.get("netns_inum", default_netns) or default_netns) if best_step else default_netns
    dev_gen = int(best_step.get("dev_gen", 1) or 1) if best_step else 1
    if ifindex == 0 and best_step is not None:
        ifindex = int(best_step.get("ifindex", 0) or 0)
    if site is None and best_step is not None and best_step.get("stage") is not None:
        stage = int(best_step["stage"])

    if summ.get("linktype") is not None:
        linktype = int(summ["linktype"])
    else:
        linktype = session.resolve_dev_linktype(ifindex, dev_gen=dev_gen)

    return (netns_inum, ifindex, dev_gen, stage, linktype)


def export_pcapng(
    session_or_dir: ReconstructedSession | str | os.PathLike[str],
    out_path: str | os.PathLike[str],
    *,
    redact: bool = False,
    redact_key: bytes | str | None = None,
) -> dict[str, Any]:
    """Export captured `SUMMARY.hdr_bytes` into a valid multi-IDB `.pcapng` file."""
    session = (
        session_or_dir
        if isinstance(session_or_dir, ReconstructedSession)
        else reconstruct_session(session_or_dir)
    )
    out_file = Path(out_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)

    redactor = Redactor(key=redact_key) if redact else None
    chunks: list[bytes] = [_build_shb(session, redacted=redact)]

    idb_map: dict[tuple[int, int, int, int, int], int] = {}
    epb_records: list[tuple[int, int, bytes]] = []  # (sort_ts, seq, epb_bytes)

    for oid in sorted(session.objects.keys()):
        obj = session.objects[oid]
        for summ in obj.summaries:
            hdr_bytes: bytes | None = summ.get("hdr_bytes")
            if not hdr_bytes:
                continue

            idb_key = _infer_summary_hook_context(session, obj, summ)
            netns_inum, ifindex, dev_gen, stage, linktype = idb_key

            if idb_key not in idb_map:
                if_id = len(idb_map)
                idb_map[idb_key] = if_id
                dev_name = session.resolve_dev_name(ifindex, dev_gen=dev_gen, netns_inum=netns_inum, ts_ns=summ.ts_ns)
                chunks.append(
                    _build_idb(
                        dev_name=dev_name,
                        netns_inum=netns_inum,
                        ifindex=ifindex,
                        dev_gen=dev_gen,
                        stage=stage,
                        linktype=linktype,
                    )
                )
            else:
                if_id = idb_map[idb_key]

            out_hdr = (
                redactor.redact_hdr_bytes(hdr_bytes, linktype=linktype)
                if redactor is not None
                else hdr_bytes
            )
            rt_ns, err_ns, is_cal = session.calibrate_boottime_to_realtime(summ.ts_ns)
            err_txt = f"{err_ns}" if is_cal else "uncalibrated"
            ev_name = EvidenceLevel(summ.evidence_level).name if summ.evidence_level in (1, 2, 3, 4) else str(summ.evidence_level)
            ev_zh = EVIDENCE_LABELS_ZH.get(summ.evidence_level, "")
            snaplen = len(out_hdr)
            orig_len = int(summ.get("pkt_len", snaplen) or snaplen)

            comment = (
                f"event_id={summ.event_id} "
                f"object_id={summ.object_id} "
                f"sample_id={obj.primary_sample_id} "
                f"evidence_level={ev_name}({summ.evidence_level}:{ev_zh}) "
                f"snaplen={snaplen} "
                f"clock_err_ns={err_txt}"
            )
            epb = _build_epb(
                interface_id=if_id,
                ts_ns=rt_ns,
                pkt_bytes=out_hdr,
                orig_len=orig_len,
                direction=summ.get("dir"),
                comment_str=comment,
            )
            epb_records.append((summ.ts_ns, summ.seq, epb))

    epb_records.sort(key=lambda item: (item[0], item[1]))
    chunks.extend(epb for _, _, epb in epb_records)

    out_file.write_bytes(b"".join(chunks))

    return {
        "out_path": str(out_file),
        "exported_packets": len(epb_records),
        "interfaces": len(idb_map),
        "metadata_only": len(epb_records) == 0,
        "redacted": redact,
    }
