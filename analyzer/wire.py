"""Canonical v1.0 wire binary codec and crash-tolerant session loader.

Matches `include/pktpath_wire.h` and `详细设计.md` v3 Appendix B byte-for-byte:
- `pkt_block_hdr_v1` (`<IHHHHIIIII16sQQ`, 64 B) + `payload[payload_len]` + `<I` IEEE CRC32
- `pkt_event_hdr_v1` (`<HHBBHIIQQQ`, 40 B) + unpadded packed TLVs (`<HH` + `val[len]`)
"""

from __future__ import annotations

import enum
import io
import ipaddress
import json
import os
import struct
import uuid
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, BinaryIO, Sequence

# ============================================================================
# 1. Wire Format v1.0 Constants & Struct Layouts
# ============================================================================

BLOCK_MAGIC = 0x42544B50  # "PKTB" in little-endian
WIRE_MAJOR = 1
WIRE_MINOR = 0
MAX_PAYLOAD_LEN = 16 * 1024 * 1024  # 16,777,216 bytes (16 MiB hard cap)
TLV_MUST_UNDERSTAND = 0x8000
USERSPACE_CPU = 0xFFFFFFFF

BLOCK_HDR_FMT = "<IHHHHIIIII16sQQ"
BLOCK_HDR_SIZE = 64
CRC32_FMT = "<I"
CRC32_SIZE = 4

EVENT_HDR_FMT = "<HHBBHIIQQQ"
EVENT_HDR_SIZE = 40

TLV_HDR_FMT = "<HH"
TLV_HDR_SIZE = 4

assert struct.calcsize(BLOCK_HDR_FMT) == BLOCK_HDR_SIZE
assert struct.calcsize(EVENT_HDR_FMT) == EVENT_HDR_SIZE
assert struct.calcsize(TLV_HDR_FMT) == TLV_HDR_SIZE

BLOCK_FLAG_ZSTD = 1 << 0


class BlockType(enum.IntEnum):
    EVENT_BATCH = 1
    QUALITY_CHECKPOINT = 2
    DICT_DELTA = 3
    END_MARKER = 4


class ProducerType(enum.IntEnum):
    KERNEL_BPF = 1
    RTNETLINK = 2
    USERSPACE_APP = 3
    CONTROLLER = 4


class EventKind(enum.IntEnum):
    OBJECT = 1
    STEP = 2
    RELATION = 3
    SUMMARY = 4
    QSTATE = 5
    QUALITY = 6


class ObjectType(enum.IntEnum):
    SKB = 1
    XDP_FRAME = 2
    SOCK_SPAN = 3
    APP_MSG = 4
    HW_DESC = 5


class EvidenceLevel(enum.IntEnum):
    DIRECT = 1
    CONTRACT_DERIVED = 2
    ANNOTATION = 3
    GAP = 4


class EventFlags(enum.IntFlag):
    NONE = 0
    IN_TASK = 1 << 0
    NONLINEAR_TRUNC = 1 << 1
    PARTIAL_COVERAGE = 1 << 2


class EndReason(enum.IntEnum):
    OPEN = 0
    TX_OK = 1
    DROP = 2
    CONSUME = 3
    SOCK_ENQUEUE = 4
    APP_READ = 5
    TIMEOUT_TRUNCATED = 6
    CONFLICT_TRUNCATED = 7
    BOUNDARY = 8


class Dir(enum.IntEnum):
    RX = 0
    TX = 1
    FWD = 2


class Stage(enum.IntEnum):
    ENTRY = 1
    CLASSIFY = 2
    QDISC_ENQ = 3
    QDISC_ENQ_RET = 4
    QDISC_DEQ = 5
    BYPASS_DIRECT = 6
    REQUEUE_GSO = 7
    REQUEUE_BAD_TXQ = 8
    XMIT_START = 9
    XMIT_RET = 10
    DELIVER_SOCK = 11
    DROP = 12
    CONSUME = 13
    HANDOFF_LAYER = 14


class RelType(enum.IntEnum):
    CLONE = 1
    COPY = 2
    REPLACE = 3
    SEGMENT = 4
    MERGE = 5
    HANDOFF = 6
    SPAN_MAP = 7


class RelFlags(enum.IntFlag):
    NONE = 0
    SUCCESSOR_TRUNCATED = 1 << 0
    UNKNOWN_PREDECESSORS = 1 << 1


class LinkType(enum.IntEnum):
    ETHERNET = 1
    RAW_IP = 101


class QStateOp(enum.IntEnum):
    TXQ_STOP = 1
    TXQ_WAKE = 2
    BQL_LIMIT = 3


class QualKind(enum.IntEnum):
    MISSED_DELTA = 1
    RB_DROP_DELTA = 2
    EPOCH_SWITCH = 3
    RET_UNMATCHED = 4
    IDENTITY_CONFLICT = 5
    RING_EVICTED_PREFIX = 6
    TOPO_DESYNC = 7


# ============================================================================
# 2. Canonical TLV Tag Constants & Schema Table
# ============================================================================

# OBJECT (1)
TLV_OBJ_SAMPLE_ID = 0x0001
TLV_OBJ_END_REASON = 0x0002
TLV_OBJ_DROP_REASON = 0x0003

# STEP (2)
TLV_STEP_VISIT_ID = 0x0101
TLV_STEP_CALL_ID = 0x0102
TLV_STEP_NETNS_INUM = 0x0103
TLV_STEP_DEV_GEN = 0x0104
TLV_STEP_IFINDEX = 0x0105
TLV_STEP_DIR = 0x0106
TLV_STEP_STAGE = 0x0107
TLV_STEP_QUEUE_GEN = 0x0108
TLV_STEP_QDISC_HANDLE = 0x0109
TLV_STEP_QDISC_PARENT = 0x010A
TLV_STEP_CLASSID = 0x010B
TLV_STEP_BUCKET = 0x010C
TLV_STEP_TXQ = 0x010D
TLV_STEP_RAW_RET = 0x010E
TLV_STEP_CTX_TID = 0x010F

# RELATION (3)
TLV_REL_OP_ID = 0x0201
TLV_REL_TYPE = 0x0202
TLV_REL_SRC_OBJECT_ID = 0x0203
TLV_REL_DST_OBJECT_ID = 0x0204
TLV_REL_FLAGS = 0x0205
TLV_REL_STREAM_OFFSET = 0x0206
TLV_REL_SPAN_LEN = 0x0207

# SUMMARY (4)
TLV_SUM_PKT_LEN = 0x0301
TLV_SUM_LINEAR_LEN = 0x0302
TLV_SUM_IFINDEX = 0x0303
TLV_SUM_DIR = 0x0304
TLV_SUM_IP_VERSION = 0x0305
TLV_SUM_L4_PROTO = 0x0306
TLV_SUM_SRC_IP = 0x0307
TLV_SUM_DST_IP = 0x0308
TLV_SUM_SRC_PORT = 0x0309
TLV_SUM_DST_PORT = 0x030A
TLV_SUM_TCP_SEQ = 0x030B
TLV_SUM_TCP_SEQ_END = 0x030C
TLV_SUM_TCP_FLAGS = 0x030D
TLV_SUM_IP_ID = 0x030E
TLV_SUM_FRAG_FLAGS = 0x030F
TLV_SUM_SKB_HASH = 0x0310
TLV_SUM_SKB_MARK = 0x0311
TLV_SUM_SKB_PRIORITY = 0x0312
TLV_SUM_UID = 0x0313
TLV_SUM_TGID = 0x0314
TLV_SUM_COMM = 0x0315
TLV_SUM_ENQUEUE_TID = 0x0316
TLV_SUM_SKB_CREATE_TS = 0x0317
TLV_SUM_HDR_BYTES = 0x0319
TLV_SUM_LINKTYPE = 0x031A
TLV_SUM_PLUGIN_VAL0 = 0x0320
TLV_SUM_PLUGIN_VAL1 = 0x0321
TLV_SUM_PLUGIN_VAL2 = 0x0322
TLV_SUM_PLUGIN_VAL3 = 0x0323

# QSTATE (5)
TLV_QS_QUEUE_GEN = 0x0401
TLV_QS_IFINDEX = 0x0402
TLV_QS_TXQ = 0x0403
TLV_QS_STATE_OP = 0x0404
TLV_QS_VALUE = 0x0405

# QUALITY (6)
TLV_QUAL_KIND = 0x0501
TLV_QUAL_SITE_DICT_IDX = 0x0502
TLV_QUAL_WIN_START_NS = 0x0503
TLV_QUAL_WIN_END_NS = 0x0504
TLV_QUAL_COUNT = 0x0505

# Mapping: base_tag -> (field_name, kind_codec)
# kind_codec in {"u8", "u16", "u32", "s32", "u64", "ip", "comm", "bytes"}
KNOWN_TLV_SPECS: dict[int, tuple[str, str]] = {
    # OBJECT
    TLV_OBJ_SAMPLE_ID: ("sample_id", "u64"),
    TLV_OBJ_END_REASON: ("end_reason", "u16"),
    TLV_OBJ_DROP_REASON: ("drop_reason", "u32"),
    # STEP
    TLV_STEP_VISIT_ID: ("visit_id", "u64"),
    TLV_STEP_CALL_ID: ("call_id", "u64"),
    TLV_STEP_NETNS_INUM: ("netns_inum", "u32"),
    TLV_STEP_DEV_GEN: ("dev_gen", "u32"),
    TLV_STEP_IFINDEX: ("ifindex", "u32"),
    TLV_STEP_DIR: ("dir", "u8"),
    TLV_STEP_STAGE: ("stage", "u8"),
    TLV_STEP_QUEUE_GEN: ("queue_gen", "u64"),
    TLV_STEP_QDISC_HANDLE: ("qdisc_handle", "u32"),
    TLV_STEP_QDISC_PARENT: ("qdisc_parent", "u32"),
    TLV_STEP_CLASSID: ("classid", "u32"),
    TLV_STEP_BUCKET: ("bucket", "u32"),
    TLV_STEP_TXQ: ("txq", "u16"),
    TLV_STEP_RAW_RET: ("raw_ret", "s32"),
    TLV_STEP_CTX_TID: ("ctx_tid", "u32"),
    # RELATION
    TLV_REL_OP_ID: ("op_id", "u64"),
    TLV_REL_TYPE: ("rel_type", "u8"),
    TLV_REL_SRC_OBJECT_ID: ("src_object_id", "u64"),
    TLV_REL_DST_OBJECT_ID: ("dst_object_id", "u64"),
    TLV_REL_FLAGS: ("rel_flags", "u8"),
    TLV_REL_STREAM_OFFSET: ("stream_offset", "u64"),
    TLV_REL_SPAN_LEN: ("span_len", "u32"),
    # SUMMARY
    TLV_SUM_PKT_LEN: ("pkt_len", "u32"),
    TLV_SUM_LINEAR_LEN: ("linear_len", "u32"),
    TLV_SUM_IFINDEX: ("ifindex", "u32"),
    TLV_SUM_DIR: ("dir", "u8"),
    TLV_SUM_IP_VERSION: ("ip_version", "u8"),
    TLV_SUM_L4_PROTO: ("l4_proto", "u8"),
    TLV_SUM_SRC_IP: ("src_ip", "ip"),
    TLV_SUM_DST_IP: ("dst_ip", "ip"),
    TLV_SUM_SRC_PORT: ("src_port", "u16"),
    TLV_SUM_DST_PORT: ("dst_port", "u16"),
    TLV_SUM_TCP_SEQ: ("tcp_seq", "u32"),
    TLV_SUM_TCP_SEQ_END: ("tcp_seq_end", "u32"),
    TLV_SUM_TCP_FLAGS: ("tcp_flags", "u8"),
    TLV_SUM_IP_ID: ("ip_id", "u16"),
    TLV_SUM_FRAG_FLAGS: ("frag_flags", "u8"),
    TLV_SUM_SKB_HASH: ("skb_hash", "u32"),
    TLV_SUM_SKB_MARK: ("skb_mark", "u32"),
    TLV_SUM_SKB_PRIORITY: ("skb_priority", "u32"),
    TLV_SUM_UID: ("uid", "u32"),
    TLV_SUM_TGID: ("tgid", "u32"),
    TLV_SUM_COMM: ("comm", "comm"),
    TLV_SUM_ENQUEUE_TID: ("enqueue_tid", "u32"),
    TLV_SUM_SKB_CREATE_TS: ("skb_create_ts", "u64"),
    TLV_SUM_HDR_BYTES: ("hdr_bytes", "bytes"),
    TLV_SUM_LINKTYPE: ("linktype", "u16"),
    TLV_SUM_PLUGIN_VAL0: ("plugin_val0", "u64"),
    TLV_SUM_PLUGIN_VAL1: ("plugin_val1", "u64"),
    TLV_SUM_PLUGIN_VAL2: ("plugin_val2", "u64"),
    TLV_SUM_PLUGIN_VAL3: ("plugin_val3", "u64"),
    # QSTATE
    TLV_QS_QUEUE_GEN: ("queue_gen", "u64"),
    TLV_QS_IFINDEX: ("ifindex", "u32"),
    TLV_QS_TXQ: ("txq", "u16"),
    TLV_QS_STATE_OP: ("state_op", "u8"),
    TLV_QS_VALUE: ("value", "u32"),
    # QUALITY
    TLV_QUAL_KIND: ("qual_kind", "u8"),
    TLV_QUAL_SITE_DICT_IDX: ("qual_site_dict_idx", "u16"),
    TLV_QUAL_WIN_START_NS: ("win_start_ns", "u64"),
    TLV_QUAL_WIN_END_NS: ("win_end_ns", "u64"),
    TLV_QUAL_COUNT: ("count", "u64"),
}

_SCALAR_CODECS: dict[str, tuple[str, int]] = {
    "u8": ("<B", 1),
    "u16": ("<H", 2),
    "u32": ("<I", 4),
    "s32": ("<i", 4),
    "u64": ("<Q", 8),
}


# ============================================================================
# 3. Wire Exceptions & Data Models
# ============================================================================


class WireError(ValueError):
    """Base error for pktpath wire format validation failures."""


class WireMagicError(WireError):
    """Block magic does not match 0x42544B50 ('PKTB')."""


class WireVersionError(WireError):
    """Incompatible major wire version."""


class WirePayloadTooLargeError(WireError):
    """Block payload_len exceeds 16 MiB hard safety limit."""


class WireCRCError(WireError):
    """Block IEEE CRC32 mismatch."""


class WireTruncatedError(WireError):
    """Truncated block, event, or TLV stream."""


class SessionUUIDMismatchError(WireError):
    """Session UUID differs across blocks or disagrees with manifest.json."""


@dataclass(frozen=True)
class UnknownTLV:
    tag: int
    length: int
    raw_bytes: bytes
    must_understand: bool

    @property
    def raw_hex(self) -> str:
        return self.raw_bytes.hex()

    def to_dict(self) -> dict[str, Any]:
        return {
            "tag": self.tag,
            "tag_hex": f"0x{self.tag:04x}",
            "len": self.length,
            "must_understand": self.must_understand,
            "raw_hex": self.raw_hex,
        }


@dataclass
class DecodedEvent:
    total_len: int
    kind: int
    object_type: int
    evidence_level: int
    site_dict_idx: int
    cpu: int
    flags: int
    seq: int
    ts_ns: int
    object_id: int
    producer_type: int = int(ProducerType.KERNEL_BPF)
    epoch: int = 1
    block_no: int = 0
    fields: dict[str, Any] = field(default_factory=dict)
    raw_tlvs: list[tuple[int, bytes]] = field(default_factory=list)
    unknown_optional_tlvs: list[UnknownTLV] = field(default_factory=list)
    unknown_must_tlvs: list[UnknownTLV] = field(default_factory=list)

    @property
    def event_id(self) -> str:
        return f"p{self.producer_type}:c{self.cpu}:s{self.seq}"

    @property
    def dedup_key(self) -> tuple[int, int, int]:
        return (self.producer_type, self.cpu, self.seq)

    @property
    def has_unknown_must_tlv(self) -> bool:
        return bool(self.unknown_must_tlvs)

    def get(self, key: str, default: Any = None) -> Any:
        return self.fields.get(key, default)

    def __getitem__(self, key: str) -> Any:
        return self.fields[key]

    def __contains__(self, key: object) -> bool:
        return key in self.fields


@dataclass(frozen=True)
class BlockHeader:
    magic: int
    major: int
    minor: int
    block_type: int
    producer_type: int
    flags: int
    payload_len: int
    epoch: int
    block_no: int
    reserved: int
    session_uuid: bytes
    min_ts_ns: int
    max_ts_ns: int

    @property
    def session_uuid_hex(self) -> str:
        return self.session_uuid.hex()

    @property
    def session_uuid_str(self) -> str:
        return str(uuid.UUID(bytes=self.session_uuid))


@dataclass
class BlockRecord:
    header: BlockHeader
    crc32: int
    events: list[DecodedEvent] = field(default_factory=list)
    meta_payload: dict[str, Any] | None = None
    source_file: str = ""


@dataclass
class LoadedSession:
    run_dir: Path
    manifest: dict[str, Any]
    dictionary: dict[str, Any]
    session_uuid: bytes
    blocks: list[BlockRecord]
    events: list[DecodedEvent]
    has_end_marker: bool
    has_corrupted_tail: bool
    tail_errors: list[str]
    last_quality_checkpoint_ts_ns: int

    @property
    def session_uuid_str(self) -> str:
        return str(uuid.UUID(bytes=self.session_uuid))

    @property
    def unclean_tail(self) -> bool:
        return (not self.has_end_marker) or self.has_corrupted_tail


# ============================================================================
# 4. UUID Normalization & Binary Decoding / Encoding Functions
# ============================================================================


def parse_uuid_bytes(val: bytes | str | uuid.UUID) -> bytes:
    if isinstance(val, bytes):
        if len(val) != 16:
            raise ValueError(f"UUID bytes must be 16 bytes, got {len(val)}")
        return val
    if isinstance(val, uuid.UUID):
        return val.bytes
    cleaned = str(val).strip()
    return uuid.UUID(cleaned).bytes


def decode_block_header(hdr_bytes: bytes) -> BlockHeader:
    """Validate and unpack a 64-byte `pkt_block_hdr_v1` BEFORE payload allocation."""
    if len(hdr_bytes) < BLOCK_HDR_SIZE:
        if len(hdr_bytes) >= 4:
            (magic_peek,) = struct.unpack_from("<I", hdr_bytes, 0)
            if magic_peek != BLOCK_MAGIC:
                raise WireMagicError(
                    f"Invalid block magic 0x{magic_peek:08x} (expected 0x{BLOCK_MAGIC:08x})"
                )
        raise WireTruncatedError(
            f"Truncated block header: expected {BLOCK_HDR_SIZE} bytes, got {len(hdr_bytes)}"
        )

    (
        magic,
        major,
        minor,
        block_type,
        producer_type,
        flags,
        payload_len,
        epoch,
        block_no,
        reserved,
        session_uuid,
        min_ts_ns,
        max_ts_ns,
    ) = struct.unpack(BLOCK_HDR_FMT, hdr_bytes[:BLOCK_HDR_SIZE])

    if magic != BLOCK_MAGIC:
        raise WireMagicError(
            f"Invalid block magic 0x{magic:08x} (expected 0x{BLOCK_MAGIC:08x})"
        )
    if major != WIRE_MAJOR:
        raise WireVersionError(
            f"Incompatible wire major version {major}.{minor} (expected major={WIRE_MAJOR})"
        )
    if payload_len > MAX_PAYLOAD_LEN:
        raise WirePayloadTooLargeError(
            f"Block payload_len {payload_len} exceeds 16 MiB cap ({MAX_PAYLOAD_LEN})"
        )

    return BlockHeader(
        magic=magic,
        major=major,
        minor=minor,
        block_type=block_type,
        producer_type=producer_type,
        flags=flags,
        payload_len=payload_len,
        epoch=epoch,
        block_no=block_no,
        reserved=reserved,
        session_uuid=session_uuid,
        min_ts_ns=min_ts_ns,
        max_ts_ns=max_ts_ns,
    )


def _decompress_payload_if_needed(payload: bytes, flags: int) -> bytes:
    if not (flags & BLOCK_FLAG_ZSTD):
        return payload
    try:
        from compression import zstd as _stdlib_zstd  # type: ignore[import-not-found]

        decompressed = _stdlib_zstd.decompress(payload)
        if len(decompressed) > MAX_PAYLOAD_LEN:
            raise WirePayloadTooLargeError(
                f"Decompressed payload {len(decompressed)} exceeds 16 MiB cap"
            )
        return decompressed
    except ImportError as exc:
        raise WireError("Block has ZSTD flag set, but stdlib zstd is unavailable") from exc


def decode_event(
    buf: bytes | memoryview,
    offset: int = 0,
    *,
    producer_type: int = int(ProducerType.KERNEL_BPF),
    epoch: int = 1,
    block_no: int = 0,
) -> tuple[DecodedEvent, int]:
    """Decode one `pkt_event_hdr_v1` + packed TLVs starting at `offset`."""
    mv = memoryview(buf)
    rem = len(mv) - offset
    if rem < EVENT_HDR_SIZE:
        raise WireTruncatedError(
            f"Truncated event header at offset {offset}: {rem} < {EVENT_HDR_SIZE}"
        )

    (
        total_len,
        kind,
        object_type,
        evidence_level,
        site_dict_idx,
        cpu,
        flags,
        seq,
        ts_ns,
        object_id,
    ) = struct.unpack_from(EVENT_HDR_FMT, mv, offset)

    if total_len < EVENT_HDR_SIZE:
        raise WireError(f"Invalid event total_len {total_len} (< {EVENT_HDR_SIZE})")
    if total_len > rem:
        raise WireTruncatedError(
            f"Truncated event payload at offset {offset}: need {total_len}, have {rem}"
        )

    fields: dict[str, Any] = {}
    raw_tlvs: list[tuple[int, bytes]] = []
    unknown_opt: list[UnknownTLV] = []
    unknown_must: list[UnknownTLV] = []

    pos = offset + EVENT_HDR_SIZE
    end = offset + total_len
    while pos < end:
        if end - pos < TLV_HDR_SIZE:
            raise WireTruncatedError(f"Truncated TLV header at byte {pos}")
        tag, tlv_len = struct.unpack_from(TLV_HDR_FMT, mv, pos)
        pos += TLV_HDR_SIZE
        if end - pos < tlv_len:
            raise WireTruncatedError(
                f"Truncated TLV 0x{tag:04x} value: need {tlv_len}, have {end - pos}"
            )
        val_bytes = bytes(mv[pos : pos + tlv_len])
        pos += tlv_len
        raw_tlvs.append((tag, val_bytes))

        must_understand = bool(tag & TLV_MUST_UNDERSTAND)
        base_tag = tag & 0x7FFF
        spec = KNOWN_TLV_SPECS.get(base_tag)

        if spec is None:
            unk = UnknownTLV(
                tag=tag,
                length=tlv_len,
                raw_bytes=val_bytes,
                must_understand=must_understand,
            )
            if must_understand:
                unknown_must.append(unk)
            else:
                unknown_opt.append(unk)
            continue

        field_name, codec = spec
        if codec in _SCALAR_CODECS:
            fmt, expected_len = _SCALAR_CODECS[codec]
            if tlv_len != expected_len:
                if must_understand:
                    unknown_must.append(
                        UnknownTLV(tag=tag, length=tlv_len, raw_bytes=val_bytes, must_understand=True)
                    )
                else:
                    unknown_opt.append(
                        UnknownTLV(tag=tag, length=tlv_len, raw_bytes=val_bytes, must_understand=False)
                    )
                continue
            (val,) = struct.unpack(fmt, val_bytes)
            fields[field_name] = val
            if base_tag == TLV_QUAL_SITE_DICT_IDX and "site_dict_idx" not in fields:
                fields["site_dict_idx"] = val
        elif codec == "ip":
            if tlv_len in (4, 16):
                ip_obj = ipaddress.ip_address(val_bytes)
                fields[field_name] = str(ip_obj)
                fields[f"{field_name}_raw"] = val_bytes
            else:
                if must_understand:
                    unknown_must.append(
                        UnknownTLV(tag=tag, length=tlv_len, raw_bytes=val_bytes, must_understand=True)
                    )
                else:
                    unknown_opt.append(
                        UnknownTLV(tag=tag, length=tlv_len, raw_bytes=val_bytes, must_understand=False)
                    )
        elif codec == "comm":
            fields["comm_raw"] = val_bytes
            fields[field_name] = val_bytes.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
        elif codec == "bytes":
            fields[field_name] = val_bytes

    ev = DecodedEvent(
        total_len=total_len,
        kind=kind,
        object_type=object_type,
        evidence_level=evidence_level,
        site_dict_idx=site_dict_idx,
        cpu=cpu,
        flags=flags,
        seq=seq,
        ts_ns=ts_ns,
        object_id=object_id,
        producer_type=producer_type,
        epoch=epoch,
        block_no=block_no,
        fields=fields,
        raw_tlvs=raw_tlvs,
        unknown_optional_tlvs=unknown_opt,
        unknown_must_tlvs=unknown_must,
    )
    return ev, end


def encode_event(ev: DecodedEvent, raw_tlvs: Sequence[tuple[int, bytes]] | None = None) -> bytes:
    """Encode a `DecodedEvent` back to binary v1.0 wire bytes."""
    tlv_list = ev.raw_tlvs if raw_tlvs is None else raw_tlvs
    tlv_chunks: list[bytes] = []
    for tag, val in tlv_list:
        tlv_chunks.append(struct.pack(TLV_HDR_FMT, tag & 0xFFFF, len(val)) + val)
    tlv_blob = b"".join(tlv_chunks)
    total_len = EVENT_HDR_SIZE + len(tlv_blob)
    hdr = struct.pack(
        EVENT_HDR_FMT,
        total_len,
        ev.kind & 0xFFFF,
        ev.object_type & 0xFF,
        ev.evidence_level & 0xFF,
        ev.site_dict_idx & 0xFFFF,
        ev.cpu & 0xFFFFFFFF,
        ev.flags & 0xFFFFFFFF,
        ev.seq & 0xFFFFFFFFFFFFFFFF,
        ev.ts_ns & 0xFFFFFFFFFFFFFFFF,
        ev.object_id & 0xFFFFFFFFFFFFFFFF,
    )
    return hdr + tlv_blob


def encode_block(header: BlockHeader, payload: bytes) -> bytes:
    """Encode a 64B `pkt_block_hdr_v1` + `payload` + IEEE CRC32."""
    if len(payload) > MAX_PAYLOAD_LEN:
        raise WirePayloadTooLargeError(f"Payload length {len(payload)} exceeds {MAX_PAYLOAD_LEN}")
    hdr = struct.pack(
        BLOCK_HDR_FMT,
        header.magic & 0xFFFFFFFF,
        header.major & 0xFFFF,
        header.minor & 0xFFFF,
        header.block_type & 0xFFFF,
        header.producer_type & 0xFFFF,
        header.flags & 0xFFFFFFFF,
        len(payload) & 0xFFFFFFFF,
        header.epoch & 0xFFFFFFFF,
        header.block_no & 0xFFFFFFFF,
        header.reserved & 0xFFFFFFFF,
        header.session_uuid,
        header.min_ts_ns & 0xFFFFFFFFFFFFFFFF,
        header.max_ts_ns & 0xFFFFFFFFFFFFFFFF,
    )
    body = hdr + payload
    crc = zlib.crc32(body) & 0xFFFFFFFF
    return body + struct.pack(CRC32_FMT, crc)


def _read_one_block_from_stream(
    stream: BinaryIO,
    *,
    source_name: str = "",
) -> BlockRecord | None:
    """Read and validate a single block from `stream` without OOM pre-allocation."""
    hdr_bytes = stream.read(BLOCK_HDR_SIZE)
    if not hdr_bytes:
        return None
    header = decode_block_header(hdr_bytes)

    # Safe to allocate now that payload_len <= 16 MiB is verified
    payload = stream.read(header.payload_len)
    if len(payload) < header.payload_len:
        raise WireTruncatedError(
            f"Truncated block payload in {source_name}: expected {header.payload_len}, got {len(payload)}"
        )
    crc_bytes = stream.read(CRC32_SIZE)
    if len(crc_bytes) < CRC32_SIZE:
        raise WireTruncatedError(f"Truncated block CRC32 trailer in {source_name}")

    (expected_crc,) = struct.unpack(CRC32_FMT, crc_bytes)
    actual_crc = zlib.crc32(hdr_bytes + payload) & 0xFFFFFFFF
    if actual_crc != expected_crc:
        raise WireCRCError(
            f"CRC32 mismatch in {source_name} block #{header.block_no}: "
            f"expected 0x{expected_crc:08x}, computed 0x{actual_crc:08x}"
        )

    decoded_payload = _decompress_payload_if_needed(payload, header.flags)
    events: list[DecodedEvent] = []
    meta_payload: dict[str, Any] | None = None

    if len(decoded_payload) > 0:
        if header.block_type in (BlockType.DICT_DELTA, BlockType.END_MARKER, BlockType.QUALITY_CHECKPOINT) and decoded_payload[:1] == b"{":
            try:
                meta_payload = json.loads(decoded_payload.decode("utf-8"))
            except json.JSONDecodeError as exc:
                raise WireError(f"Malformed JSON payload in {source_name}: {exc}") from exc
        else:
            offset = 0
            mv = memoryview(decoded_payload)
            while offset < len(mv):
                ev, offset = decode_event(
                    mv,
                    offset,
                    producer_type=header.producer_type,
                    epoch=header.epoch,
                    block_no=header.block_no,
                )
                events.append(ev)

    return BlockRecord(
        header=header,
        crc32=expected_crc,
        events=events,
        meta_payload=meta_payload,
        source_file=source_name,
    )


def decode_block(data: bytes, *, source_name: str = "<memory>") -> BlockRecord:
    """Strictly decode a single `.pktb` block from `bytes`."""
    stream = io.BytesIO(data)
    blk = _read_one_block_from_stream(stream, source_name=source_name)
    if blk is None:
        raise WireTruncatedError(f"Empty block buffer in {source_name}")
    return blk


# ============================================================================
# 5. Session Directory Loader (with Crash / Power-Loss Tail Handling)
# ============================================================================


def _merge_dict_delta(dictionary: dict[str, Any], delta: dict[str, Any]) -> None:
    if "sites" in delta and isinstance(delta["sites"], list):
        existing = {s.get("site_idx"): s for s in dictionary.setdefault("sites", [])}
        for s in delta["sites"]:
            existing[s.get("site_idx")] = s
        dictionary["sites"] = [existing[k] for k in sorted(k for k in existing if k is not None)]
    if "topology_epochs" in delta and isinstance(delta["topology_epochs"], list):
        dictionary.setdefault("topology_epochs", []).extend(delta["topology_epochs"])


def load_session(
    run_dir: str | os.PathLike[str],
    *,
    strict_tail: bool = False,
) -> LoadedSession:
    """Load `manifest.json`, `dict.json`, and all valid `block_*.pktb` files in `run_dir`.

    Enforces:
    - Magic == 0x42544B50 ('PKTB'), Major == 1, payload_len <= 16 MiB (pre-read check!)
    - Consistent `session_uuid` across `manifest.json` and every block
    - Crash/power-loss tolerance (`strict_tail=False`): if a trailing `.pktb` block is
      truncated or fails IEEE CRC32, or `END_MARKER` is absent, replays all prior
      CRC-valid blocks and records `has_corrupted_tail` / `last_quality_checkpoint_ts_ns`
      so downstream reconstruction marks post-checkpoint / open paths `UNKNOWN_TAIL`.
    """
    root = Path(run_dir)
    if not root.is_dir():
        raise FileNotFoundError(f"Session directory not found: {root}")

    manifest_path = root / "manifest.json"
    dict_path = root / "dict.json"

    manifest: dict[str, Any] = {}
    if manifest_path.is_file():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    dictionary: dict[str, Any] = {"sites": [], "topology_epochs": []}
    if dict_path.is_file():
        loaded_dict = json.loads(dict_path.read_text(encoding="utf-8"))
        if isinstance(loaded_dict, dict):
            dictionary.update(loaded_dict)

    expected_uuid: bytes | None = None
    if manifest.get("session_uuid"):
        expected_uuid = parse_uuid_bytes(manifest["session_uuid"])

    block_files = sorted(p for p in root.glob("block_*.pktb") if p.is_file())
    if not block_files:
        block_files = sorted(p for p in root.glob("*.pktb") if p.is_file())

    valid_blocks: list[BlockRecord] = []
    all_events: list[DecodedEvent] = []
    has_end_marker = False
    has_corrupted_tail = False
    tail_errors: list[str] = []
    last_checkpoint_ts_ns = 0

    # Leftover uncommitted `.tmp` block files indicate interrupted atomic write
    tmp_files = sorted(p.name for p in root.glob("*.tmp") if p.is_file())
    if tmp_files:
        tail_errors.append(f"Uncommitted temporary files present: {', '.join(tmp_files)}")

    for file_idx, blk_path in enumerate(block_files):
        is_last_file = file_idx == len(block_files) - 1
        with blk_path.open("rb") as f:
            block_in_file_idx = 0
            while True:
                try:
                    blk = _read_one_block_from_stream(
                        f,
                        source_name=blk_path.name,
                    )
                except (WireCRCError, WireTruncatedError) as exc:
                    if strict_tail:
                        raise
                    # Crash / power-loss tail corruption: stop replaying from tail onward
                    if is_last_file or valid_blocks:
                        has_corrupted_tail = True
                        tail_errors.append(str(exc))
                        blk = None
                        break
                    raise

                if blk is None:
                    if block_in_file_idx == 0 and blk_path.stat().st_size == 0:
                        if strict_tail:
                            raise WireTruncatedError(f"Zero-length block file {blk_path.name}")
                        has_corrupted_tail = True
                        tail_errors.append(f"Zero-length trailing block file {blk_path.name}")
                    break

                block_in_file_idx += 1

                if expected_uuid is None:
                    expected_uuid = blk.header.session_uuid
                elif blk.header.session_uuid != expected_uuid:
                    raise SessionUUIDMismatchError(
                        f"Session UUID mismatch in {blk_path.name}: "
                        f"got {blk.header.session_uuid_str}, expected {uuid.UUID(bytes=expected_uuid)}"
                    )

                valid_blocks.append(blk)
                all_events.extend(blk.events)

                if blk.header.block_type == BlockType.QUALITY_CHECKPOINT:
                    last_checkpoint_ts_ns = max(last_checkpoint_ts_ns, blk.header.max_ts_ns)
                    for ev in blk.events:
                        last_checkpoint_ts_ns = max(
                            last_checkpoint_ts_ns,
                            ev.ts_ns,
                            int(ev.get("win_end_ns", 0) or 0),
                        )
                elif blk.header.block_type == BlockType.DICT_DELTA and blk.meta_payload:
                    _merge_dict_delta(dictionary, blk.meta_payload)
                elif blk.header.block_type == BlockType.END_MARKER:
                    has_end_marker = True
                    if blk.meta_payload and "admissions" in blk.meta_payload and not manifest.get("admissions"):
                        manifest["admissions"] = blk.meta_payload["admissions"]

            if has_corrupted_tail:
                break

    if expected_uuid is None:
        expected_uuid = bytes(16)

    return LoadedSession(
        run_dir=root,
        manifest=manifest,
        dictionary=dictionary,
        session_uuid=expected_uuid,
        blocks=valid_blocks,
        events=all_events,
        has_end_marker=has_end_marker,
        has_corrupted_tail=has_corrupted_tail,
        tail_errors=tail_errors,
        last_quality_checkpoint_ts_ns=last_checkpoint_ts_ns,
    )
