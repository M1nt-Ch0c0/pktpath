"""Evidence-centric multi-branch / multi-predecessor DAG reconstruction engine.

Implements `详细设计.md` v3 §2–§6:
1. Exact deduplication by `(producer_type, cpu, seq)` & per-stream sequence-gap windows
2. Quality-loss window intersection (`MISSED_DELTA`, `RB_DROP_DELTA`, `RET_UNMATCHED`,
   `IDENTITY_CONFLICT`, `RING_EVICTED_PREFIX`, `TOPO_DESYNC`), crash tail (`UNKNOWN_TAIL`),
   unknown must-understand TLVs (`INCOMPLETE_UNKNOWN_MUST_TLV`), and unobservable
   adapter missed counters (`missed_source == "none"` -> `completeness = "unknown"`)
3. General Object DAG (`CLONE`, `COPY`, `REPLACE`, `SEGMENT`, `MERGE`, `HANDOFF`, `SPAN_MAP`)
4. Strict `(object_id, queue_gen, visit_id)` queue sojourn pairing with `NET_XMIT_*`
   handling, cross-CPU late-return tolerance, and `QSTATE` backpressure annotations
"""

from __future__ import annotations

import os
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence

from .wire import (
    DecodedEvent,
    Dir,
    EndReason,
    EventFlags,
    EventKind,
    EvidenceLevel,
    LinkType,
    LoadedSession,
    ObjectType,
    QStateOp,
    QualKind,
    RelFlags,
    RelType,
    Stage,
    UnknownTLV,
    load_session,
)

# Linux kernel <linux/netdevice.h> return codes
NETDEV_TX_OK = 0x00
NETDEV_TX_BUSY = 0x10

NET_XMIT_SUCCESS = 0x00
NET_XMIT_DROP = 0x01
NET_XMIT_CN = 0x02
NET_XMIT_POLICED = 0x03

END_REASON_NAMES: dict[int, str] = {
    int(EndReason.OPEN): "OPEN",
    int(EndReason.TX_OK): "TX_OK",
    int(EndReason.DROP): "DROP",
    int(EndReason.CONSUME): "CONSUME",
    int(EndReason.SOCK_ENQUEUE): "SOCK_ENQUEUE",
    int(EndReason.APP_READ): "APP_READ",
    int(EndReason.TIMEOUT_TRUNCATED): "TIMEOUT_TRUNCATED",
    int(EndReason.CONFLICT_TRUNCATED): "CONFLICT_TRUNCATED",
    int(EndReason.BOUNDARY): "BOUNDARY",
}

STAGE_NAMES: dict[int, str] = {
    int(Stage.ENTRY): "ENTRY",
    int(Stage.CLASSIFY): "CLASSIFY",
    int(Stage.QDISC_ENQ): "QDISC_ENQ",
    int(Stage.QDISC_ENQ_RET): "QDISC_ENQ_RET",
    int(Stage.QDISC_DEQ): "QDISC_DEQ",
    int(Stage.BYPASS_DIRECT): "BYPASS_DIRECT",
    int(Stage.REQUEUE_GSO): "REQUEUE_GSO",
    int(Stage.REQUEUE_BAD_TXQ): "REQUEUE_BAD_TXQ",
    int(Stage.XMIT_START): "XMIT_START",
    int(Stage.XMIT_RET): "XMIT_RET",
    int(Stage.DELIVER_SOCK): "DELIVER_SOCK",
    int(Stage.DROP): "DROP",
    int(Stage.CONSUME): "CONSUME",
    int(Stage.HANDOFF_LAYER): "HANDOFF_LAYER",
}

REL_TYPE_NAMES: dict[int, str] = {
    int(RelType.CLONE): "CLONE",
    int(RelType.COPY): "COPY",
    int(RelType.REPLACE): "REPLACE",
    int(RelType.SEGMENT): "SEGMENT",
    int(RelType.MERGE): "MERGE",
    int(RelType.HANDOFF): "HANDOFF",
    int(RelType.SPAN_MAP): "SPAN_MAP",
}

QSTATE_OP_NAMES: dict[int, str] = {
    int(QStateOp.TXQ_STOP): "TXQ_STOP",
    int(QStateOp.TXQ_WAKE): "TXQ_WAKE",
    int(QStateOp.BQL_LIMIT): "BQL_LIMIT",
}

QUAL_KIND_NAMES: dict[int, str] = {
    int(QualKind.MISSED_DELTA): "MISSED_DELTA",
    int(QualKind.RB_DROP_DELTA): "RB_DROP_DELTA",
    int(QualKind.EPOCH_SWITCH): "EPOCH_SWITCH",
    int(QualKind.RET_UNMATCHED): "RET_UNMATCHED",
    int(QualKind.IDENTITY_CONFLICT): "IDENTITY_CONFLICT",
    int(QualKind.RING_EVICTED_PREFIX): "RING_EVICTED_PREFIX",
    int(QualKind.TOPO_DESYNC): "TOPO_DESYNC",
}

EVIDENCE_LABELS_ZH: dict[int, str] = {
    int(EvidenceLevel.DIRECT): "直接观测",
    int(EvidenceLevel.CONTRACT_DERIVED): "契约推导",
    int(EvidenceLevel.ANNOTATION): "辅助旁注",
    int(EvidenceLevel.GAP): "缺口/未知",
}


def format_rate_bps(rate_bps: int | None, ceil_bps: int | None = None) -> str | None:
    """Format bits/s (and optional ceil bits/s) into compact human string like '10M→20M' or '1.05G'."""
    if not rate_bps or int(rate_bps) <= 0:
        return None

    def _fmt_one(bps: int) -> str:
        if bps >= 1_000_000_000:
            val = bps / 1_000_000_000.0
            return f"{int(val)}G" if val.is_integer() else f"{val:.2f}".rstrip("0").rstrip(".") + "G"
        if bps >= 1_000_000:
            val = bps / 1_000_000.0
            return f"{int(val)}M" if val.is_integer() else f"{val:.2f}".rstrip("0").rstrip(".") + "M"
        if bps >= 1_000:
            val = bps / 1_000.0
            return f"{int(val)}K" if val.is_integer() else f"{val:.1f}".rstrip("0").rstrip(".") + "K"
        return f"{bps}bps"

    r_val = int(rate_bps)
    c_val = int(ceil_bps) if ceil_bps else 0
    if c_val > 0 and c_val != r_val:
        return f"{_fmt_one(r_val)}→{_fmt_one(c_val)}"
    return _fmt_one(r_val)


# ============================================================================
# 1. Reconstructed Data Structures
# ============================================================================


@dataclass(frozen=True)
class SeqGap:
    producer_type: int
    cpu: int
    prev_seq: int
    next_seq: int
    missing_count: int
    win_start_ns: int
    win_end_ns: int
    prev_object_id: int
    next_object_id: int


@dataclass
class CallPair:
    call_id: int
    object_id: int
    entry_event: DecodedEvent | None = None
    ret_event: DecodedEvent | None = None
    paired: bool = False
    ambiguous: bool = False
    raw_ret: int | None = None
    cross_cpu_late: bool = False


@dataclass
class QStateAnnotation:
    ifindex: int
    txq: int
    queue_gen: int
    state_op: int
    state_name: str
    start_ns: int
    end_ns: int | None = None
    value: int = 0
    event_ids: list[str] = field(default_factory=list)


@dataclass
class QueueVisit:
    object_id: int
    queue_gen: int
    visit_id: int
    visit_kind: str  # "qdisc", "requeue_gso", "requeue_bad_txq"
    netns_inum: int = 0
    ifindex: int = 0
    dev_gen: int = 0
    qdisc_handle: int = 0
    qdisc_parent: int = 0
    classid: int = 0
    bucket: int | None = None
    txq: int | None = None
    entry_event: DecodedEvent | None = None
    enq_ret_event: DecodedEvent | None = None
    exit_event: DecodedEvent | None = None
    paired: bool = False
    ambiguous: bool = False
    enq_dropped: bool = False
    enq_cn: bool = False
    enq_ret_code: int | None = None
    sojourn_ns: int | None = None
    cross_thread_dequeue: bool = False
    backpressure: list[QStateAnnotation] = field(default_factory=list)

    @property
    def sojourn_us(self) -> float | None:
        if self.sojourn_ns is None:
            return None
        return self.sojourn_ns / 1_000.0


@dataclass(frozen=True)
class RelationEdge:
    event: DecodedEvent
    op_id: int
    rel_type: int
    rel_type_name: str
    src_object_id: int
    dst_object_id: int
    rel_flags: int
    successor_truncated: bool
    unknown_predecessors: bool
    stream_offset: int | None
    span_len: int | None
    ts_ns: int


@dataclass
class ObjectNode:
    object_id: int
    object_type: int = int(ObjectType.SKB)
    sample_ids: set[int] = field(default_factory=set)
    primary_sample_id: int = 0
    object_events: list[DecodedEvent] = field(default_factory=list)
    steps: list[DecodedEvent] = field(default_factory=list)
    summaries: list[DecodedEvent] = field(default_factory=list)
    visits: list[QueueVisit] = field(default_factory=list)
    calls: list[CallPair] = field(default_factory=list)
    outgoing_relations: list[RelationEdge] = field(default_factory=list)
    incoming_relations: list[RelationEdge] = field(default_factory=list)
    explicit_end_reason: int = int(EndReason.OPEN)
    effective_end_reason: int = int(EndReason.OPEN)
    drop_reason: int | None = None
    unknown_must_tlvs: list[UnknownTLV] = field(default_factory=list)
    unknown_optional_tlvs: list[UnknownTLV] = field(default_factory=list)
    successor_truncated: bool = False
    unknown_predecessors: bool = False
    identity_conflict: bool = False
    attribution: dict[str, Any] = field(default_factory=dict)
    first_ts_ns: int = 0
    last_ts_ns: int = 0

    @property
    def predecessor_ids(self) -> list[int]:
        return [r.src_object_id for r in self.incoming_relations]

    @property
    def successor_ids(self) -> list[int]:
        return [r.dst_object_id for r in self.outgoing_relations]

    @property
    def initial_summary(self) -> DecodedEvent | None:
        return self.summaries[0] if self.summaries else None

    @property
    def latest_summary(self) -> DecodedEvent | None:
        return self.summaries[-1] if self.summaries else None


@dataclass
class BranchPath:
    branch_id: str
    sample_id: int
    branch_index: int
    object_ids: list[int]
    object_slices: list[tuple[int, int, int | None]]  # (obj_id, min_ts, max_ts_or_None)
    relation_chain: list[RelationEdge] = field(default_factory=list)
    events: list[DecodedEvent] = field(default_factory=list)
    steps: list[DecodedEvent] = field(default_factory=list)
    summaries: list[DecodedEvent] = field(default_factory=list)
    visits: list[QueueVisit] = field(default_factory=list)
    calls: list[CallPair] = field(default_factory=list)
    qstate_annotations: list[QStateAnnotation] = field(default_factory=list)
    tcpdump_annotations: list[Any] = field(default_factory=list)
    end_reason: int = int(EndReason.OPEN)
    end_reason_name: str = "OPEN"
    drop_reason: int | None = None
    complete: bool = False
    completeness: str = "incomplete"  # "complete" | "incomplete" | "unknown"
    gap_reasons: list[str] = field(default_factory=list)
    unknown_must_tlvs: list[UnknownTLV] = field(default_factory=list)
    successor_truncated: bool = False
    unknown_predecessors: bool = False
    requeue_count: int = 0
    start_ts_ns: int = 0
    end_ts_ns: int = 0

    @property
    def leaf_object_id(self) -> int:
        return self.object_ids[-1]


@dataclass
class SampleGraph:
    sample_id: int
    root_object_ids: list[int]
    object_ids: list[int]
    relations: list[RelationEdge] = field(default_factory=list)
    branches: list[BranchPath] = field(default_factory=list)
    complete: bool = False
    completeness: str = "incomplete"
    gap_reasons: list[str] = field(default_factory=list)
    successor_truncated: bool = False
    unknown_predecessors: bool = False
    attribution: dict[str, Any] = field(default_factory=dict)
    first_ts_ns: int = 0
    last_ts_ns: int = 0

    @property
    def tcpdump_annotations(self) -> list[Any]:
        seen: set[int] = set()
        out: list[Any] = []
        for br in self.branches:
            for cand in br.tcpdump_annotations:
                ident = getattr(cand, "frame_index", id(cand))
                if ident not in seen:
                    seen.add(ident)
                    out.append(cand)
        return out


@dataclass
class ReconstructedSession:
    loaded: LoadedSession
    manifest: dict[str, Any]
    dictionary: dict[str, Any]
    sites_by_idx: dict[int, dict[str, Any]]
    events: list[DecodedEvent]
    dedup_dropped_count: int
    seq_gaps: list[SeqGap]
    quality_events: list[DecodedEvent]
    qstate_events: list[DecodedEvent]
    qstate_annotations: list[QStateAnnotation]
    objects: dict[int, ObjectNode]
    relations: list[RelationEdge]
    samples: dict[int, SampleGraph]
    branches: list[BranchPath]
    unmatched_returns: list[DecodedEvent]
    has_unobservable_missed_source: bool
    unobservable_adapters: list[str]
    topo_desync_windows: list[tuple[int, int]]
    requeue_count: int
    requeue_gso_count: int
    requeue_bad_txq_count: int
    reorder_count: int

    def resolve_site(self, site_idx: int) -> dict[str, Any] | None:
        return self.sites_by_idx.get(site_idx)

    def is_topo_desynced_at(self, ts_ns: int) -> bool:
        for ws, we in self.topo_desync_windows:
            if ws <= ts_ns <= we:
                return True
        return False

    def resolve_dev_info(
        self,
        ifindex: int,
        *,
        dev_gen: int | None = None,
        netns_inum: int | None = None,
        ts_ns: int | None = None,
    ) -> dict[str, Any] | None:
        epochs = self.dictionary.get("topology_epochs", [])
        best: dict[str, Any] | None = None
        for ep in epochs:
            if netns_inum and ep.get("netns_inum") and ep["netns_inum"] != netns_inum:
                continue
            for dev in ep.get("devices", []):
                if dev.get("ifindex") != ifindex:
                    continue
                if dev_gen is not None and dev_gen != 0 and dev.get("dev_gen") not in (None, 0, dev_gen):
                    continue
                best = dev
                if ts_ns is None or ep.get("ts_ns", 0) <= ts_ns:
                    pass
        if best is None:
            for ep in epochs:
                for dev in ep.get("devices", []):
                    if dev.get("ifindex") == ifindex:
                        return dev
        return best

    def resolve_dev_name(
        self,
        ifindex: int,
        *,
        dev_gen: int | None = None,
        netns_inum: int | None = None,
        ts_ns: int | None = None,
    ) -> str:
        if ifindex == 0:
            return "if0"
        dev = self.resolve_dev_info(ifindex, dev_gen=dev_gen, netns_inum=netns_inum, ts_ns=ts_ns)
        if dev and dev.get("name"):
            return str(dev["name"])
        return f"if{ifindex}"

    def resolve_dev_linktype(self, ifindex: int, *, dev_gen: int | None = None) -> int:
        dev = self.resolve_dev_info(ifindex, dev_gen=dev_gen)
        if dev and dev.get("linktype") is not None:
            return int(dev["linktype"])
        return int(LinkType.ETHERNET)

    def _ordered_epochs_for_ts(self, ts_ns: int | None) -> list[dict[str, Any]]:
        epochs = list(self.dictionary.get("topology_epochs", []) or [])
        if ts_ns is None or len(epochs) <= 1:
            return epochs
        prior = [ep for ep in epochs if int(ep.get("ts_ns", 0) or 0) <= ts_ns]
        later = [ep for ep in epochs if int(ep.get("ts_ns", 0) or 0) > ts_ns]
        return list(reversed(prior)) + later

    def infer_qdisc_kind_from_site(self, site_idx: int | None) -> str | None:
        if site_idx is None:
            return None
        site = self.resolve_site(int(site_idx))
        if not site:
            return None
        qkind = str(site.get("qdisc_kind") or "").strip().lower()
        if qkind:
            return qkind
        haystack = f"{site.get('symbol', '')} {site.get('name', '')}".lower()
        if "pfifo_fast" in haystack:
            return "pfifo_fast"
        if "pfifo_tail" in haystack or "pfifo_head_drop" in haystack or "ptail" in haystack:
            return "pfifo_head_drop"
        if "pfifo" in haystack:
            return "pfifo"
        if "bfifo" in haystack:
            return "bfifo"
        if "fq_codel" in haystack:
            return "fq_codel"
        if "sfq" in haystack:
            return "sfq"
        if "htb" in haystack:
            return "htb"
        if "fifo_deq" in haystack or "qdisc_dequeue_head" in haystack:
            return "pfifo"
        return None

    def resolve_qdisc_info(
        self,
        *,
        ifindex: int,
        queue_gen: int | None = None,
        handle: int | None = None,
        parent: int | None = None,
        dev_gen: int | None = None,
        ts_ns: int | None = None,
    ) -> dict[str, Any] | None:
        if ts_ns is not None and self.is_topo_desynced_at(ts_ns):
            return None
        epochs = self._ordered_epochs_for_ts(ts_ns)
        # Priority 1: exact (ifindex, queue_gen) match when queue_gen > 0
        if queue_gen is not None and queue_gen > 0:
            for ep in epochs:
                for q in ep.get("qdiscs", []):
                    if q.get("ifindex") in (None, 0, ifindex) and q.get("queue_gen") == queue_gen:
                        if dev_gen and q.get("dev_gen") and q["dev_gen"] != dev_gen:
                            continue
                        return q
        # Priority 2: match by (ifindex, handle, parent)
        if handle is not None:
            for ep in epochs:
                for q in ep.get("qdiscs", []):
                    if q.get("ifindex") in (None, 0, ifindex) and q.get("handle") == handle:
                        if parent is not None and parent != 0 and q.get("parent") not in (None, parent):
                            continue
                        return q
        return None

    def resolve_effective_qdisc_kind(
        self,
        *,
        ifindex: int,
        queue_gen: int | None = None,
        handle: int | None = None,
        parent: int | None = None,
        dev_gen: int | None = None,
        ts_ns: int | None = None,
        site_dict_idx: int | None = None,
    ) -> str | None:
        qinfo = self.resolve_qdisc_info(
            ifindex=ifindex,
            queue_gen=queue_gen,
            handle=handle,
            parent=parent,
            dev_gen=dev_gen,
            ts_ns=ts_ns,
        )
        if qinfo and qinfo.get("kind"):
            return str(qinfo["kind"])
        if ts_ns is not None and self.is_topo_desynced_at(ts_ns):
            return None
        return self.infer_qdisc_kind_from_site(site_dict_idx)

    def resolve_class_info(
        self,
        ifindex: int,
        classid: int | None,
        *,
        dev_gen: int | None = None,
        ts_ns: int | None = None,
    ) -> dict[str, Any] | None:
        if classid is None or int(classid) == 0:
            return None
        if ts_ns is not None and self.is_topo_desynced_at(ts_ns):
            return None
        target = int(classid) & 0xFFFFFFFF
        for ep in self._ordered_epochs_for_ts(ts_ns):
            for cls in ep.get("classes", []) or []:
                if cls.get("ifindex") not in (None, 0, ifindex):
                    continue
                if dev_gen and cls.get("dev_gen") and int(cls["dev_gen"]) != dev_gen:
                    continue
                if int(cls.get("handle", 0) or 0) == target:
                    return cls
        return None

    ResolveClassInfo = resolve_class_info

    def calibrate_boottime_to_realtime(self, boottime_ns: int) -> tuple[int, int, bool]:
        """Return `(est_realtime_ns, err_ns, is_calibrated)` from `manifest.calibrations`."""
        cals = self.manifest.get("calibrations") or []
        if not cals:
            return boottime_ns, 0, False
        nearest = min(cals, key=lambda c: abs(int(c.get("boottime_ns", 0)) - boottime_ns))
        bt_ref = int(nearest.get("boottime_ns", 0))
        rt_ref = int(nearest.get("realtime_ns", bt_ref))
        err_ns = int(nearest.get("err_ns", nearest.get("est_err_ns", 0)) or 0)
        return rt_ref + (boottime_ns - bt_ref), err_ns, True


# ============================================================================
# 2. Internal Reconstruction Helpers
# ============================================================================


def _dedup_and_detect_seq_gaps(
    raw_events: Sequence[DecodedEvent],
) -> tuple[list[DecodedEvent], int, list[SeqGap]]:
    seen_keys: set[tuple[int, int, int]] = set()
    deduped: list[DecodedEvent] = []
    dedup_dropped = 0
    by_stream: dict[tuple[int, int], list[DecodedEvent]] = defaultdict(list)

    for ev in raw_events:
        key = ev.dedup_key
        if key in seen_keys:
            dedup_dropped += 1
            continue
        seen_keys.add(key)
        deduped.append(ev)
        by_stream[(ev.producer_type, ev.cpu)].append(ev)

    seq_gaps: list[SeqGap] = []
    for (prod, cpu), stream_evs in sorted(by_stream.items()):
        ordered = sorted(stream_evs, key=lambda e: e.seq)
        for i in range(1, len(ordered)):
            prev_ev = ordered[i - 1]
            curr_ev = ordered[i]
            if curr_ev.seq > prev_ev.seq + 1:
                seq_gaps.append(
                    SeqGap(
                        producer_type=prod,
                        cpu=cpu,
                        prev_seq=prev_ev.seq,
                        next_seq=curr_ev.seq,
                        missing_count=curr_ev.seq - prev_ev.seq - 1,
                        win_start_ns=prev_ev.ts_ns,
                        win_end_ns=curr_ev.ts_ns,
                        prev_object_id=prev_ev.object_id,
                        next_object_id=curr_ev.object_id,
                    )
                )

    # Global deterministic order: (ts_ns, producer_type, seq)
    deduped.sort(key=lambda e: (e.ts_ns, e.producer_type, e.seq))
    return deduped, dedup_dropped, seq_gaps


def _build_qstate_annotations(qstate_events: Sequence[DecodedEvent]) -> list[QStateAnnotation]:
    annotations: list[QStateAnnotation] = []
    open_stops: dict[tuple[int, int], QStateAnnotation] = {}

    for ev in sorted(qstate_events, key=lambda e: (e.ts_ns, e.seq)):
        ifindex = int(ev.get("ifindex", 0) or 0)
        txq = int(ev.get("txq", 0) or 0)
        qgen = int(ev.get("queue_gen", 0) or 0)
        op = int(ev.get("state_op", 0) or 0)
        val = int(ev.get("value", 0) or 0)
        key = (ifindex, txq)

        if op == int(QStateOp.TXQ_STOP):
            if key in open_stops:
                annotations.append(open_stops.pop(key))
            open_stops[key] = QStateAnnotation(
                ifindex=ifindex,
                txq=txq,
                queue_gen=qgen,
                state_op=op,
                state_name="TXQ_STOP_WAKE",
                start_ns=ev.ts_ns,
                end_ns=None,
                value=val,
                event_ids=[ev.event_id],
            )
        elif op == int(QStateOp.TXQ_WAKE):
            if key in open_stops:
                ann = open_stops.pop(key)
                ann.end_ns = ev.ts_ns
                ann.event_ids.append(ev.event_id)
                annotations.append(ann)
            else:
                annotations.append(
                    QStateAnnotation(
                        ifindex=ifindex,
                        txq=txq,
                        queue_gen=qgen,
                        state_op=op,
                        state_name="TXQ_WAKE",
                        start_ns=ev.ts_ns,
                        end_ns=ev.ts_ns,
                        value=val,
                        event_ids=[ev.event_id],
                    )
                )
        else:
            annotations.append(
                QStateAnnotation(
                    ifindex=ifindex,
                    txq=txq,
                    queue_gen=qgen,
                    state_op=op,
                    state_name=QSTATE_OP_NAMES.get(op, f"QSTATE_{op}"),
                    start_ns=ev.ts_ns,
                    end_ns=ev.ts_ns,
                    value=val,
                    event_ids=[ev.event_id],
                )
            )

    for ann in open_stops.values():
        annotations.append(ann)

    annotations.sort(key=lambda a: a.start_ns)
    return annotations


def _matching_qstates(
    all_qstates: Sequence[QStateAnnotation],
    *,
    ifindex: int,
    txq: int | None,
    win_start_ns: int,
    win_end_ns: int,
) -> list[QStateAnnotation]:
    matched: list[QStateAnnotation] = []
    for qs in all_qstates:
        if ifindex != 0 and qs.ifindex != 0 and qs.ifindex != ifindex:
            continue
        if txq is not None and qs.txq != txq:
            continue
        qs_end = win_end_ns if qs.end_ns is None else qs.end_ns
        if qs.start_ns <= win_end_ns and qs_end >= win_start_ns:
            matched.append(qs)
    return matched


def _pair_calls_and_visits(
    objects: dict[int, ObjectNode],
    all_qstates: Sequence[QStateAnnotation],
) -> list[DecodedEvent]:
    """Pair `(object_id, call_id)` calls and `(object_id, queue_gen, visit_id)` queue visits."""
    unmatched_returns: list[DecodedEvent] = []

    # Global index of entry calls by call_id for late cross-CPU returns with object_id==0 or A
    entry_calls_by_id: dict[int, list[CallPair]] = defaultdict(list)
    entry_calls_by_obj_id: dict[tuple[int, int], list[CallPair]] = defaultdict(list)

    entry_call_stages = {
        int(Stage.QDISC_ENQ),
        int(Stage.REQUEUE_GSO),
        int(Stage.REQUEUE_BAD_TXQ),
        int(Stage.XMIT_START),
        int(Stage.CLASSIFY),
        int(Stage.ENTRY),
        int(Stage.HANDOFF_LAYER),
    }
    ret_call_stages = {
        int(Stage.QDISC_ENQ_RET),
        int(Stage.XMIT_RET),
    }

    for obj_id, obj in objects.items():
        for st in obj.steps:
            stage = int(st.get("stage", 0) or 0)
            call_id = st.get("call_id")
            if call_id is not None and int(call_id) > 0 and stage in entry_call_stages:
                cid = int(call_id)
                cp = CallPair(call_id=cid, object_id=obj_id, entry_event=st)
                obj.calls.append(cp)
                entry_calls_by_id[cid].append(cp)
                entry_calls_by_obj_id[(obj_id, cid)].append(cp)

    # Match return steps strictly by call_id
    for obj_id in list(objects.keys()):
        obj = objects[obj_id]
        reassigned_steps: list[DecodedEvent] = []
        for st in obj.steps:
            stage = int(st.get("stage", 0) or 0)
            if stage not in ret_call_stages:
                reassigned_steps.append(st)
                continue

            call_id = st.get("call_id")
            if call_id is None or int(call_id) == 0:
                reassigned_steps.append(st)
                continue

            cid = int(call_id)
            candidates = entry_calls_by_obj_id.get((obj_id, cid))
            if not candidates:
                # Cross-CPU late return fallback when call_id uniquely identifies original object
                global_cands = entry_calls_by_id.get(cid, [])
                if len(global_cands) == 1:
                    candidates = global_cands
                    target_obj_id = global_cands[0].object_id
                    if target_obj_id != obj_id:
                        objects[target_obj_id].steps.append(st)
                    else:
                        reassigned_steps.append(st)
                else:
                    unmatched_returns.append(st)
                    continue
            else:
                reassigned_steps.append(st)

            if len(candidates) != 1 or candidates[0].ret_event is not None:
                for c in candidates:
                    c.ambiguous = True
                    c.paired = False
                unmatched_returns.append(st)
            else:
                cp = candidates[0]
                cp.ret_event = st
                cp.paired = True
                cp.raw_ret = st.get("raw_ret")

        obj.steps = reassigned_steps

    # Re-sort object steps after any cross-CPU call_id reassignment
    for obj in objects.values():
        obj.steps.sort(key=lambda e: (e.ts_ns, e.seq))
        # Flag cross-CPU late returns whose ts_ns >= a downstream step's ts_ns
        for cp in obj.calls:
            if cp.paired and cp.entry_event and cp.ret_event:
                for other in obj.steps:
                    if other is cp.entry_event or other is cp.ret_event:
                        continue
                    if cp.entry_event.ts_ns <= other.ts_ns <= cp.ret_event.ts_ns and other.cpu != cp.entry_event.cpu:
                        cp.cross_cpu_late = True
                        break

    # Detect unexpected same-(netns, ifindex, dir) re-entry without HANDOFF_LAYER
    for obj in objects.values():
        seen_entries: set[tuple[int, int, int, int]] = set()
        saw_handoff_since_last_entry = False
        for st in obj.steps:
            stage = int(st.get("stage", 0) or 0)
            if stage == int(Stage.HANDOFF_LAYER):
                saw_handoff_since_last_entry = True
            elif stage == int(Stage.ENTRY):
                sig = (
                    int(st.get("netns_inum", 0) or 0),
                    int(st.get("ifindex", 0) or 0),
                    int(st.get("dev_gen", 0) or 0),
                    int(st.get("dir", 0) or 0),
                )
                if sig in seen_entries and not saw_handoff_since_last_entry:
                    obj.identity_conflict = True
                seen_entries.add(sig)
                saw_handoff_since_last_entry = False

    # Pair queue visits strictly by (object_id, queue_gen, visit_id)
    visit_entry_stages = {
        int(Stage.QDISC_ENQ): "qdisc",
        int(Stage.REQUEUE_GSO): "requeue_gso",
        int(Stage.REQUEUE_BAD_TXQ): "requeue_bad_txq",
    }
    visit_exit_stages = {
        int(Stage.QDISC_DEQ),
        int(Stage.DROP),
    }

    for obj_id, obj in objects.items():
        if obj_id == 0:
            continue
        entries_by_key: dict[tuple[int, int], list[DecodedEvent]] = defaultdict(list)
        entries_by_visit_only: dict[int, list[tuple[int, DecodedEvent]]] = defaultdict(list)
        enq_rets_by_key: dict[tuple[int, int], list[DecodedEvent]] = defaultdict(list)
        exits_by_key: dict[tuple[int, int], list[DecodedEvent]] = defaultdict(list)
        unkeyed_exits: list[DecodedEvent] = []
        call_map: dict[int, CallPair] = {cp.call_id: cp for cp in obj.calls if not cp.ambiguous}

        # Determine known xmit txq on object (helpful for attaching txq stop/wake to leaf visit)
        known_obj_txq: int | None = None
        for st in obj.steps:
            if st.get("txq") is not None and int(st.get("stage", 0) or 0) in (
                int(Stage.XMIT_START),
                int(Stage.QDISC_ENQ),
                int(Stage.QDISC_DEQ),
            ):
                known_obj_txq = int(st["txq"])
                break

        for st in obj.steps:
            stage = int(st.get("stage", 0) or 0)
            vid = st.get("visit_id")
            if vid is None or int(vid) == 0:
                continue
            vid_int = int(vid)
            qgen_raw = st.get("queue_gen")
            qgen_int = int(qgen_raw) if qgen_raw is not None else 0

            if stage in visit_entry_stages:
                entries_by_key[(qgen_int, vid_int)].append(st)
                entries_by_visit_only[vid_int].append((qgen_int, st))
            elif stage == int(Stage.QDISC_ENQ_RET):
                enq_rets_by_key[(qgen_int, vid_int)].append(st)
            elif stage in visit_exit_stages:
                if qgen_raw is None or qgen_int == 0:
                    unkeyed_exits.append(st)
                else:
                    exits_by_key[(qgen_int, vid_int)].append(st)

        # Resolve exits where queue_gen was omitted (e.g. skb:kfree_skb tracepoint closing unique open visit)
        ambiguous_visit_ids: set[int] = set()
        for ex in unkeyed_exits:
            vid_int = int(ex["visit_id"]) if isinstance(ex, dict) else int(ex.get("visit_id", 0))
            cands = entries_by_visit_only.get(vid_int, [])
            unique_qgens = {qg for qg, _ in cands}
            if len(unique_qgens) == 1:
                only_qgen = next(iter(unique_qgens))
                exits_by_key[(only_qgen, vid_int)].append(ex)
            elif len(unique_qgens) > 1:
                ambiguous_visit_ids.add(vid_int)
            else:
                exits_by_key[(0, vid_int)].append(ex)

        all_visit_keys = sorted(
            set(entries_by_key.keys()) | set(exits_by_key.keys()),
            key=lambda kv: (
                entries_by_key[kv][0].ts_ns if entries_by_key.get(kv) else exits_by_key[kv][0].ts_ns,
                kv[1],
            ),
        )

        enqueue_tid = obj.attribution.get("enqueue_tid")
        for qgen_int, vid_int in all_visit_keys:
            en_list = entries_by_key.get((qgen_int, vid_int), [])
            ex_list = exits_by_key.get((qgen_int, vid_int), [])

            ref_ev = en_list[0] if en_list else ex_list[0]
            ref_stage = int(ref_ev.get("stage", int(Stage.QDISC_ENQ)) or int(Stage.QDISC_ENQ))
            vkind = visit_entry_stages.get(ref_stage, "qdisc")

            visit = QueueVisit(
                object_id=obj_id,
                queue_gen=qgen_int,
                visit_id=vid_int,
                visit_kind=vkind,
                netns_inum=int(ref_ev.get("netns_inum", 0) or 0),
                ifindex=int(ref_ev.get("ifindex", 0) or 0),
                dev_gen=int(ref_ev.get("dev_gen", 0) or 0),
                qdisc_handle=int(ref_ev.get("qdisc_handle", 0) or 0),
                qdisc_parent=int(ref_ev.get("qdisc_parent", 0) or 0),
                classid=int(ref_ev.get("classid", 0) or 0),
                bucket=ref_ev.get("bucket"),
                txq=ref_ev.get("txq"),
                entry_event=en_list[0] if len(en_list) == 1 else None,
                exit_event=ex_list[0] if len(ex_list) == 1 else None,
            )

            if vid_int in ambiguous_visit_ids or len(en_list) > 1 or len(ex_list) > 1:
                visit.ambiguous = True

            # Check QDISC_ENQ_RET return code via call_id or (queue_gen, visit_id)
            if visit.entry_event is not None:
                cid = visit.entry_event.get("call_id")
                ret_ev: DecodedEvent | None = None
                if cid is not None and int(cid) in call_map:
                    cp = call_map[int(cid)]
                    ret_ev = cp.ret_event
                elif len(enq_rets_by_key.get((qgen_int, vid_int), [])) == 1:
                    ret_ev = enq_rets_by_key[(qgen_int, vid_int)][0]

                if ret_ev is not None:
                    visit.enq_ret_event = ret_ev
                    rc_val = ret_ev.get("raw_ret")
                    visit.enq_ret_code = rc_val
                    if rc_val == NET_XMIT_DROP or (rc_val is not None and int(rc_val) < 0):
                        visit.enq_dropped = True
                    elif rc_val == NET_XMIT_CN:
                        visit.enq_cn = True

            if (
                not visit.ambiguous
                and not visit.enq_dropped
                and visit.entry_event is not None
                and visit.exit_event is not None
            ):
                delta = visit.exit_event.ts_ns - visit.entry_event.ts_ns
                if delta >= 0:
                    visit.paired = True
                    visit.sojourn_ns = delta
                    ex_tid = visit.exit_event.get("ctx_tid")
                    if (
                        enqueue_tid
                        and ex_tid is not None
                        and int(ex_tid) != int(enqueue_tid)
                    ):
                        visit.cross_thread_dequeue = True

            # Attach overlapping QSTATE backpressure context
            w_start = visit.entry_event.ts_ns if visit.entry_event else ref_ev.ts_ns
            w_end = (
                visit.exit_event.ts_ns
                if visit.exit_event
                else max(obj.last_ts_ns, w_start)
            )
            txq_filter = visit.txq if visit.txq is not None else known_obj_txq
            visit.backpressure = _matching_qstates(
                all_qstates,
                ifindex=visit.ifindex,
                txq=txq_filter,
                win_start_ns=w_start,
                win_end_ns=w_end,
            )
            obj.visits.append(visit)

    return unmatched_returns


def _extract_attribution(obj: ObjectNode) -> dict[str, Any]:
    attr: dict[str, Any] = {}
    for s in obj.summaries:
        for k in ("uid", "tgid", "comm", "enqueue_tid", "skb_create_ts"):
            val = s.get(k)
            if val is not None and k not in attr:
                attr[k] = val
        for slot in range(4):
            pv = s.get(f"plugin_val{slot}")
            if pv is not None:
                attr.setdefault("plugin_vals", {})[slot] = pv
        if "in_task" not in attr:
            attr["in_task"] = bool(s.flags & int(EventFlags.IN_TASK))

    for st in obj.steps:
        stage = int(st.get("stage", 0) or 0)
        if stage == int(Stage.ENTRY):
            if "enqueue_tid" not in attr and st.get("ctx_tid") is not None:
                attr["enqueue_tid"] = int(st["ctx_tid"])
            if "in_task" not in attr:
                attr["in_task"] = bool(st.flags & int(EventFlags.IN_TASK))
        elif stage == int(Stage.XMIT_START):
            if st.get("ctx_tid") is not None:
                attr["xmit_tid"] = int(st["ctx_tid"])
                attr["xmit_in_task"] = bool(st.flags & int(EventFlags.IN_TASK))
    return attr


def _compute_effective_end_reason(obj: ObjectNode) -> int:
    if obj.explicit_end_reason != int(EndReason.OPEN):
        return obj.explicit_end_reason

    # Non-fork outgoing transformation means object handed off to successor(s)
    has_non_fork_out = any(
        r.rel_type not in (int(RelType.CLONE), int(RelType.COPY))
        for r in obj.outgoing_relations
    )
    if has_non_fork_out:
        return int(EndReason.CONSUME)

    # Check terminal step evidence in reverse chronological order
    for st in reversed(obj.steps):
        stage = int(st.get("stage", 0) or 0)
        if stage == int(Stage.XMIT_RET):
            rc = st.get("raw_ret")
            if rc is None or int(rc) == NETDEV_TX_OK:
                return int(EndReason.TX_OK)
        elif stage == int(Stage.DROP):
            return int(EndReason.DROP)
        elif stage == int(Stage.CONSUME):
            return int(EndReason.CONSUME)
        elif stage == int(Stage.DELIVER_SOCK):
            return int(EndReason.SOCK_ENQUEUE)

    return int(EndReason.OPEN)


def _seq_gap_overlaps_branch(gap: SeqGap, branch: BranchPath) -> bool:
    obj_set = set(branch.object_ids)
    if gap.prev_object_id in obj_set and gap.prev_object_id != 0:
        if gap.win_start_ns <= branch.end_ts_ns:
            return True

    # Check if branch was created strictly at or after `next_seq` on the same stream
    same_stream_evs = [
        e for e in branch.events if e.producer_type == gap.producer_type and e.cpu == gap.cpu
    ]
    if same_stream_evs:
        min_seq = min(e.seq for e in same_stream_evs)
        max_seq = max(e.seq for e in same_stream_evs)
        if min_seq >= gap.next_seq and branch.start_ts_ns >= gap.win_end_ns:
            return False
        if max_seq <= gap.prev_seq and branch.end_ts_ns < gap.win_start_ns:
            return False
        if min_seq <= gap.prev_seq and max_seq >= gap.next_seq:
            return True

    # Strict open-end window intersection for cross-CPU or open branches
    return branch.start_ts_ns < gap.win_end_ns and branch.end_ts_ns >= gap.win_start_ns


def _compute_reorder_count(objects: dict[int, ObjectNode]) -> int:
    """Count packets departing (`QDISC_DEQ`/`XMIT_START`) out-of-order vs `ENTRY` order per `(netns, ifindex, dir)`."""
    per_flow_port: dict[tuple[int, int, int], list[tuple[tuple[int, int], tuple[int, int]]]] = defaultdict(list)

    for obj in objects.values():
        if obj.object_type != int(ObjectType.SKB):
            continue
        entry_ev: DecodedEvent | None = None
        depart_ev: DecodedEvent | None = None
        for st in obj.steps:
            stage = int(st.get("stage", 0) or 0)
            if stage == int(Stage.ENTRY) and entry_ev is None:
                entry_ev = st
            elif stage in (int(Stage.QDISC_DEQ), int(Stage.XMIT_START)):
                if depart_ev is None:
                    depart_ev = st

        if entry_ev is not None and depart_ev is not None:
            port_key = (
                int(entry_ev.get("netns_inum", 0) or 0),
                int(entry_ev.get("ifindex", 0) or 0),
                int(entry_ev.get("dir", 0) or 0),
            )
            per_flow_port[port_key].append(
                ((entry_ev.ts_ns, entry_ev.seq), (depart_ev.ts_ns, depart_ev.seq))
            )

    reorder_total = 0
    for items in per_flow_port.values():
        if len(items) < 2:
            continue
        by_entry = sorted(items, key=lambda pair: pair[0])
        ranked = [(entry_rank, pair[1]) for entry_rank, pair in enumerate(by_entry)]
        by_depart = sorted(ranked, key=lambda item: item[1])

        max_rank_seen = -1
        for entry_rank, _ in by_depart:
            if entry_rank < max_rank_seen:
                reorder_total += 1
            else:
                max_rank_seen = entry_rank

    return reorder_total


# ============================================================================
# 3. Main Entry Point: `reconstruct_session`
# ============================================================================


def reconstruct_session(
    session_or_dir: LoadedSession | str | os.PathLike[str],
    *,
    strict_tail: bool = False,
) -> ReconstructedSession:
    """Reconstruct complete multi-branch evidence DAG, visits, and completeness status."""
    loaded = (
        session_or_dir
        if isinstance(session_or_dir, LoadedSession)
        else load_session(session_or_dir, strict_tail=strict_tail)
    )

    manifest = loaded.manifest
    dictionary = loaded.dictionary
    sites_by_idx: dict[int, dict[str, Any]] = {
        int(s["site_idx"]): s
        for s in dictionary.get("sites", [])
        if "site_idx" in s
    }

    events, dedup_dropped, seq_gaps = _dedup_and_detect_seq_gaps(loaded.events)

    # Check manifest adapters for unobservable silent loss (`missed_source == "none"`)
    unobservable_adapters: list[str] = []
    for ad in manifest.get("adapters", []) or []:
        if not ad.get("enabled", True):
            continue
        if ad.get("required") is False:
            continue
        msrc = str(ad.get("missed_source", "")).strip().lower()
        if msrc == "none":
            unobservable_adapters.append(str(ad.get("adapter_id") or ad.get("name") or "unknown"))
    has_unobservable_missed_source = len(unobservable_adapters) > 0

    objects: dict[int, ObjectNode] = {}
    relations: list[RelationEdge] = []
    qstate_events: list[DecodedEvent] = []
    quality_events: list[DecodedEvent] = []
    topo_desync_windows: list[tuple[int, int]] = []

    def get_or_create_obj(oid: int, otype: int = int(ObjectType.SKB)) -> ObjectNode:
        node = objects.get(oid)
        if node is None:
            node = ObjectNode(object_id=oid, object_type=otype)
            objects[oid] = node
        elif node.object_type == int(ObjectType.SKB) and otype != int(ObjectType.SKB):
            node.object_type = otype
        return node

    for ev in events:
        if ev.kind == int(EventKind.OBJECT):
            if ev.object_id == 0:
                continue
            obj = get_or_create_obj(ev.object_id, ev.object_type)
            obj.object_events.append(ev)
            sid = int(ev.get("sample_id", 0) or 0)
            if sid > 0:
                obj.sample_ids.add(sid)
                if obj.primary_sample_id == 0:
                    obj.primary_sample_id = sid
            end_r = ev.get("end_reason")
            if end_r is not None and int(end_r) != int(EndReason.OPEN):
                obj.explicit_end_reason = int(end_r)
                if int(end_r) == int(EndReason.CONFLICT_TRUNCATED):
                    obj.identity_conflict = True
            if ev.get("drop_reason") is not None:
                obj.drop_reason = int(ev["drop_reason"])
            obj.unknown_must_tlvs.extend(ev.unknown_must_tlvs)
            obj.unknown_optional_tlvs.extend(ev.unknown_optional_tlvs)

        elif ev.kind == int(EventKind.STEP):
            if ev.object_id != 0:
                obj = get_or_create_obj(ev.object_id, ev.object_type)
                obj.steps.append(ev)
                obj.unknown_must_tlvs.extend(ev.unknown_must_tlvs)
                obj.unknown_optional_tlvs.extend(ev.unknown_optional_tlvs)
            else:
                # Late return with object_id==0 will be routed via call_id
                dummy = get_or_create_obj(0, ev.object_type)
                dummy.steps.append(ev)

        elif ev.kind == int(EventKind.SUMMARY):
            if ev.object_id == 0:
                continue
            obj = get_or_create_obj(ev.object_id, ev.object_type)
            obj.summaries.append(ev)
            obj.unknown_must_tlvs.extend(ev.unknown_must_tlvs)
            obj.unknown_optional_tlvs.extend(ev.unknown_optional_tlvs)

        elif ev.kind == int(EventKind.RELATION):
            src_id = int(ev.get("src_object_id", ev.object_id) or 0)
            dst_id = int(ev.get("dst_object_id", 0) or 0)
            rtype = int(ev.get("rel_type", 0) or 0)
            rflags = int(ev.get("rel_flags", 0) or 0)
            succ_trunc = bool(rflags & int(RelFlags.SUCCESSOR_TRUNCATED))
            unk_pred = bool(rflags & int(RelFlags.UNKNOWN_PREDECESSORS))

            edge = RelationEdge(
                event=ev,
                op_id=int(ev.get("op_id", 0) or 0),
                rel_type=rtype,
                rel_type_name=REL_TYPE_NAMES.get(rtype, f"REL_{rtype}"),
                src_object_id=src_id,
                dst_object_id=dst_id,
                rel_flags=rflags,
                successor_truncated=succ_trunc,
                unknown_predecessors=unk_pred,
                stream_offset=ev.get("stream_offset"),
                span_len=ev.get("span_len"),
                ts_ns=ev.ts_ns,
            )
            relations.append(edge)

            if src_id != 0:
                src_obj = get_or_create_obj(
                    src_id,
                    int(ObjectType.APP_MSG) if rtype == int(RelType.SPAN_MAP) and src_id not in objects else ev.object_type,
                )
                src_obj.outgoing_relations.append(edge)
                src_obj.unknown_must_tlvs.extend(ev.unknown_must_tlvs)
                if succ_trunc:
                    src_obj.successor_truncated = True
            if dst_id != 0:
                dst_obj = get_or_create_obj(dst_id, int(ObjectType.SKB))
                dst_obj.incoming_relations.append(edge)
                dst_obj.unknown_must_tlvs.extend(ev.unknown_must_tlvs)
                if unk_pred:
                    dst_obj.unknown_predecessors = True
                if succ_trunc:
                    dst_obj.successor_truncated = True

        elif ev.kind == int(EventKind.QSTATE):
            qstate_events.append(ev)

        elif ev.kind == int(EventKind.QUALITY):
            quality_events.append(ev)
            qkind = int(ev.get("qual_kind", 0) or 0)
            qcnt = int(ev.get("count", 1) if ev.get("count") is not None else 1)
            if qkind == int(QualKind.TOPO_DESYNC) and qcnt > 0:
                ws = int(ev.get("win_start_ns", 0) or ev.ts_ns)
                we = int(ev.get("win_end_ns", 0) or ev.ts_ns)
                topo_desync_windows.append((ws, max(ws, we)))
            elif qkind == int(QualKind.IDENTITY_CONFLICT) and qcnt > 0 and ev.object_id != 0:
                c_obj = get_or_create_obj(ev.object_id, ev.object_type)
                c_obj.identity_conflict = True

    qstate_annotations = _build_qstate_annotations(qstate_events)

    # Initial timestamps & attribution before visit pairing
    for oid, obj in list(objects.items()):
        if oid == 0:
            continue
        all_ts = [
            e.ts_ns
            for e in (*obj.object_events, *obj.steps, *obj.summaries)
        ]
        if all_ts:
            obj.first_ts_ns = min(all_ts)
            obj.last_ts_ns = max(all_ts)
        obj.attribution = _extract_attribution(obj)

    unmatched_returns = _pair_calls_and_visits(objects, qstate_annotations)
    objects.pop(0, None)

    # Recompute object timestamps & effective end reasons after cross-CPU call routing
    requeue_gso_count = 0
    requeue_bad_txq_count = 0
    for obj in objects.values():
        all_ts = [
            e.ts_ns
            for e in (*obj.object_events, *obj.steps, *obj.summaries)
        ]
        if all_ts:
            obj.first_ts_ns = min(all_ts)
            obj.last_ts_ns = max(all_ts)
        obj.attribution = _extract_attribution(obj)
        obj.effective_end_reason = _compute_effective_end_reason(obj)
        for st in obj.steps:
            stg = int(st.get("stage", 0) or 0)
            if stg == int(Stage.REQUEUE_GSO):
                requeue_gso_count += 1
            elif stg == int(Stage.REQUEUE_BAD_TXQ):
                requeue_bad_txq_count += 1

    # Propagate sample_ids across DAG relations (forward, plus backward for SPAN_MAP / unlabelled roots)
    changed = True
    while changed:
        changed = False
        for rel in relations:
            src = objects.get(rel.src_object_id)
            dst = objects.get(rel.dst_object_id)
            if src is None or dst is None:
                continue
            before_dst = len(dst.sample_ids)
            dst.sample_ids.update(src.sample_ids)
            if len(dst.sample_ids) != before_dst:
                if dst.primary_sample_id == 0:
                    dst.primary_sample_id = min(dst.sample_ids)
                changed = True
            # If SPAN_MAP source APP_MSG had sample_id==0 while target SKB had sample_id>0, link it
            if not src.sample_ids and dst.sample_ids and rel.rel_type == int(RelType.SPAN_MAP):
                src.sample_ids.update(dst.sample_ids)
                src.primary_sample_id = min(src.sample_ids)
                changed = True

    # Fallback sample_id = object_id for orphan objects that omitted sample_id TLV
    for obj in objects.values():
        if not obj.sample_ids:
            obj.sample_ids.add(obj.object_id)
            obj.primary_sample_id = obj.object_id

    # Build SampleGraphs & enumerate all DAG branches
    sample_obj_map: dict[int, list[int]] = defaultdict(list)
    for oid, obj in sorted(objects.items()):
        for sid in sorted(obj.sample_ids):
            sample_obj_map[sid].append(oid)

    all_branches: list[BranchPath] = []
    samples: dict[int, SampleGraph] = {}

    # Pre-extract active quality loss events (`count > 0`)
    loss_qual_events: list[tuple[int, str, int, int, int, int]] = []
    for qev in quality_events:
        qkind = int(qev.get("qual_kind", 0) or 0)
        qcnt = int(qev.get("count", 1) if qev.get("count") is not None else 1)
        if qkind in (
            int(QualKind.MISSED_DELTA),
            int(QualKind.RB_DROP_DELTA),
            int(QualKind.RET_UNMATCHED),
            int(QualKind.IDENTITY_CONFLICT),
            int(QualKind.RING_EVICTED_PREFIX),
            int(QualKind.TOPO_DESYNC),
        ) and qcnt > 0:
            ws = int(qev.get("win_start_ns", 0) or qev.ts_ns)
            we = int(qev.get("win_end_ns", 0) or qev.ts_ns)
            if we < ws:
                we = ws
            loss_qual_events.append(
                (qkind, QUAL_KIND_NAMES[qkind], ws, we, qev.object_id, int(qev.get("site_dict_idx", qev.site_dict_idx) or 0))
            )

    for sid, obj_id_list in sorted(sample_obj_map.items()):
        sid_set = set(obj_id_list)
        sample_rels = [
            r
            for r in relations
            if r.src_object_id in sid_set or r.dst_object_id in sid_set
        ]

        # Root objects in this sample: objects with no incoming relation from within `sid_set`
        roots = [
            oid
            for oid in obj_id_list
            if not any(r.src_object_id in sid_set for r in objects[oid].incoming_relations)
        ]
        if not roots:
            roots = [obj_id_list[0]]

        raw_paths: list[tuple[list[tuple[int, int, int | None]], list[RelationEdge]]] = []

        def _dfs(
            curr_oid: int,
            min_ts: int,
            prefix_slices: list[tuple[int, int, int | None]],
            prefix_rels: list[RelationEdge],
            visited: frozenset[int],
        ) -> None:
            node = objects[curr_oid]
            out_rels = [
                r
                for r in node.outgoing_relations
                if r.dst_object_id in objects and r.dst_object_id not in visited
            ]
            fork_rels = [
                r for r in out_rels if r.rel_type in (int(RelType.CLONE), int(RelType.COPY))
            ]
            xform_rels = [
                r for r in out_rels if r.rel_type not in (int(RelType.CLONE), int(RelType.COPY))
            ]

            # Forked children (CLONE / COPY) branch off at `fork_rel.ts_ns`
            for frel in fork_rels:
                _dfs(
                    frel.dst_object_id,
                    0,
                    prefix_slices + [(curr_oid, min_ts, frel.ts_ns)],
                    prefix_rels + [frel],
                    visited | {curr_oid},
                )

            # Continuation of `curr_oid` itself
            if xform_rels:
                for xrel in xform_rels:
                    _dfs(
                        xrel.dst_object_id,
                        0,
                        prefix_slices + [(curr_oid, min_ts, None)],
                        prefix_rels + [xrel],
                        visited | {curr_oid},
                    )
            else:
                raw_paths.append((prefix_slices + [(curr_oid, min_ts, None)], list(prefix_rels)))

        for root_oid in roots:
            _dfs(root_oid, 0, [], [], frozenset())

        sample_branches: list[BranchPath] = []
        for b_idx, (slices, rel_chain) in enumerate(raw_paths, start=1):
            b_obj_ids = [oid for oid, _, _ in slices]
            leaf_obj = objects[b_obj_ids[-1]]

            b_events: list[DecodedEvent] = []
            b_steps: list[DecodedEvent] = []
            b_summaries: list[DecodedEvent] = []
            b_visits: list[QueueVisit] = []
            b_calls: list[CallPair] = []
            b_unk_must: list[UnknownTLV] = []
            b_succ_trunc = any(r.successor_truncated for r in rel_chain)
            b_unk_pred = any(r.unknown_predecessors for r in rel_chain)
            b_id_conflict = False

            for oid, slice_min, slice_max in slices:
                onode = objects[oid]
                if slice_max is None and onode.successor_truncated:
                    b_succ_trunc = True
                if onode.unknown_predecessors:
                    b_unk_pred = True
                if onode.identity_conflict:
                    b_id_conflict = True

                def _in_slice(ev_ts: int) -> bool:
                    if ev_ts < slice_min:
                        return False
                    if slice_max is not None and ev_ts > slice_max:
                        return False
                    return True

                for ev in onode.object_events:
                    if _in_slice(ev.ts_ns):
                        b_events.append(ev)
                        b_unk_must.extend(ev.unknown_must_tlvs)
                for ev in onode.steps:
                    if _in_slice(ev.ts_ns):
                        b_events.append(ev)
                        b_steps.append(ev)
                        b_unk_must.extend(ev.unknown_must_tlvs)
                for ev in onode.summaries:
                    if _in_slice(ev.ts_ns):
                        b_events.append(ev)
                        b_summaries.append(ev)
                        b_unk_must.extend(ev.unknown_must_tlvs)
                for v in onode.visits:
                    v_ts = v.entry_event.ts_ns if v.entry_event else (v.exit_event.ts_ns if v.exit_event else 0)
                    if _in_slice(v_ts):
                        b_visits.append(v)
                for cp in onode.calls:
                    cp_ts = cp.entry_event.ts_ns if cp.entry_event else 0
                    if _in_slice(cp_ts):
                        b_calls.append(cp)

            for r in rel_chain:
                b_events.append(r.event)
                b_unk_must.extend(r.event.unknown_must_tlvs)

            b_events.sort(key=lambda e: (e.ts_ns, e.producer_type, e.seq))
            b_steps.sort(key=lambda e: (e.ts_ns, e.seq))
            b_summaries.sort(key=lambda e: (e.ts_ns, e.seq))

            start_ts = min((e.ts_ns for e in b_events), default=0)
            end_ts = max((e.ts_ns for e in b_events), default=0)

            end_reason = leaf_obj.effective_end_reason
            end_reason_name = END_REASON_NAMES.get(end_reason, f"END_{end_reason}")

            # Collect QSTATE annotations matching any interface touched by branch
            touched_ifindices = {
                int(s.get("ifindex", 0) or 0)
                for s in (*b_steps, *b_summaries)
                if int(s.get("ifindex", 0) or 0) != 0
            }
            b_qstates: list[QStateAnnotation] = []
            seen_qs_ids: set[int] = set()
            for v in b_visits:
                for qs in v.backpressure:
                    if id(qs) not in seen_qs_ids:
                        seen_qs_ids.add(id(qs))
                        b_qstates.append(qs)
            for ifidx in touched_ifindices:
                for qs in _matching_qstates(
                    qstate_annotations,
                    ifindex=ifidx,
                    txq=None,
                    win_start_ns=start_ts,
                    win_end_ns=end_ts,
                ):
                    if id(qs) not in seen_qs_ids:
                        seen_qs_ids.add(id(qs))
                        b_qstates.append(qs)
            b_qstates.sort(key=lambda q: q.start_ns)

            b_requeue_cnt = sum(
                1
                for s in b_steps
                if int(s.get("stage", 0) or 0) in (int(Stage.REQUEUE_GSO), int(Stage.REQUEUE_BAD_TXQ))
            )

            branch = BranchPath(
                branch_id=f"s{sid}:b{b_idx}",
                sample_id=sid,
                branch_index=b_idx,
                object_ids=b_obj_ids,
                object_slices=slices,
                relation_chain=rel_chain,
                events=b_events,
                steps=b_steps,
                summaries=b_summaries,
                visits=b_visits,
                calls=b_calls,
                qstate_annotations=b_qstates,
                end_reason=end_reason,
                end_reason_name=end_reason_name,
                drop_reason=leaf_obj.drop_reason,
                unknown_must_tlvs=b_unk_must,
                successor_truncated=b_succ_trunc,
                unknown_predecessors=b_unk_pred,
                requeue_count=b_requeue_cnt,
                start_ts_ns=start_ts,
                end_ts_ns=end_ts,
            )

            # Evaluate completeness strictly per `详细设计 §5.3` & `§6.2`
            explicit_gaps: list[str] = []
            visit_or_call_gaps: list[str] = []

            if b_unk_must:
                explicit_gaps.append("INCOMPLETE_UNKNOWN_MUST_TLV")
            if manifest.get("partial_coverage") or any(
                bool(e.flags & int(EventFlags.PARTIAL_COVERAGE)) for e in b_events
            ):
                explicit_gaps.append("PARTIAL_COVERAGE")
            if any(
                e.kind != int(EventKind.QUALITY) and e.evidence_level == int(EvidenceLevel.GAP)
                for e in b_events
            ):
                explicit_gaps.append("EVIDENCE_GAP")
            if b_id_conflict:
                explicit_gaps.append("IDENTITY_CONFLICT")
            if b_succ_trunc:
                explicit_gaps.append("SUCCESSOR_TRUNCATED")

            # Crash / power-loss tail check (`UNKNOWN_TAIL`)
            if loaded.unclean_tail:
                if end_reason == int(EndReason.OPEN) or end_ts > loaded.last_quality_checkpoint_ts_ns:
                    explicit_gaps.append("UNKNOWN_TAIL")
                    if end_reason == int(EndReason.OPEN):
                        branch.end_reason_name = "UNKNOWN_TAIL"

            # Endpoint check
            if end_reason == int(EndReason.OPEN):
                if "UNKNOWN_TAIL" not in explicit_gaps:
                    explicit_gaps.append("OPEN_UNFINISHED")
            elif end_reason == int(EndReason.TIMEOUT_TRUNCATED):
                explicit_gaps.append("TIMEOUT_TRUNCATED")
            elif end_reason == int(EndReason.CONFLICT_TRUNCATED):
                explicit_gaps.append("CONFLICT_TRUNCATED")

            # Intersect per-stream sequence gaps
            for gap in seq_gaps:
                if _seq_gap_overlaps_branch(gap, branch):
                    explicit_gaps.append("SEQ_GAP")
                    break

            # Intersect QUALITY loss events
            b_obj_set = set(b_obj_ids)
            for _qkind, qname, ws, we, q_oid, _q_site in loss_qual_events:
                if q_oid != 0:
                    if q_oid in b_obj_set and qname not in explicit_gaps:
                        explicit_gaps.append(qname)
                else:
                    if start_ts <= we and end_ts >= ws and qname not in explicit_gaps:
                        explicit_gaps.append(qname)

            # Check unpaired/ambiguous queue visits & call pairs
            for v in b_visits:
                if v.ambiguous:
                    visit_or_call_gaps.append("AMBIGUOUS_VISIT")
                elif not v.paired and not v.enq_dropped:
                    visit_or_call_gaps.append("UNCLOSED_VISIT")
            for cp in b_calls:
                if cp.ambiguous:
                    visit_or_call_gaps.append("AMBIGUOUS_CALL")
                elif not cp.paired:
                    visit_or_call_gaps.append("UNMATCHED_CALL_RETURN")

            if explicit_gaps:
                branch.completeness = "incomplete"
                branch.complete = False
                branch.gap_reasons = list(dict.fromkeys(explicit_gaps + visit_or_call_gaps))
            elif has_unobservable_missed_source:
                branch.completeness = "unknown"
                branch.complete = False
                branch.gap_reasons = list(
                    dict.fromkeys(["UNOBSERVABLE_MISSED_SOURCE", *visit_or_call_gaps])
                )
            elif visit_or_call_gaps:
                branch.completeness = "incomplete"
                branch.complete = False
                branch.gap_reasons = list(dict.fromkeys(visit_or_call_gaps))
            else:
                branch.completeness = "complete"
                branch.complete = True
                branch.gap_reasons = []

            sample_branches.append(branch)
            all_branches.append(branch)

        # Sample-level rollup
        s_first_ts = min((objects[oid].first_ts_ns for oid in obj_id_list if objects[oid].first_ts_ns > 0), default=0)
        s_last_ts = max((objects[oid].last_ts_ns for oid in obj_id_list), default=0)
        s_attr: dict[str, Any] = {}
        for oid in obj_id_list:
            for k, val in objects[oid].attribution.items():
                if k not in s_attr and val is not None:
                    s_attr[k] = val

        s_gaps: list[str] = []
        for br in sample_branches:
            for g in br.gap_reasons:
                if g not in s_gaps:
                    s_gaps.append(g)

        s_succ_trunc = any(br.successor_truncated for br in sample_branches) or any(
            objects[oid].successor_truncated for oid in obj_id_list
        )
        s_unk_pred = any(br.unknown_predecessors for br in sample_branches) or any(
            objects[oid].unknown_predecessors for oid in obj_id_list
        )

        if any(br.completeness == "incomplete" for br in sample_branches) or s_succ_trunc:
            s_completeness = "incomplete"
            s_complete = False
        elif any(br.completeness == "unknown" for br in sample_branches) or has_unobservable_missed_source:
            s_completeness = "unknown"
            s_complete = False
        else:
            s_completeness = "complete"
            s_complete = bool(sample_branches)

        samples[sid] = SampleGraph(
            sample_id=sid,
            root_object_ids=roots,
            object_ids=obj_id_list,
            relations=sample_rels,
            branches=sample_branches,
            complete=s_complete,
            completeness=s_completeness,
            gap_reasons=s_gaps,
            successor_truncated=s_succ_trunc,
            unknown_predecessors=s_unk_pred,
            attribution=s_attr,
            first_ts_ns=s_first_ts,
            last_ts_ns=s_last_ts,
        )

    reorder_count = _compute_reorder_count(objects)

    return ReconstructedSession(
        loaded=loaded,
        manifest=manifest,
        dictionary=dictionary,
        sites_by_idx=sites_by_idx,
        events=events,
        dedup_dropped_count=dedup_dropped,
        seq_gaps=seq_gaps,
        quality_events=quality_events,
        qstate_events=qstate_events,
        qstate_annotations=qstate_annotations,
        objects=objects,
        relations=relations,
        samples=samples,
        branches=all_branches,
        unmatched_returns=unmatched_returns,
        has_unobservable_missed_source=has_unobservable_missed_source,
        unobservable_adapters=unobservable_adapters,
        topo_desync_windows=topo_desync_windows,
        requeue_count=requeue_gso_count + requeue_bad_txq_count,
        requeue_gso_count=requeue_gso_count,
        requeue_bad_txq_count=requeue_bad_txq_count,
        reorder_count=reorder_count,
    )
