"""Cohort statistics, admission denominators, completeness & sojourn quantiles (`pktpath stats`).

Implements `详细设计.md` v3 §5.2–§5.3:
- All 5 admission denominators: `filter_unknown`, `matched`, `selected`, `created`, `rejected`
- Branch completeness breakdown: `complete`, `incomplete`, `unknown_completeness`
- Endpoint distribution (`TX_OK`, `DROP`, `CONSUME`, `SOCK_ENQUEUE`, `TIMEOUT_TRUNCATED`, ...)
- `requeue_count` vs `reorder_count`
- Per-queue `p50`/`p95`/`p99` sojourn with paired sample count `n` (never fabricating sojourn on `BYPASS_DIRECT` or unpaired visits)
- Independent `skb_bytes` vs `wire_bytes` accounting
- Grouping by `path | leaf | status | uid`
"""

from __future__ import annotations

import math
from collections import defaultdict
from typing import Any, Sequence

from .reconstruct import (
    STAGE_NAMES,
    BranchPath,
    QueueVisit,
    ReconstructedSession,
    format_rate_bps,
)
from .show import format_tc_handle
from .wire import Dir, EndReason, ObjectType, QualKind, Stage


def _percentile(sorted_vals: Sequence[float], pct: float) -> float | None:
    if not sorted_vals:
        return None
    if len(sorted_vals) == 1:
        return round(sorted_vals[0], 3)
    rank = (pct / 100.0) * (len(sorted_vals) - 1)
    lo = int(math.floor(rank))
    hi = int(math.ceil(rank))
    if lo == hi:
        return round(sorted_vals[lo], 3)
    weight = rank - lo
    return round(sorted_vals[lo] * (1.0 - weight) + sorted_vals[hi] * weight, 3)


def _push_dedup(tokens: list[str], tok: str) -> None:
    if not tokens or tokens[-1] != tok:
        tokens.append(tok)


def _is_tc_class_handle(h: int | None) -> bool:
    if h is None:
        return False
    u = int(h) & 0xFFFFFFFF
    return u != 0 and (u & 0xFFFF0000) != 0xFFFF0000


def _branch_path_tokens(session: ReconstructedSession, br: BranchPath) -> list[str]:
    tokens: list[str] = []
    for st in br.steps:
        stage = int(st.get("stage", 0) or 0)
        ifidx = int(st.get("ifindex", 0) or 0)
        dev = session.resolve_dev_name(ifidx, dev_gen=st.get("dev_gen"), ts_ns=st.ts_ns)
        if stage == int(Stage.ENTRY):
            tokens.append(f"ENTRY({dev})")
        elif stage in (int(Stage.CLASSIFY), int(Stage.QDISC_ENQ)):
            qhandle = int(st.get("qdisc_handle", 0) or 0)
            qparent = int(st.get("qdisc_parent", 0) or 0)
            cid = int(st.get("classid", 0) or 0)

            # Pure tcf_classify step (qdisc_handle == 0, qdisc_parent == 0, classid != 0)
            if stage == int(Stage.CLASSIFY) and qhandle == 0 and qparent == 0 and cid != 0:
                _push_dedup(tokens, f"CLASS:{format_tc_handle(cid)}")
                continue

            # Qdisc classify / enqueue step: emit CLASS:<classid> first when classid != 0
            if cid != 0:
                _push_dedup(tokens, f"CLASS:{format_tc_handle(cid)}")

            eff_kind = session.resolve_effective_qdisc_kind(
                ifindex=ifidx,
                queue_gen=st.get("queue_gen"),
                handle=st.get("qdisc_handle") if st.get("qdisc_handle") is not None else qhandle,
                parent=st.get("qdisc_parent") if st.get("qdisc_parent") is not None else qparent,
                dev_gen=st.get("dev_gen"),
                ts_ns=st.ts_ns,
                site_dict_idx=st.site_dict_idx,
            )
            qkind = eff_kind.upper() if eff_kind else "QDISC"
            if qhandle == 0 and _is_tc_class_handle(qparent):
                lbl = f"{qkind}@{format_tc_handle(qparent)}"
            else:
                lbl = f"{qkind}:{format_tc_handle(qhandle)}"
            _push_dedup(tokens, lbl)
        elif stage == int(Stage.BYPASS_DIRECT):
            tokens.append("BYPASS_DIRECT")
        elif stage == int(Stage.REQUEUE_GSO):
            tokens.append("REQUEUE_GSO")
        elif stage == int(Stage.REQUEUE_BAD_TXQ):
            tokens.append("REQUEUE_BAD_TXQ")
        elif stage == int(Stage.HANDOFF_LAYER):
            tokens.append(f"HANDOFF({dev})")
        elif stage == int(Stage.XMIT_START):
            tokens.append(f"XMIT({dev}:txq{st.get('txq', 0)})")
    tokens.append(br.end_reason_name)
    return tokens


def _branch_path_signature(session: ReconstructedSession, br: BranchPath) -> str:
    return " -> ".join(_branch_path_tokens(session, br))


def _branch_leaf_signature(session: ReconstructedSession, br: BranchPath) -> str:
    if br.visits:
        qdisc_visits = [v for v in br.visits if v.visit_kind == "qdisc"]
        v = qdisc_visits[-1] if qdisc_visits else br.visits[-1]
        dev = session.resolve_dev_name(v.ifindex, dev_gen=v.dev_gen)
        eff_kind = session.resolve_effective_qdisc_kind(
            ifindex=v.ifindex,
            queue_gen=v.queue_gen,
            handle=v.qdisc_handle,
            parent=v.qdisc_parent,
            dev_gen=v.dev_gen,
            ts_ns=v.entry_event.ts_ns if v.entry_event else None,
            site_dict_idx=v.entry_event.site_dict_idx if v.entry_event else None,
        )
        qkind = eff_kind if eff_kind else v.visit_kind
        h_str = format_tc_handle(v.qdisc_handle)
        p_str = format_tc_handle(v.qdisc_parent)
        txq_part = f":txq{v.txq}" if v.txq is not None else ""
        if v.qdisc_handle == 0 and _is_tc_class_handle(v.qdisc_parent):
            return f"{dev}:{qkind}@{p_str}(parent={p_str},gen={v.queue_gen}{txq_part})"
        return f"{dev}:{qkind}:{h_str}(parent={p_str},gen={v.queue_gen}{txq_part})"

    if any(int(s.get("stage", 0) or 0) == int(Stage.BYPASS_DIRECT) for s in br.steps):
        return "BYPASS_DIRECT"
    return "NO_QUEUE_VISIT"


def _branch_uid_key(session: ReconstructedSession, br: BranchPath) -> str:
    sg = session.samples.get(br.sample_id)
    if sg and sg.attribution.get("uid") is not None:
        return str(sg.attribution["uid"])
    for s in br.summaries:
        if s.get("uid") is not None:
            return str(s["uid"])
    return "unknown"


def compute_stats(
    session: ReconstructedSession,
    *,
    group_by: str = "path",
) -> dict[str, Any]:
    """Compute comprehensive cohort statistics, denominators, quantiles, and byte totals."""
    if group_by not in ("path", "leaf", "status", "uid"):
        raise ValueError(f"Unsupported --group-by value: {group_by!r}")

    raw_adm = session.manifest.get("admissions") or {}
    admissions = {
        "filter_unknown": int(raw_adm.get("filter_unknown", 0) or 0),
        "matched": int(raw_adm.get("matched", raw_adm.get("admission_matched", 0)) or 0),
        "selected": int(raw_adm.get("selected", raw_adm.get("admission_selected", 0)) or 0),
        "created": int(raw_adm.get("created", raw_adm.get("admission_created", 0)) or 0),
        "rejected": int(raw_adm.get("rejected", raw_adm.get("admission_rejected", 0)) or 0),
    }

    complete_cnt = sum(1 for b in session.branches if b.completeness == "complete")
    incomplete_cnt = sum(1 for b in session.branches if b.completeness == "incomplete")
    unknown_cnt = sum(1 for b in session.branches if b.completeness == "unknown")

    endpoint_dist: dict[str, int] = defaultdict(int)
    for b in session.branches:
        endpoint_dist[b.end_reason_name] += 1

    # Separate skb_bytes vs wire_bytes accounting (`详细设计 §5.2`)
    # 1) skb_bytes: unique root/entry SKB objects (not child clones/segments of another SKB)
    skb_bytes = 0
    skb_packets = 0
    rx_wire_bytes = 0
    rx_wire_packets = 0

    for obj in session.objects.values():
        if obj.object_type != int(ObjectType.SKB):
            continue
        has_skb_parent = any(
            session.objects.get(r.src_object_id) is not None
            and session.objects[r.src_object_id].object_type == int(ObjectType.SKB)
            for r in obj.incoming_relations
        )
        if not has_skb_parent:
            init_s = obj.initial_summary
            plen = int(init_s.get("pkt_len", 0) or 0) if init_s is not None else 0
            skb_bytes += plen
            skb_packets += 1
            s_dir = init_s.get("dir") if init_s is not None else None
            if s_dir == int(Dir.RX):
                rx_wire_bytes += plen
                rx_wire_packets += 1

    # 2) wire_bytes: leaf SKB objects transmitted on wire (`TX_OK`), plus RX wire arrivals
    tx_wire_bytes = 0
    tx_wire_packets = 0
    counted_tx_leaf_objs: set[int] = set()
    for br in session.branches:
        leaf_oid = br.leaf_object_id
        if br.end_reason == int(EndReason.TX_OK) and leaf_oid not in counted_tx_leaf_objs:
            counted_tx_leaf_objs.add(leaf_oid)
            leaf_obj = session.objects[leaf_oid]
            last_s = leaf_obj.latest_summary
            if last_s is None and br.summaries:
                last_s = br.summaries[-1]
            plen = int(last_s.get("pkt_len", 0) or 0) if last_s is not None else 0
            tx_wire_bytes += plen
            tx_wire_packets += 1

    wire_bytes = tx_wire_bytes + rx_wire_bytes
    wire_packets = tx_wire_packets + rx_wire_packets

    # Per-queue sojourn quantiles (strictly deduplicated per unique QueueVisit object)
    seen_visits: set[tuple[int, int, int]] = set()
    queue_buckets: dict[tuple[Any, ...], list[QueueVisit]] = defaultdict(list)

    for obj in session.objects.values():
        for v in obj.visits:
            v_uid = (v.object_id, v.queue_gen, v.visit_id)
            if v_uid in seen_visits:
                continue
            seen_visits.add(v_uid)
            q_key = (
                v.netns_inum,
                v.ifindex,
                v.dev_gen,
                v.queue_gen,
                v.visit_kind,
                v.qdisc_handle,
                v.qdisc_parent,
                v.txq if v.qdisc_handle == 0 else None,
            )
            queue_buckets[q_key].append(v)

    queues_out: list[dict[str, Any]] = []
    for q_key, v_list in sorted(queue_buckets.items()):
        netns, ifidx, dgen, qgen, vkind, handle, parent, txq_key = q_key
        dev_name = session.resolve_dev_name(ifidx, dev_gen=dgen, netns_inum=netns)
        sample_ev = v_list[0].entry_event or v_list[0].exit_event
        eff_kind = session.resolve_effective_qdisc_kind(
            ifindex=ifidx,
            queue_gen=qgen,
            handle=handle,
            parent=parent,
            dev_gen=dgen,
            ts_ns=sample_ev.ts_ns if sample_ev else None,
            site_dict_idx=sample_ev.site_dict_idx if sample_ev else None,
        )
        if vkind != "qdisc":
            qkind_name = vkind
        elif eff_kind:
            qkind_name = eff_kind
        else:
            qkind_name = "qdisc"

        h_str = format_tc_handle(handle)
        p_str = format_tc_handle(parent)
        if vkind == "requeue_gso":
            q_label = f"{dev_name} gso_skb 重排队列"
        elif vkind == "requeue_bad_txq":
            q_label = f"{dev_name} skb_bad_txq 队列"
        elif handle == 0 and _is_tc_class_handle(parent):
            q_label = f"{dev_name} {qkind_name.upper()} @ {p_str}"
        else:
            q_label = f"{dev_name} {qkind_name.upper()} {h_str}"

        cls_lookup_id = (
            parent
            if (_is_tc_class_handle(parent) and (parent & 0xFFFF) != 0)
            else v_list[0].classid
        )
        cinfo = session.resolve_class_info(
            ifidx,
            cls_lookup_id,
            dev_gen=dgen,
            ts_ns=sample_ev.ts_ns if sample_ev else None,
        )
        class_rate = (
            format_rate_bps(cinfo.get("rate_bps"), cinfo.get("ceil_bps"))
            if cinfo is not None
            else None
        )
        class_prio = int(cinfo["prio"]) if cinfo is not None and cinfo.get("prio") is not None else None

        paired_us = sorted(
            v.sojourn_us for v in v_list if v.paired and v.sojourn_us is not None
        )
        paired_ns = sorted(
            v.sojourn_ns for v in v_list if v.paired and v.sojourn_ns is not None
        )
        paired_n = len(paired_us)
        unpaired_n = sum(1 for v in v_list if not v.paired and not v.enq_dropped)
        enq_drop_n = sum(1 for v in v_list if v.enq_dropped)

        queues_out.append(
            {
                "label": q_label,
                "netns_inum": netns,
                "ifindex": ifidx,
                "dev_gen": dgen,
                "dev_name": dev_name,
                "queue_gen": qgen,
                "kind": qkind_name,
                "visit_kind": vkind,
                "handle": h_str,
                "parent": p_str,
                "class_rate": class_rate,
                "class_prio": class_prio,
                "txq": txq_key if txq_key is not None else v_list[0].txq,
                "n": paired_n,
                "paired_n": paired_n,
                "unpaired_n": unpaired_n,
                "enq_drop_n": enq_drop_n,
                "p50_us": _percentile(paired_us, 50.0),
                "p95_us": _percentile(paired_us, 95.0),
                "p99_us": _percentile(paired_us, 99.0),
                "min_us": round(paired_us[0], 3) if paired_us else None,
                "max_us": round(paired_us[-1], 3) if paired_us else None,
                "mean_us": round(sum(paired_us) / paired_n, 3) if paired_n > 0 else None,
                "p50_ns": int(_percentile([float(x) for x in paired_ns], 50.0)) if paired_ns else None,
                "p95_ns": int(_percentile([float(x) for x in paired_ns], 95.0)) if paired_ns else None,
                "p99_ns": int(_percentile([float(x) for x in paired_ns], 99.0)) if paired_ns else None,
            }
        )

    # Cohort grouping (`path | leaf | status | uid`)
    grouped_branches: dict[str, list[BranchPath]] = defaultdict(list)
    for br in session.branches:
        if group_by == "path":
            gkey = _branch_path_signature(session, br)
        elif group_by == "leaf":
            gkey = _branch_leaf_signature(session, br)
        elif group_by == "status":
            gkey = f"{br.completeness}:{br.end_reason_name}"
        else:  # uid
            gkey = _branch_uid_key(session, br)
        grouped_branches[gkey].append(br)

    groups_out: list[dict[str, Any]] = []
    for gkey, b_list in sorted(grouped_branches.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        g_endpoints: dict[str, int] = defaultdict(int)
        g_wire_bytes = 0
        g_skb_bytes = 0
        seen_root_objs: set[int] = set()
        seen_tx_objs: set[int] = set()

        for b in b_list:
            g_endpoints[b.end_reason_name] += 1
            root_oid = b.object_ids[0]
            if root_oid not in seen_root_objs and session.objects[root_oid].object_type == int(ObjectType.SKB):
                seen_root_objs.add(root_oid)
                s0 = session.objects[root_oid].initial_summary
                if s0 is not None:
                    g_skb_bytes += int(s0.get("pkt_len", 0) or 0)
            leaf_oid = b.leaf_object_id
            if b.end_reason == int(EndReason.TX_OK) and leaf_oid not in seen_tx_objs:
                seen_tx_objs.add(leaf_oid)
                sl = session.objects[leaf_oid].latest_summary
                if sl is not None:
                    g_wire_bytes += int(sl.get("pkt_len", 0) or 0)

        groups_out.append(
            {
                "key": gkey,
                "branch_count": len(b_list),
                "complete": sum(1 for b in b_list if b.completeness == "complete"),
                "incomplete": sum(1 for b in b_list if b.completeness == "incomplete"),
                "unknown_completeness": sum(1 for b in b_list if b.completeness == "unknown"),
                "skb_bytes": g_skb_bytes,
                "wire_bytes": g_wire_bytes,
                "endpoints": dict(sorted(g_endpoints.items())),
            }
        )

    qual_totals: dict[str, int] = defaultdict(int)
    for qev in session.quality_events:
        qkind = int(qev.get("qual_kind", 0) or 0)
        qcnt = int(qev.get("count", 0) or 0)
        if qkind == int(QualKind.MISSED_DELTA):
            qual_totals["missed_delta"] += qcnt
        elif qkind == int(QualKind.RB_DROP_DELTA):
            qual_totals["rb_drop_delta"] += qcnt
        elif qkind == int(QualKind.RET_UNMATCHED):
            qual_totals["ret_unmatched"] += max(qcnt, 1)
        elif qkind == int(QualKind.IDENTITY_CONFLICT):
            qual_totals["identity_conflict"] += max(qcnt, 1)
        elif qkind == int(QualKind.TOPO_DESYNC):
            qual_totals["topo_desync"] += max(qcnt, 1)

    return {
        "session_uuid": session.loaded.session_uuid_str,
        "scope": session.manifest.get("scope", "tc-egress"),
        "mode": session.manifest.get("mode", "oneshot"),
        "sample_rate": session.manifest.get("sample_rate", "1/1"),
        "group_by": group_by,
        "admissions": admissions,
        "samples": {
            "total": len(session.samples),
            "objects_total": len(session.objects),
            "events_total": len(session.events),
            "dedup_dropped": session.dedup_dropped_count,
        },
        "branches": {
            "total": len(session.branches),
            "complete": complete_cnt,
            "incomplete": incomplete_cnt,
            "unknown_completeness": unknown_cnt,
            "unknown": unknown_cnt,
        },
        "endpoints": dict(sorted(endpoint_dist.items())),
        "requeue_count": session.requeue_count,
        "requeue_gso_count": session.requeue_gso_count,
        "requeue_bad_txq_count": session.requeue_bad_txq_count,
        "reorder_count": session.reorder_count,
        "dynamics": {
            "requeue_count": session.requeue_count,
            "requeue_gso_count": session.requeue_gso_count,
            "requeue_bad_txq_count": session.requeue_bad_txq_count,
            "reorder_count": session.reorder_count,
        },
        "skb_bytes": skb_bytes,
        "wire_bytes": wire_bytes,
        "skb_packets": skb_packets,
        "wire_packets": wire_packets,
        "bytes": {
            "skb_bytes": skb_bytes,
            "wire_bytes": wire_bytes,
            "skb_packets": skb_packets,
            "wire_packets": wire_packets,
        },
        "queues": queues_out,
        "groups": groups_out,
        "quality": {
            "seq_gap_windows": len(session.seq_gaps),
            "seq_gap_missing_events": sum(g.missing_count for g in session.seq_gaps),
            "missed_delta": qual_totals["missed_delta"],
            "rb_drop_delta": qual_totals["rb_drop_delta"],
            "ret_unmatched": qual_totals["ret_unmatched"] + len(session.unmatched_returns),
            "identity_conflict": qual_totals["identity_conflict"],
            "topo_desync": qual_totals["topo_desync"],
            "unclean_tail": session.loaded.unclean_tail,
            "unobservable_missed_source": session.has_unobservable_missed_source,
        },
    }


def render_stats_text(stats: dict[str, Any]) -> str:
    """Format `compute_stats()` dictionary into a clean human-readable report."""
    adm = stats["admissions"]
    br = stats["branches"]
    sm = stats["samples"]
    ql = stats["quality"]

    lines = [
        f"=== pktpath 会话统计报告 (UUID: {stats['session_uuid']}, scope={stats['scope']}, mode={stats['mode']}) ===",
        "",
        "1. 入口准入分母披露 (Admissions):",
        f"   filter_unknown={adm['filter_unknown']}  matched={adm['matched']}  "
        f"selected={adm['selected']}  created={adm['created']}  rejected={adm['rejected']}",
        f"   已重建样本数={sm['total']}  对象总数={sm['objects_total']}  "
        f"有效事件={sm['events_total']} (去重丢弃={sm['dedup_dropped']})",
        "",
        "2. 支路完整性与终点分布 (Branches & Endpoints):",
        f"   total={br['total']}  complete={br['complete']}  "
        f"incomplete={br['incomplete']}  unknown_completeness={br['unknown_completeness']}",
        "   终点分布: "
        + (
            "  ".join(f"{k}={v}" for k, v in stats["endpoints"].items())
            if stats["endpoints"]
            else "(无)"
        ),
        "",
        "3. 调度动态与独立字节记账 (Requeue vs Reorder / SKB vs Wire):",
        f"   requeue_count={stats['requeue_count']} (gso_skb={stats['requeue_gso_count']}, bad_txq={stats['requeue_bad_txq_count']})  "
        f"reorder_count={stats['reorder_count']}",
        f"   skb_bytes={stats['skb_bytes']} ({stats['skb_packets']} pkts)  "
        f"wire_bytes={stats['wire_bytes']} ({stats['wire_packets']} pkts)",
        "",
        "4. 逐队列成对驻留分位数 (Per-Queue Sojourn µs):",
    ]

    if not stats["queues"]:
        lines.append("   (无队列访问记录；直接旁路 BYPASS_DIRECT 不计伪队列驻留)")
    else:
        for q in stats["queues"]:
            txq_str = f", txq={q['txq']}" if q["txq"] is not None else ""
            cls_meta: list[str] = []
            if q.get("class_prio") is not None:
                cls_meta.append(f"prio={q['class_prio']}")
            if q.get("class_rate"):
                cls_meta.append(f"rate={q['class_rate']}")
            cls_str = f", {', '.join(cls_meta)}" if cls_meta else ""
            q_head = q.get("label") or f"{q['dev_name']} {q['kind']} {q['handle']}"
            if q["paired_n"] > 0:
                lines.append(
                    f"   - {q_head} (parent={q['parent']}, gen={q['queue_gen']}{txq_str}{cls_str}): "
                    f"n={q['paired_n']} (unpaired={q['unpaired_n']}, enq_drop={q['enq_drop_n']}) | "
                    f"p50={q['p50_us']} µs  p95={q['p95_us']} µs  p99={q['p99_us']} µs"
                )
            else:
                lines.append(
                    f"   - {q_head} (parent={q['parent']}, gen={q['queue_gen']}{txq_str}{cls_str}): "
                    f"n=0 (unpaired={q['unpaired_n']}, enq_drop={q['enq_drop_n']}) | 无有效成对样本"
                )

    lines.extend(
        [
            "",
            f"5. 分组汇总 (--group-by {stats['group_by']}):",
        ]
    )
    if not stats["groups"]:
        lines.append("   (无支路数据)")
    else:
        for g in stats["groups"]:
            lines.append(
                f"   - [{g['key']}] branches={g['branch_count']} "
                f"(complete={g['complete']}, incomplete={g['incomplete']}, unknown={g['unknown_completeness']}) "
                f"skb_bytes={g['skb_bytes']} wire_bytes={g['wire_bytes']}"
            )

    lines.extend(
        [
            "",
            "6. 质量与静默损失检查 (Quality & Silent Loss):",
            f"   seq_gaps={ql['seq_gap_windows']} ({ql['seq_gap_missing_events']} evs)  "
            f"missed_delta={ql['missed_delta']}  rb_drop_delta={ql['rb_drop_delta']}  "
            f"ret_unmatched={ql['ret_unmatched']}  identity_conflict={ql['identity_conflict']}  "
            f"topo_desync={ql['topo_desync']}  unclean_tail={ql['unclean_tail']}  "
            f"unobservable_missed_source={ql['unobservable_missed_source']}",
        ]
    )
    return "\n".join(lines)
