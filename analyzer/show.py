"""Single-packet / multi-branch timeline & evidence renderer (`pktpath show`).

Matches `总体设计.md` §2.1–§2.2 and `详细设计.md` v3 §2.4 & §5:
- Relative microsecond (`µs`) timeline from sample's first observed timestamp
- Explicit 4-tier evidence labels: `[直接观测]`, `[契约推导]`, `[辅助旁注]`, `[缺口/未知]`
- L1 pure-Linux attribution (`uid`, `pid/comm`, `enqueue_tid (in_task/softirq)`, `xmit_tid`)
- Paired queue visit sojourn (`µs`), `QSTATE` backpressure context, multi-branch forks,
  in-place header rewrites (CLAT/NAT), `SPAN_MAP`, and explicit scope boundary footer
"""

from __future__ import annotations

from typing import Any, Sequence

from .reconstruct import (
    END_REASON_NAMES,
    EVIDENCE_LABELS_ZH,
    STAGE_NAMES,
    BranchPath,
    ObjectNode,
    QueueVisit,
    ReconstructedSession,
    SampleGraph,
    format_rate_bps,
)
from .wire import (
    DecodedEvent,
    Dir,
    EndReason,
    EventFlags,
    EvidenceLevel,
    ObjectType,
    Stage,
)

TC_H_ROOT = 0xFFFFFFFF
TC_H_INGRESS = 0xFFFFFFF1

DIR_LABELS_ZH: dict[int, str] = {
    int(Dir.RX): "RX 接收",
    int(Dir.TX): "本地 TX",
    int(Dir.FWD): "转发 FWD",
}

L4_PROTO_NAMES: dict[int, str] = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    58: "ICMPv6",
}


def format_tc_handle(handle: int | None) -> str:
    if handle is None:
        return "0:"
    h = handle & 0xFFFFFFFF
    if h == TC_H_ROOT:
        return "root"
    if h == TC_H_INGRESS:
        return "ffff:fff1"
    if h == 0:
        return "0:"
    major = (h >> 16) & 0xFFFF
    minor = h & 0xFFFF
    if minor == 0:
        return f"{major:x}:"
    return f"{major:x}:{minor:x}"


def _fmt_rel_us(ts_ns: int, base_ns: int) -> str:
    delta_ns = ts_ns - base_ns
    if delta_ns % 1_000 == 0:
        return f"{delta_ns // 1_000} µs"
    return f"{delta_ns / 1_000.0:.1f} µs"


def _fmt_dur_us(dur_ns: int) -> str:
    if dur_ns % 1_000 == 0:
        return f"{dur_ns // 1_000} µs"
    return f"{dur_ns / 1_000.0:.1f} µs"


def _tcp_seq_in_range(target: int, start: int, end: int) -> bool:
    t = target & 0xFFFFFFFF
    s = start & 0xFFFFFFFF
    e = end & 0xFFFFFFFF
    if t == s:
        return True
    span = (e - s) & 0xFFFFFFFF
    offset = (t - s) & 0xFFFFFFFF
    return span > 0 and offset < span


def filter_samples(
    session: ReconstructedSession,
    *,
    sample_id: int | None = None,
    object_id: int | None = None,
    tcp_seq: int | None = None,
    uid: int | None = None,
) -> list[SampleGraph]:
    """Filter reconstructed samples by any combination of CLI selectors."""
    matched: list[SampleGraph] = []
    for sid in sorted(session.samples.keys()):
        sg = session.samples[sid]
        if sample_id is not None and sg.sample_id != sample_id:
            continue
        if object_id is not None and object_id not in sg.object_ids:
            continue
        if uid is not None:
            uid_hit = sg.attribution.get("uid") == uid or any(
                s.get("uid") == uid
                for oid in sg.object_ids
                for s in session.objects[oid].summaries
            )
            if not uid_hit:
                continue
        if tcp_seq is not None:
            seq_hit = False
            for oid in sg.object_ids:
                for s in session.objects[oid].summaries:
                    if s.get("tcp_seq") is not None:
                        s_seq = int(s["tcp_seq"])
                        e_seq = int(s.get("tcp_seq_end", s_seq) or s_seq)
                        if _tcp_seq_in_range(tcp_seq, s_seq, e_seq):
                            seq_hit = True
                            break
                if seq_hit:
                    break
            if not seq_hit:
                continue
        matched.append(sg)
    return matched


def _format_evidence_suffix(session: ReconstructedSession, ev: DecodedEvent, enabled: bool) -> str:
    if not enabled:
        return ""
    site = session.resolve_site(ev.site_dict_idx)
    parts = [f"event_id={ev.event_id}"]
    if site:
        sym = site.get("symbol") or site.get("name") or f"site#{ev.site_dict_idx}"
        ptype = site.get("probe_type", "probe")
        pver = site.get("probe_version", "1.0")
        adap = site.get("adapter_id", "")
        parts.append(f"probe={ptype}:{sym}@v{pver}")
        if adap:
            parts.append(f"adapter={adap}")
    else:
        parts.append(f"site_idx={ev.site_dict_idx}")
    if ev.unknown_must_tlvs:
        hex_tags = ",".join(f"0x{u.tag:04x}:{u.raw_hex}" for u in ev.unknown_must_tlvs)
        parts.append(f"unknown_must_tlv=[{hex_tags}]")
    return "  [" + ", ".join(parts) + "]"


def _format_summary_brief(summ: DecodedEvent) -> str:
    proto = summ.get("l4_proto")
    pname = L4_PROTO_NAMES.get(int(proto), f"L4({proto})") if proto is not None else "PKT"
    sip = summ.get("src_ip")
    dip = summ.get("dst_ip")
    sport = summ.get("src_port")
    dport = summ.get("dst_port")
    pieces: list[str] = []
    if sip and dip:
        if sport is not None and dport is not None and proto in (6, 17):
            pieces.append(f"{pname} {sip}:{sport} → {dip}:{dport}")
        else:
            pieces.append(f"{pname} {sip} → {dip}")
    if proto == 6 and summ.get("tcp_seq") is not None:
        tseq = int(summ["tcp_seq"])
        tend = int(summ.get("tcp_seq_end", tseq) or tseq)
        pieces.append(f"TCP seq {tseq}:{tend}")
    plen = summ.get("pkt_len")
    if plen is not None:
        pieces.append(f"len={plen}B")
    return "  ".join(pieces)


def _is_tc_class_handle(h: int | None) -> bool:
    if h is None:
        return False
    u = int(h) & 0xFFFFFFFF
    return u != 0 and (u & 0xFFFF0000) != 0xFFFF0000


def _format_class_badge(
    session: ReconstructedSession,
    ifindex: int,
    classid: int,
    *,
    dev_gen: int | None = None,
    ts_ns: int | None = None,
) -> str:
    cls_str = format_tc_handle(classid)
    cinfo = session.resolve_class_info(ifindex, classid, dev_gen=dev_gen, ts_ns=ts_ns)
    if not cinfo:
        return f"CLASS {cls_str}"
    meta: list[str] = []
    if cinfo.get("prio") is not None:
        meta.append(f"prio {cinfo['prio']}")
    rate_txt = format_rate_bps(cinfo.get("rate_bps"), cinfo.get("ceil_bps"))
    if rate_txt:
        meta.append(f"rate {rate_txt}")
    return f"CLASS {cls_str}" + (f" ({', '.join(meta)})" if meta else "")


_format_class_detail_line = _format_class_badge


def _qdisc_label(
    session: ReconstructedSession,
    st: DecodedEvent,
    *,
    site_override: int | None = None,
) -> str:
    ifidx = int(st.get("ifindex", 0) or 0)
    qgen = st.get("queue_gen")
    handle = st.get("qdisc_handle")
    parent = st.get("qdisc_parent")
    dev_gen = st.get("dev_gen")
    h_int = int(handle) if handle is not None else 0
    p_int = int(parent) if parent is not None else 0
    eff_kind = session.resolve_effective_qdisc_kind(
        ifindex=ifidx,
        queue_gen=int(qgen) if qgen is not None else None,
        handle=int(handle) if handle is not None else None,
        parent=int(parent) if parent is not None else None,
        dev_gen=int(dev_gen) if dev_gen is not None else None,
        ts_ns=st.ts_ns,
        site_dict_idx=site_override if site_override is not None else st.site_dict_idx,
    )
    h_str = format_tc_handle(handle)
    if eff_kind:
        kind_str = eff_kind.upper()
    elif session.is_topo_desynced_at(st.ts_ns):
        kind_str = "Qdisc(拓扑失步未知)"
    else:
        kind_str = "Qdisc"
    extras: list[str] = []
    if h_int == 0 and st.get("txq") is not None:
        extras.append(f"txq={st.get('txq')}")
    if qgen is not None and int(qgen) > 0:
        extras.append(f"gen={qgen}")
    suffix = f" ({', '.join(extras)})" if extras else ""
    if h_int == 0 and _is_tc_class_handle(p_int):
        return f"{kind_str} @ {format_tc_handle(p_int)}{suffix}"
    return f"{kind_str} {h_str}{suffix}"


def _boundary_message(scope: str, branch: BranchPath) -> str:
    er = branch.end_reason
    if branch.end_reason_name == "UNKNOWN_TAIL":
        return "会话异常中断/缺少末尾健康检查点 (UNKNOWN_TAIL)；后续状态不可证"
    if er == int(EndReason.TX_OK):
        return f"驱动接手 (NETDEV_TX_OK)；硬件队列/Wi-Fi 固件排队与空口 ACK 位于 {scope} 软件观测范围之外"
    if er == int(EndReason.DROP):
        dr = f" (drop_reason={branch.drop_reason})" if branch.drop_reason is not None else ""
        return f"内核协议栈/队列明确丢包 (DROP){dr}"
    if er == int(EndReason.CONSUME):
        return "内核正常消费释放 (CONSUME)"
    if er == int(EndReason.SOCK_ENQUEUE):
        return "已交付 Socket 接收队列 (SOCK_ENQUEUE)；应用态 recvmsg 读取不在默认边界内"
    if er == int(EndReason.APP_READ):
        return "应用态已完成读取 (APP_READ)"
    if er == int(EndReason.TIMEOUT_TRUNCATED):
        return "采集窗口到期或 Epoch 切换排空截断 (TIMEOUT_TRUNCATED)"
    if er == int(EndReason.CONFLICT_TRUNCATED):
        return "检测到地址身份冲突并隔离截断 (CONFLICT_TRUNCATED)"
    if er == int(EndReason.BOUNDARY):
        return f"跨出当前已挂载观测边界 ({scope} BOUNDARY)"
    return "未观测到终点事件 (OPEN_UNFINISHED)"


def _render_branch_lines(
    session: ReconstructedSession,
    sample: SampleGraph,
    branch: BranchPath,
    *,
    base_ns: int,
    evidence: bool,
    multi_branch: bool,
) -> list[str]:
    lines: list[str] = []
    comp_map = {
        "complete": "完整",
        "incomplete": f"不完整: {', '.join(branch.gap_reasons)}",
        "unknown": f"完整性未知: {', '.join(branch.gap_reasons)}",
    }
    comp_str = comp_map.get(branch.completeness, branch.completeness)

    if multi_branch or len(branch.object_ids) > 1:
        obj_chain = " → ".join(f"#{oid}" for oid in branch.object_ids)
        rel_desc = (
            " / ".join(f"{r.rel_type_name}(#{r.src_object_id}→#{r.dst_object_id})" for r in branch.relation_chain)
            if branch.relation_chain
            else "主路径"
        )
        lines.append(
            f"  ── 支路 #{branch.branch_index} [{rel_desc}]  对象链: {obj_chain}  状态: [{comp_str}]"
        )
    elif branch.completeness != "complete":
        lines.append(f"  [状态提示]  [{comp_str}]")

    # Index visits by entry_event and exit_event identity
    visit_by_entry_id: dict[str, QueueVisit] = {}
    visit_by_exit_id: dict[str, QueueVisit] = {}
    for v in branch.visits:
        if v.entry_event is not None:
            visit_by_entry_id[v.entry_event.event_id] = v
        if v.exit_event is not None:
            visit_by_exit_id[v.exit_event.event_id] = v

    # Show SPAN_MAP / MERGE / SEGMENT relations explicitly
    for rel in branch.relation_chain:
        ev_lbl = EVIDENCE_LABELS_ZH.get(rel.event.evidence_level, "直接观测")
        rel_t = _fmt_rel_us(rel.ts_ns, base_ns)
        extra = ""
        if rel.stream_offset is not None or rel.span_len is not None:
            extra = f", stream_offset={rel.stream_offset}, span_len={rel.span_len}"
        lines.append(
            f"  {rel_t:>8}  [{ev_lbl}]  对象关系       "
            f"{rel.rel_type_name} #{rel.src_object_id} → #{rel.dst_object_id}{extra}"
            f"{_format_evidence_suffix(session, rel.event, evidence)}"
        )
        if rel.unknown_predecessors:
            lines.append(
                "            [缺口/未知]  合并前驱缺失   存在未追踪到的输入前驱 (UNKNOWN_PREDECESSORS)"
            )
        if rel.successor_truncated:
            lines.append(
                "            [缺口/未知]  分段遍历截断   超出最大遍历步长，部分后继段未追踪 (SUCCESSOR_TRUNCATED)"
            )

    # Also check if any object in branch has >1 incoming MERGE predecessors outside `relation_chain`
    for oid in branch.object_ids:
        onode: ObjectNode = session.objects[oid]
        if len(onode.incoming_relations) > 1:
            preds = ", ".join(f"#{r.src_object_id}" for r in onode.incoming_relations)
            lines.append(
                f"    [汇聚]  [直接观测]  多前驱合并     对象 #{oid} 汇聚自前驱 [{preds}]"
            )
        if onode.unknown_predecessors and not any(r.unknown_predecessors for r in branch.relation_chain):
            lines.append(
                f"            [缺口/未知]  合并前驱缺失   对象 #{oid} 含未知前驱 (UNKNOWN_PREDECESSORS)"
            )

    # Interleave steps and secondary (rewrite) summaries
    rewrite_summaries = branch.summaries[1:] if len(branch.summaries) > 1 else []
    rw_idx = 0

    rendered_qstate_ids: set[int] = set()
    last_announced_classid = 0
    i = 0
    steps = branch.steps
    while i < len(steps):
        st = steps[i]

        # Emit any in-place rewrite summary occurring before or at `st.ts_ns`
        while rw_idx < len(rewrite_summaries) and rewrite_summaries[rw_idx].ts_ns <= st.ts_ns:
            rws = rewrite_summaries[rw_idx]
            rw_idx += 1
            rw_t = _fmt_rel_us(rws.ts_ns, base_ns)
            rw_lbl = EVIDENCE_LABELS_ZH.get(rws.evidence_level, "直接观测")
            lines.append(
                f"  {rw_t:>8}  [{rw_lbl}]  原地改写摘要   object_id=#{rws.object_id}  {_format_summary_brief(rws)}"
                f"{_format_evidence_suffix(session, rws, evidence)}"
            )

        stage = int(st.get("stage", 0) or 0)
        ev_lbl = EVIDENCE_LABELS_ZH.get(st.evidence_level, "直接观测")
        rel_t = _fmt_rel_us(st.ts_ns, base_ns)
        ifidx_cur = int(st.get("ifindex", 0) or 0)
        dev_name = session.resolve_dev_name(
            ifidx_cur,
            dev_gen=st.get("dev_gen"),
            netns_inum=st.get("netns_inum"),
            ts_ns=st.ts_ns,
        )

        # Standalone tcf_classify hit (`stage == CLASSIFY`, `qdisc_handle == 0`, `qdisc_parent == 0`, `classid != 0`)
        if (
            stage == int(Stage.CLASSIFY)
            and int(st.get("qdisc_handle", 0) or 0) == 0
            and int(st.get("qdisc_parent", 0) or 0) == 0
            and int(st.get("classid", 0) or 0) != 0
        ):
            cid_val = int(st["classid"])
            c_badge = _format_class_detail_line(
                session, ifidx_cur, cid_val, dev_gen=st.get("dev_gen"), ts_ns=st.ts_ns
            )
            lines.append(
                f"  {rel_t:>8}  [{ev_lbl}]  TC 规则命中子类  {c_badge}"
                f"{_format_evidence_suffix(session, st, evidence)}"
            )
            last_announced_classid = cid_val
            i += 1
            continue

        # Collapse consecutive non-visit CLASSIFY / hierarchy QDISC_ENQ(visit_id==0) steps on same object
        if stage == int(Stage.CLASSIFY) or (
            stage == int(Stage.QDISC_ENQ) and not st.get("visit_id")
        ):
            chain_evs = [st]
            j = i + 1
            while j < len(steps):
                nxt = steps[j]
                nxt_stage = int(nxt.get("stage", 0) or 0)
                nxt_pure_cls = (
                    nxt_stage == int(Stage.CLASSIFY)
                    and int(nxt.get("qdisc_handle", 0) or 0) == 0
                    and int(nxt.get("qdisc_parent", 0) or 0) == 0
                    and int(nxt.get("classid", 0) or 0) != 0
                )
                if (
                    nxt.object_id == st.object_id
                    and not nxt_pure_cls
                    and (
                        nxt_stage == int(Stage.CLASSIFY)
                        or (nxt_stage == int(Stage.QDISC_ENQ) and not nxt.get("visit_id"))
                    )
                ):
                    chain_evs.append(nxt)
                    j += 1
                else:
                    break
            chain_parts: list[str] = []
            for e in chain_evs:
                ecid = int(e.get("classid", 0) or 0)
                if ecid != 0 and ecid != last_announced_classid:
                    chain_parts.append(
                        _format_class_badge(
                            session,
                            int(e.get("ifindex", 0) or 0),
                            ecid,
                            dev_gen=e.get("dev_gen"),
                            ts_ns=e.ts_ns,
                        )
                    )
                    last_announced_classid = ecid
                chain_parts.append(_qdisc_label(session, e))
            chain_txt = " → ".join(chain_parts)
            ev_suf = (
                "".join(_format_evidence_suffix(session, e, evidence) for e in chain_evs)
                if evidence
                else ""
            )
            lines.append(
                f"  {rel_t:>8}  [{ev_lbl}]  {chain_txt:<14} 实读各级 Qdisc handle/parent{ev_suf}"
            )
            i = j
            continue

        if stage == int(Stage.ENTRY):
            tid = st.get("ctx_tid")
            if tid is None:
                tid = sample.attribution.get("enqueue_tid", 0)
            in_task = bool(st.flags & int(EventFlags.IN_TASK))
            ctx_tag = "in_task" if in_task and tid else "softirq"
            lines.append(
                f"  {rel_t:>8}  [{ev_lbl}]  入口准入       "
                f"dev={dev_name}, object_id=#{st.object_id}, enqueue_tid={tid or 0} ({ctx_tag})"
                f"{_format_evidence_suffix(session, st, evidence)}"
            )

        elif st.event_id in visit_by_entry_id:
            v = visit_by_entry_id[st.event_id]
            vcid = int(st.get("classid", 0) or 0)
            if vcid != 0 and vcid != last_announced_classid:
                c_badge = _format_class_detail_line(
                    session, ifidx_cur, vcid, dev_gen=st.get("dev_gen"), ts_ns=st.ts_ns
                )
                lines.append(
                    f"  {rel_t:>8}  [{ev_lbl}]  TC 规则命中子类  {c_badge}"
                )
                last_announced_classid = vcid

            qlbl = (
                "gso_skb 重排队列"
                if v.visit_kind == "requeue_gso"
                else ("skb_bad_txq 队列" if v.visit_kind == "requeue_bad_txq" else _qdisc_label(session, st))
            )
            action_desc = "重新排队入队" if v.visit_kind != "qdisc" else "接收入队"
            enq_note = ""
            if v.enq_dropped:
                enq_note = " -> 入队即丢弃 (NET_XMIT_DROP)"
            elif v.enq_cn:
                enq_note = " [NET_XMIT_CN 拥塞提示]"
            lines.append(
                f"  {rel_t:>8}  [{ev_lbl}]  {qlbl:<14} {action_desc} (visit #{v.visit_id} 开始){enq_note}"
                f"{_format_evidence_suffix(session, st, evidence)}"
            )
            for qs in v.backpressure:
                if id(qs) in rendered_qstate_ids:
                    continue
                rendered_qstate_ids.add(id(qs))
                s_us = _fmt_rel_us(qs.start_ns, base_ns)
                if qs.state_name == "TXQ_STOP_WAKE":
                    e_us = _fmt_rel_us(qs.end_ns, base_ns) if qs.end_ns is not None else "未唤醒"
                    lines.append(
                        f"    [背景]  [直接观测]  队列状态       txq {qs.txq} STOP ({s_us}) → WAKE ({e_us})"
                    )
                else:
                    lines.append(
                        f"    [背景]  [直接观测]  队列状态       txq {qs.txq} {qs.state_name} ({s_us}, val={qs.value})"
                    )
            if not v.paired and not v.enq_dropped:
                lines.append(
                    f"            [缺口/未知]  访问未闭合     visit #{v.visit_id} 缺少匹配出队/丢弃事件，不计算伪驻留时间"
                )

        elif st.event_id in visit_by_exit_id:
            v = visit_by_exit_id[st.event_id]
            entry_site = v.entry_event.site_dict_idx if v.entry_event is not None else st.site_dict_idx
            qlbl = (
                "gso_skb 重排队列"
                if v.visit_kind == "requeue_gso"
                else (
                    "skb_bad_txq 队列"
                    if v.visit_kind == "requeue_bad_txq"
                    else _qdisc_label(session, st, site_override=entry_site)
                )
            )
            if stage == int(Stage.DROP):
                soj_txt = f"，丢弃前停留 {_fmt_dur_us(v.sojourn_ns)}" if v.sojourn_ns is not None else ""
                lines.append(
                    f"  {rel_t:>8}  [{ev_lbl}]  {qlbl:<14} 队列内淘汰丢弃{soj_txt} (visit #{v.visit_id} 闭合)"
                    f"{_format_evidence_suffix(session, st, evidence)}"
                )
            else:
                if v.sojourn_ns is not None:
                    xthread = "，由另一线程出队" if v.cross_thread_dequeue else ""
                    lines.append(
                        f"  {rel_t:>8}  [{ev_lbl}]  {qlbl:<14} 出队，本次停留 {_fmt_dur_us(v.sojourn_ns)} "
                        f"(visit #{v.visit_id} 闭合{xthread})"
                        f"{_format_evidence_suffix(session, st, evidence)}"
                    )
                else:
                    lines.append(
                        f"  {rel_t:>8}  [缺口/未知]  {qlbl:<14} 出队 (visit #{v.visit_id} 缺少唯一入队，不计算驻留)"
                        f"{_format_evidence_suffix(session, st, evidence)}"
                    )

        elif stage == int(Stage.QDISC_ENQ_RET):
            # Only print standalone if not already folded into a visit
            rc = st.get("raw_ret", 0)
            if evidence or (rc is not None and int(rc) != 0):
                lines.append(
                    f"  {rel_t:>8}  [{ev_lbl}]  入队返回       call_id={st.get('call_id', 0)}, rc={rc}"
                    f"{_format_evidence_suffix(session, st, evidence)}"
                )

        elif stage == int(Stage.BYPASS_DIRECT):
            lines.append(
                f"  {rel_t:>8}  [{ev_lbl}]  直接旁路发送   {dev_name} sch_direct_xmit (空队列旁路，0 队列驻留)"
                f"{_format_evidence_suffix(session, st, evidence)}"
            )

        elif stage == int(Stage.HANDOFF_LAYER):
            lines.append(
                f"  {rel_t:>8}  [{ev_lbl}]  跨层/设备交接  {dev_name} (合法延续 object_id=#{st.object_id})"
                f"{_format_evidence_suffix(session, st, evidence)}"
            )

        elif stage == int(Stage.XMIT_START):
            txq = st.get("txq", 0)
            xtid = st.get("ctx_tid", 0)
            # Check if paired XMIT_RET immediately follows or is matched via CallPair
            paired_ret: DecodedEvent | None = None
            cid = st.get("call_id")
            if cid:
                for cp in branch.calls:
                    if cp.entry_event is st and cp.ret_event is not None:
                        paired_ret = cp.ret_event
                        break
            if paired_ret is not None:
                rc = paired_ret.get("raw_ret", 0)
                rc_str = "NETDEV_TX_OK, 驱动接受" if rc in (None, 0) else f"NETDEV_TX_BUSY/rc={rc}"
                ret_t = _fmt_rel_us(paired_ret.ts_ns, base_ns)
                lines.append(
                    f"  {rel_t:>8}  [{ev_lbl}]  TX queue {txq:<5} 提交驱动 -> {ret_t} 返回 ({rc_str}, xmit_tid={xtid or 0})"
                    f"{_format_evidence_suffix(session, st, evidence)}"
                    f"{_format_evidence_suffix(session, paired_ret, evidence)}"
                )
            else:
                lines.append(
                    f"  {rel_t:>8}  [{ev_lbl}]  TX queue {txq:<5} 提交驱动 (ndo_start_xmit, xmit_tid={xtid or 0})"
                    f"{_format_evidence_suffix(session, st, evidence)}"
                )

        elif stage == int(Stage.XMIT_RET):
            # Skip if already rendered together with XMIT_START via CallPair
            already_shown = any(
                cp.ret_event is st and cp.entry_event in steps for cp in branch.calls
            )
            if not already_shown:
                rc = st.get("raw_ret", 0)
                rc_str = "NETDEV_TX_OK" if rc in (None, 0) else f"NETDEV_TX_BUSY/rc={rc}"
                lines.append(
                    f"  {rel_t:>8}  [{ev_lbl}]  驱动发送返回   {rc_str} (call_id={st.get('call_id', 0)})"
                    f"{_format_evidence_suffix(session, st, evidence)}"
                )

        elif stage in (int(Stage.DROP), int(Stage.CONSUME), int(Stage.DELIVER_SOCK)):
            sname = STAGE_NAMES.get(stage, f"STAGE_{stage}")
            lines.append(
                f"  {rel_t:>8}  [{ev_lbl}]  {sname:<14} dev={dev_name}, object_id=#{st.object_id}"
                f"{_format_evidence_suffix(session, st, evidence)}"
            )

        else:
            sname = STAGE_NAMES.get(stage, f"STAGE_{stage}")
            lines.append(
                f"  {rel_t:>8}  [{ev_lbl}]  {sname:<14} dev={dev_name}, object_id=#{st.object_id}"
                f"{_format_evidence_suffix(session, st, evidence)}"
            )

        i += 1

    while rw_idx < len(rewrite_summaries):
        rws = rewrite_summaries[rw_idx]
        rw_idx += 1
        rw_t = _fmt_rel_us(rws.ts_ns, base_ns)
        rw_lbl = EVIDENCE_LABELS_ZH.get(rws.evidence_level, "直接观测")
        lines.append(
            f"  {rw_t:>8}  [{rw_lbl}]  原地改写摘要   object_id=#{rws.object_id}  {_format_summary_brief(rws)}"
            f"{_format_evidence_suffix(session, rws, evidence)}"
        )

    # Render remaining QSTATE annotations not already attached to a specific visit
    for qs in branch.qstate_annotations:
        if id(qs) in rendered_qstate_ids:
            continue
        rendered_qstate_ids.add(id(qs))
        s_us = _fmt_rel_us(qs.start_ns, base_ns)
        if qs.state_name == "TXQ_STOP_WAKE":
            e_us = _fmt_rel_us(qs.end_ns, base_ns) if qs.end_ns is not None else "未唤醒"
            lines.append(
                f"    [背景]  [直接观测]  队列状态       txq {qs.txq} STOP ({s_us}) → WAKE ({e_us})"
            )
        else:
            lines.append(
                f"    [背景]  [直接观测]  队列状态       txq {qs.txq} {qs.state_name} ({s_us}, val={qs.value})"
            )

    # Render external tcpdump candidates strictly as Level-3 annotations (`[辅助旁注]`)
    for cand in branch.tcpdump_annotations:
        lines.append(
            f"    [对照]  [辅助旁注]  tcpdump 候选   frame #{cand.frame_index} [{cand.match_kind}] "
            f"len={cand.orig_len}B, Δt={_fmt_dur_us(cand.delta_from_xmit_ns)} (±{_fmt_dur_us(cand.clock_err_ns)}) — {cand.note}"
        )

    scope_name = str(session.manifest.get("scope") or "tc-egress")
    lines.append(
        f"            [观测边界]  本次观测终点   {_boundary_message(scope_name, branch)}"
    )
    return lines


def render_show_text(
    session: ReconstructedSession,
    samples: Sequence[SampleGraph] | None = None,
    *,
    evidence: bool = False,
    show_evidence: bool | None = None,
) -> str:
    """Render human-readable timeline matching `总体设计 §2.1`."""
    evidence = evidence or bool(show_evidence)
    target_samples = list(session.samples.values()) if samples is None else list(samples)
    if not target_samples:
        return "未找到匹配的样本记录 (0 samples matched)。"

    blocks_txt: list[str] = []
    for sg in target_samples:
        base_ns = sg.first_ts_ns
        root_obj = session.objects[sg.root_object_ids[0]]
        init_sum = root_obj.initial_summary
        if init_sum is None:
            for oid in sg.object_ids:
                if session.objects[oid].initial_summary is not None:
                    init_sum = session.objects[oid].initial_summary
                    break

        first_step = root_obj.steps[0] if root_obj.steps else None
        ifidx = int(
            (init_sum.get("ifindex") if init_sum else None)
            or (first_step.get("ifindex") if first_step else 0)
            or 0
        )
        dir_val = int(
            (init_sum.get("dir") if init_sum and init_sum.get("dir") is not None else None)
            if (init_sum and init_sum.get("dir") is not None)
            else (first_step.get("dir", int(Dir.TX)) if first_step else int(Dir.TX))
        )
        dev_name = session.resolve_dev_name(ifidx, ts_ns=base_ns)
        dir_txt = DIR_LABELS_ZH.get(dir_val, "TX")

        attr = sg.attribution
        uid_str = f"UID {attr['uid']}" if attr.get("uid") is not None else "UID unknown"
        if attr.get("tgid") is not None or attr.get("comm"):
            pid_part = f"pid {attr.get('tgid', '?')}/{attr.get('comm', '?')}"
            owner_txt = f"{uid_str} ({pid_part})"
        else:
            owner_txt = uid_str
        pvals = attr.get("plugin_vals") or {}
        if pvals:
            field_labels = {
                int(pf.get("slot", -1)): str(pf.get("label") or f"plugin_{pf.get('slot')}")
                for pf in (session.dictionary.get("plugin_fields") or [])
                if isinstance(pf, dict)
            }
            for slot in sorted(pvals):
                lbl = field_labels.get(int(slot), f"ext{slot}")
                owner_txt += f" [{lbl}={pvals[slot]}]"

        flow_txt = _format_summary_brief(init_sum) if init_sum is not None else f"object_type={ObjectType(root_obj.object_type).name}"
        hdr = f"样本 {sg.sample_id}  {dir_txt} → {dev_name}  {owner_txt}  {flow_txt}".rstrip()

        sample_lines = [hdr]
        if attr.get("skb_create_ts") is not None and base_ns >= int(attr["skb_create_ts"]):
            pre_us = _fmt_dur_us(base_ns - int(attr["skb_create_ts"]))
            sample_lines.append(
                f"  [-{pre_us}]  [直接观测]  Socket 创建    skb_create_ts 距入口 {pre_us}"
            )

        multi = len(sg.branches) > 1
        for br in sg.branches:
            sample_lines.extend(
                _render_branch_lines(
                    session,
                    sg,
                    br,
                    base_ns=base_ns,
                    evidence=evidence,
                    multi_branch=multi,
                )
            )

        blocks_txt.append("\n".join(sample_lines))

    return "\n\n".join(blocks_txt)


def render_show_json(
    session: ReconstructedSession,
    samples: Sequence[SampleGraph] | None = None,
    *,
    evidence: bool = False,
    show_evidence: bool | None = None,
) -> dict[str, Any]:
    """Serialize matched samples & timelines into structured JSON."""
    evidence = evidence or bool(show_evidence)
    target_samples = list(session.samples.values()) if samples is None else list(samples)
    out_samples: list[dict[str, Any]] = []

    for sg in target_samples:
        base_ns = sg.first_ts_ns
        branches_json: list[dict[str, Any]] = []
        for br in sg.branches:
            steps_json: list[dict[str, Any]] = []
            for st in br.steps:
                stage = int(st.get("stage", 0) or 0)
                st_entry: dict[str, Any] = {
                    "ts_ns": st.ts_ns,
                    "rel_us": round((st.ts_ns - base_ns) / 1_000.0, 3),
                    "object_id": st.object_id,
                    "stage": stage,
                    "stage_name": STAGE_NAMES.get(stage, f"STAGE_{stage}"),
                    "evidence_level": st.evidence_level,
                    "evidence_label": EVIDENCE_LABELS_ZH.get(st.evidence_level, "未知"),
                    "ifindex": st.get("ifindex"),
                    "dev_name": session.resolve_dev_name(int(st.get("ifindex", 0) or 0), ts_ns=st.ts_ns),
                    "visit_id": st.get("visit_id"),
                    "call_id": st.get("call_id"),
                    "queue_gen": st.get("queue_gen"),
                    "qdisc_handle": format_tc_handle(st.get("qdisc_handle")) if st.get("qdisc_handle") is not None else None,
                    "qdisc_parent": format_tc_handle(st.get("qdisc_parent")) if st.get("qdisc_parent") is not None else None,
                    "classid": format_tc_handle(st.get("classid")) if st.get("classid") else None,
                    "txq": st.get("txq"),
                    "raw_ret": st.get("raw_ret"),
                    "ctx_tid": st.get("ctx_tid"),
                    "in_task": bool(st.flags & int(EventFlags.IN_TASK)),
                }
                if evidence:
                    st_entry["event_id"] = st.event_id
                    st_entry["site"] = session.resolve_site(st.site_dict_idx)
                    if st.unknown_must_tlvs:
                        st_entry["unknown_must_tlvs"] = [u.to_dict() for u in st.unknown_must_tlvs]
                steps_json.append(st_entry)

            visits_json = [
                {
                    "visit_id": v.visit_id,
                    "object_id": v.object_id,
                    "queue_gen": v.queue_gen,
                    "visit_kind": v.visit_kind,
                    "qdisc_handle": format_tc_handle(v.qdisc_handle),
                    "qdisc_parent": format_tc_handle(v.qdisc_parent),
                    "txq": v.txq,
                    "paired": v.paired,
                    "ambiguous": v.ambiguous,
                    "enq_dropped": v.enq_dropped,
                    "sojourn_ns": v.sojourn_ns,
                    "sojourn_us": v.sojourn_us,
                    "cross_thread_dequeue": v.cross_thread_dequeue,
                }
                for v in br.visits
            ]

            summaries_json = [
                {
                    "ts_ns": s.ts_ns,
                    "rel_us": round((s.ts_ns - base_ns) / 1_000.0, 3),
                    "object_id": s.object_id,
                    "pkt_len": s.get("pkt_len"),
                    "ip_version": s.get("ip_version"),
                    "l4_proto": s.get("l4_proto"),
                    "src_ip": s.get("src_ip"),
                    "dst_ip": s.get("dst_ip"),
                    "src_port": s.get("src_port"),
                    "dst_port": s.get("dst_port"),
                    "tcp_seq": s.get("tcp_seq"),
                    "tcp_seq_end": s.get("tcp_seq_end"),
                    "uid": s.get("uid"),
                    "tgid": s.get("tgid"),
                    "comm": s.get("comm"),
                    "enqueue_tid": s.get("enqueue_tid"),
                }
                for s in br.summaries
            ]

            branches_json.append(
                {
                    "branch_id": br.branch_id,
                    "branch_index": br.branch_index,
                    "object_ids": br.object_ids,
                    "end_reason": br.end_reason,
                    "end_reason_name": br.end_reason_name,
                    "drop_reason": br.drop_reason,
                    "complete": br.complete,
                    "completeness": br.completeness,
                    "gap_reasons": br.gap_reasons,
                    "requeue_count": br.requeue_count,
                    "successor_truncated": br.successor_truncated,
                    "unknown_predecessors": br.unknown_predecessors,
                    "summaries": summaries_json,
                    "steps": steps_json,
                    "visits": visits_json,
                    "qstate_annotations": [
                        {
                            "ifindex": q.ifindex,
                            "txq": q.txq,
                            "state_name": q.state_name,
                            "start_ns": q.start_ns,
                            "end_ns": q.end_ns,
                            "value": q.value,
                        }
                        for q in br.qstate_annotations
                    ],
                    "tcpdump_annotations": [
                        c.to_dict() if hasattr(c, "to_dict") else c
                        for c in br.tcpdump_annotations
                    ],
                    "relations": [
                        {
                            "op_id": r.op_id,
                            "rel_type": r.rel_type,
                            "rel_type_name": r.rel_type_name,
                            "src_object_id": r.src_object_id,
                            "dst_object_id": r.dst_object_id,
                            "stream_offset": r.stream_offset,
                            "span_len": r.span_len,
                            "successor_truncated": r.successor_truncated,
                            "unknown_predecessors": r.unknown_predecessors,
                        }
                        for r in br.relation_chain
                    ],
                }
            )

        out_samples.append(
            {
                "sample_id": sg.sample_id,
                "root_object_ids": sg.root_object_ids,
                "object_ids": sg.object_ids,
                "complete": sg.complete,
                "completeness": sg.completeness,
                "gap_reasons": sg.gap_reasons,
                "attribution": sg.attribution,
                "first_ts_ns": sg.first_ts_ns,
                "last_ts_ns": sg.last_ts_ns,
                "branches": branches_json,
            }
        )

    return {
        "session_uuid": session.loaded.session_uuid_str,
        "scope": session.manifest.get("scope", "tc-egress"),
        "unclean_tail": session.loaded.unclean_tail,
        "matched_sample_count": len(out_samples),
        "samples": out_samples,
    }
