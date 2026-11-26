// Pure TypeScript 1:1 port of studio/pkg/reconstruct/views.go (erasableSyntaxOnly).
// All uint64 IDs/timestamps/counts are stored as bigint internally and serialized
// as decimal strings in JSON views per WAVE1-CONTRACT.md v1.1/v1.2.

import {
  DIR_FWD,
  DIR_RX,
  DIR_TX,
  END_APP_READ,
  END_BOUNDARY,
  END_CONFLICT_TRUNCATED,
  END_CONSUME,
  END_DROP,
  END_SOCK_ENQUEUE,
  END_TIMEOUT_TRUNCATED,
  END_TX_OK,
  EV_FLAG_IN_TASK,
  EVIDENCE_ANNOTATION,
  EVIDENCE_CONTRACT_DERIVED,
  EVIDENCE_DIRECT,
  EVIDENCE_GAP,
  EVIDENCE_LABELS_ZH,
  REL_CLONE,
  REL_COPY,
  STAGE_BYPASS_DIRECT,
  STAGE_CLASSIFY,
  STAGE_DROP,
  STAGE_ENTRY,
  STAGE_HANDOFF_LAYER,
  STAGE_NAMES,
  STAGE_QDISC_ENQ,
  STAGE_QDISC_ENQ_RET,
  STAGE_XMIT_RET,
  STAGE_XMIT_START,
  USERSPACE_CPU,
} from '../wire/consts.ts'
import { asInt } from '../wire/wire.ts'
import type { WireEvent } from '../wire/wire.ts'
import {
  branchLeafObjectId,
  objectInitialSummary,
} from './model.ts'
import type { BranchPath, QStateAnnotation, QueueVisit, SampleGraph, Session } from './model.ts'
import { branchPathSignature, computeStats, round3 } from './stats.ts'
import type { Stats } from './stats.ts'
import {
  evOpt,
  formatClassSummary,
  formatTCHandle,
  isParentTCClass,
  jstr,
  manifestStr,
} from './topo.ts'

const DIR_LABELS_ZH: Record<number, string> = {
  [DIR_RX]: 'RX 接收',
  [DIR_TX]: '本地 TX',
  [DIR_FWD]: '转发 FWD',
}

const L4_PROTO_NAMES: Record<string, string> = {
  '1': 'ICMP',
  '6': 'TCP',
  '17': 'UDP',
  '58': 'ICMPv6',
}

export interface SessionOverview {
  manifest: Record<string, unknown>
  dict: Record<string, unknown>
  stats: Stats
  samples: SampleRow[]
}

export interface SampleRow {
  sample_id: string
  uid: string | null
  tgid: string | null
  comm: string
  enqueue_tid: string
  in_task: boolean
  proto: string
  src: string
  dst: string
  src_ip: string
  dst_ip: string
  src_port: string | null
  dst_port: string | null
  tcp_seq: string | null
  tcp_seq_end: string | null
  pkt_len: string
  max_sojourn_us: number
  total_us: number
  complete: boolean
  completeness: string
  gap_reasons: string[]
  endpoint: string
  branch_count: number
  requeued: boolean
  path_sig: string
  path_sigs: string[]
}

export interface SampleSummary {
  sample_id: string
  uid: string | null
  tgid: string | null
  comm: string
  enqueue_tid: string
  proto: string
  src: string
  dst: string
  tcp_seq: string | null
  pkt_len: string
  max_sojourn_us: number
  total_us: number
  complete: boolean
  completeness: string
  endpoint: string
  branch_count: number
  requeued: boolean
  path_sig: string
  dev_name: string
  dir_label: string
  xmit_tid?: string
  skb_create_rel_us?: number
  plugin_tags?: Record<string, string>
  tcp_seq_end?: string
  skb_mark?: string
  skb_priority?: string
  skb_hash?: string
  linear_len?: string
  headline?: string
  gap_reasons: string[]
}

export interface TimelineEvent {
  rel_us: number
  ts_ns: string
  evidence_level: number
  evidence_label: string
  stage: string
  stage_code: number
  title: string
  detail: string
  sojourn_us: number | null
  cpu: number | null
  tid: string | null
  in_task: boolean | null
  enqueue_cpu?: number
  enqueue_tid?: string
  cross_cpu: boolean
  cross_thread: boolean
  object_id: string
  visit_id?: string
  qdisc_handle?: string
  txq?: string
  event_id: string
  probe_name: string
  probe_type: string
  probe_version: string
  adapter_name: string
}

export interface BranchDetail {
  branch_id: string
  branch_index: number
  label: string
  path_sig: string
  complete: boolean
  completeness: string
  gap_reasons: string[]
  endpoint: string
  end_reason: number
  drop_reason: string | null
  boundary_note: string
  object_chain: string[]
  requeue_count: number
  start_rel_us: number
  end_rel_us: number
  total_us: number
  max_sojourn_us: number
  timeline: TimelineEvent[]
}

export interface RelationEdge {
  op_id: string
  rel_type: string
  rel_type_code: number
  src_object_id: string
  dst_object_id: string
  rel_us: number
  ts_ns: string
  stream_offset?: string
  span_len?: string
  successor_truncated: boolean
  unknown_predecessors: boolean
}

export interface QStateSpan {
  ifindex: string
  dev_name: string
  txq: string
  queue_gen: string
  state_op: string
  state_op_code: number
  start_rel_us: number
  end_rel_us: number | null
  start_ns: string
  end_ns: string | null
  open: boolean
  value: string
}

export interface SampleDetail {
  sample_id: string
  summary: SampleSummary
  branches: BranchDetail[]
  relations: RelationEdge[]
  qstates: QStateSpan[]
}

function relUs(tsNs: bigint, baseNs: bigint): number {
  return round3(Number(tsNs - baseNs) / 1000.0)
}

function durUs(startNs: bigint, endNs: bigint): number {
  if (endNs <= startNs) return 0
  return round3(Number(endNs - startNs) / 1000.0)
}

function fmtDurUsText(ns: bigint): string {
  if (ns % 1000n === 0n) return `${(ns / 1000n).toString()} µs`
  return `${(Number(ns) / 1000.0).toFixed(1)} µs`
}

function fmtRelUsText(tsNs: bigint, baseNs: bigint): string {
  const d = tsNs - baseNs
  if (d % 1000n === 0n) return `${(d / 1000n).toString()} µs`
  return `${(Number(d) / 1000.0).toFixed(1)} µs`
}

function protoLabel(summ: WireEvent | undefined): string {
  if (!summ) return 'PKT'
  const p = summ.get('l4_proto')
  if (p === undefined) return 'PKT'
  const n = L4_PROTO_NAMES[p.toString()]
  if (n) return n
  return `L4(${p.toString()})`
}

function formatEndpointAddr(ip: string, port: bigint | undefined, proto: bigint | undefined): string {
  if (ip === '') return ''
  if (port !== undefined && (proto === 6n || proto === 17n)) {
    if (ip.includes(':')) return `[${ip}]:${port.toString()}`
    return `${ip}:${port.toString()}`
  }
  return ip
}

function optStr(v: bigint | undefined): string | null {
  return v !== undefined ? v.toString() : null
}

function primarySummary(s: Session, sg: SampleGraph): WireEvent | undefined {
  if (sg.root_object_ids.length > 0) {
    const r = s.objects.get(sg.root_object_ids[0]!)
    if (r) {
      const init = objectInitialSummary(r)
      if (init) return init
    }
  }
  for (const oid of sg.object_ids) {
    const o = s.objects.get(oid)
    if (!o) continue
    const init = objectInitialSummary(o)
    if (init) return init
  }
  return undefined
}

function primaryBranch(branches: BranchPath[]): BranchPath | undefined {
  if (branches.length === 0) return undefined
  const score = (b: BranchPath): number => {
    let sc = 0
    let isClone = false
    for (const r of b.relation_chain) {
      if (r.rel_type === REL_CLONE || r.rel_type === REL_COPY) {
        isClone = true
        break
      }
    }
    if (!isClone) sc += 1000
    if (
      b.end_reason === END_TX_OK ||
      b.end_reason === END_DROP ||
      b.end_reason === END_SOCK_ENQUEUE ||
      b.end_reason === END_APP_READ
    ) {
      sc += 500
    }
    if (b.visits.length > 0) sc += 200
    sc += b.steps.length
    return sc
  }
  let best = branches[0]!
  let bestScore = score(best)
  for (let i = 1; i < branches.length; i++) {
    const sc = score(branches[i]!)
    if (sc > bestScore) {
      best = branches[i]!
      bestScore = sc
    }
  }
  return best
}

function sampleMaxSojournUs(sg: SampleGraph): number {
  let mx = 0
  for (const br of sg.branches) {
    for (const v of br.visits) {
      if (v.paired && v.sojourn_ns !== undefined) {
        const u = round3(Number(v.sojourn_ns) / 1000.0)
        if (u > mx) mx = u
      }
    }
  }
  return mx
}

function branchMaxSojournUs(br: BranchPath): number {
  let mx = 0
  for (const v of br.visits) {
    if (v.paired && v.sojourn_ns !== undefined) {
      const u = round3(Number(v.sojourn_ns) / 1000.0)
      if (u > mx) mx = u
    }
  }
  return mx
}

function stageName(stage: number): string {
  return STAGE_NAMES[stage] ?? `STAGE_${stage}`
}

function evLabel(lvl: number): string {
  return EVIDENCE_LABELS_ZH[lvl] ?? '直接观测'
}

function formatSummaryBrief(summ: WireEvent | undefined): string {
  if (!summ) return ''
  const p = protoLabel(summ)
  const protoOpt = evOpt(summ, 'l4_proto')
  const sip = summ.str('src_ip') ?? ''
  const dip = summ.str('dst_ip') ?? ''
  const sp = evOpt(summ, 'src_port')
  const dp = evOpt(summ, 'dst_port')
  const pieces: string[] = []
  if (sip !== '' && dip !== '') {
    pieces.push(`${p} ${formatEndpointAddr(sip, sp, protoOpt)} → ${formatEndpointAddr(dip, dp, protoOpt)}`)
  }
  if (protoOpt === 6n) {
    const tseq = summ.get('tcp_seq')
    if (tseq !== undefined) {
      let tend = tseq
      const te = summ.get('tcp_seq_end')
      if (te !== undefined && te !== 0n) tend = te
      pieces.push(`TCP seq ${tseq.toString()}:${tend.toString()}`)
    }
  }
  const plen = summ.get('pkt_len')
  if (plen !== undefined) pieces.push(`len=${plen.toString()}B`)
  return pieces.join('  ')
}

function qdiscStepLabelWithHint(s: Session, st: WireEvent, fallbackKind: string): string {
  const ifidx = st.u('ifindex')
  const qgen = evOpt(st, 'queue_gen')
  const handle = evOpt(st, 'qdisc_handle')
  const parent = evOpt(st, 'qdisc_parent')
  const devGen = evOpt(st, 'dev_gen')
  const qi = s.resolveQdiscInfo(ifidx, qgen, handle, parent, devGen, st.ts_ns)
  const hStr = formatTCHandle(handle)
  let kindStr: string
  if (qi && qi.kind !== '') kindStr = qi.kind.toUpperCase()
  else if (s.isTopoDesyncedAt(st.ts_ns)) kindStr = 'Qdisc(拓扑失步未知)'
  else if (fallbackKind !== '') kindStr = fallbackKind.toUpperCase()
  else {
    const inf = s.inferQdiscKind(st.site_dict_idx)
    kindStr = inf !== '' ? inf.toUpperCase() : 'Qdisc'
  }
  if ((handle === undefined || handle === 0n) && parent !== undefined && isParentTCClass(parent)) {
    let lbl = `${kindStr} @ ${formatTCHandle(parent)}`
    if (qgen !== undefined && qgen > 0n) lbl += ` (gen=${qgen.toString()})`
    return lbl
  }
  const extras: string[] = []
  if (handle === 0n) {
    const txq = st.get('txq')
    if (txq !== undefined) extras.push(`txq=${txq.toString()}`)
  }
  if (qgen !== undefined && qgen > 0n) extras.push(`gen=${qgen.toString()}`)
  if (extras.length > 0) return `${kindStr} ${hStr} (${extras.join(', ')})`
  return `${kindStr} ${hStr}`
}

function visitQueueLabel(s: Session, v: QueueVisit, st: WireEvent): string {
  if (v.visit_kind === 'requeue_gso') return 'gso_skb 重排队列'
  if (v.visit_kind === 'requeue_bad_txq') return 'skb_bad_txq 队列'
  return qdiscStepLabelWithHint(s, st, s.resolveVisitQdiscKind(v))
}

function boundaryMessage(scope: string, br: BranchPath): string {
  if (br.end_reason_name === 'UNKNOWN_TAIL') {
    return '会话异常中断/缺少末尾健康检查点 (UNKNOWN_TAIL)；后续状态不可证'
  }
  switch (br.end_reason) {
    case END_TX_OK:
      return `驱动接手 (NETDEV_TX_OK)；硬件队列/Wi-Fi 固件排队与空口 ACK 位于 ${scope} 软件观测范围之外`
    case END_DROP:
      if (br.drop_reason !== undefined) {
        return `内核协议栈/队列明确丢包 (DROP) (drop_reason=${br.drop_reason.toString()})`
      }
      return '内核协议栈/队列明确丢包 (DROP)'
    case END_CONSUME:
      return '内核正常消费释放 (CONSUME)'
    case END_SOCK_ENQUEUE:
      return '已交付 Socket 接收队列 (SOCK_ENQUEUE)；应用态 recvmsg 读取不在默认边界内'
    case END_APP_READ:
      return '应用态已完成读取 (APP_READ)'
    case END_TIMEOUT_TRUNCATED:
      return '采集窗口到期或 Epoch 切换排空截断 (TIMEOUT_TRUNCATED)'
    case END_CONFLICT_TRUNCATED:
      return '检测到地址身份冲突并隔离截断 (CONFLICT_TRUNCATED)'
    case END_BOUNDARY:
      return `跨出当前已挂载观测边界 (${scope} BOUNDARY)`
    default:
      return '未观测到终点事件 (OPEN_UNFINISHED)'
  }
}

function fillProbeMeta(s: Session, te: TimelineEvent, ev: WireEvent | undefined): void {
  if (!ev) return
  te.event_id = ev.eventId()
  if (ev.cpu !== USERSPACE_CPU) te.cpu = ev.cpu
  te.in_task = (ev.flags & EV_FLAG_IN_TASK) !== 0
  const tid = ev.get('ctx_tid')
  if (tid !== undefined) te.tid = tid.toString()
  const site = s.resolveSite(ev.site_dict_idx)
  if (site) {
    const sym = site.symbol || site.name
    const ptype = site.probe_type || 'probe'
    const pver = site.probe_version || '1.0'
    te.probe_type = ptype
    te.probe_name = `${ptype}:${sym}`
    te.probe_version = pver
    te.adapter_name = s.adapterName(site.adapter_id)
  } else {
    te.probe_name = `site#${ev.site_dict_idx}`
  }
}

function makeEmptyTimelineEvent(partial: Partial<TimelineEvent> & {
  rel_us: number
  ts_ns: string
  evidence_level: number
  evidence_label: string
  stage: string
  title: string
  detail: string
  object_id: string
}): TimelineEvent {
  return {
    stage_code: 0,
    sojourn_us: null,
    cpu: null,
    tid: null,
    in_task: null,
    cross_cpu: false,
    cross_thread: false,
    event_id: '',
    probe_name: '',
    probe_type: '',
    probe_version: '',
    adapter_name: '',
    ...partial,
  }
}

function buildSampleRow(s: Session, sg: SampleGraph): SampleRow {
  const summ = primarySummary(s, sg)
  const row: SampleRow = {
    sample_id: sg.sample_id.toString(),
    uid: optStr(sg.attr.uid),
    tgid: optStr(sg.attr.tgid),
    comm: sg.attr.comm ?? '',
    enqueue_tid: (sg.attr.enqueue_tid ?? 0n).toString(),
    in_task: sg.attr.in_task ?? false,
    proto: protoLabel(summ),
    src: '',
    dst: '',
    src_ip: '',
    dst_ip: '',
    src_port: null,
    dst_port: null,
    tcp_seq: null,
    tcp_seq_end: null,
    pkt_len: '0',
    max_sojourn_us: sampleMaxSojournUs(sg),
    total_us: durUs(sg.first_ts_ns, sg.last_ts_ns),
    complete: sg.complete,
    completeness: sg.completeness,
    gap_reasons: [...sg.gap_reasons],
    endpoint: '',
    branch_count: sg.branches.length,
    requeued: false,
    path_sig: '',
    path_sigs: [],
  }
  if (summ) {
    const protoOpt = evOpt(summ, 'l4_proto')
    const sip = summ.str('src_ip') ?? ''
    const dip = summ.str('dst_ip') ?? ''
    const sp = evOpt(summ, 'src_port')
    const dp = evOpt(summ, 'dst_port')
    row.src_ip = sip
    row.dst_ip = dip
    row.src_port = optStr(sp)
    row.dst_port = optStr(dp)
    row.src = formatEndpointAddr(sip, sp, protoOpt)
    row.dst = formatEndpointAddr(dip, dp, protoOpt)
    row.tcp_seq = optStr(evOpt(summ, 'tcp_seq'))
    row.tcp_seq_end = optStr(evOpt(summ, 'tcp_seq_end'))
    row.pkt_len = summ.u('pkt_len').toString()
  }
  const seenSig = new Set<string>()
  for (const br of sg.branches) {
    if (br.requeue_count > 0) row.requeued = true
    const sig = branchPathSignature(s, br)
    if (!seenSig.has(sig)) {
      seenSig.add(sig)
      row.path_sigs.push(sig)
    }
  }
  const pb = primaryBranch(sg.branches)
  if (pb) {
    row.endpoint = pb.end_reason_name
    const primarySig = branchPathSignature(s, pb)
    const ordered = [primarySig]
    for (const sig of row.path_sigs) {
      if (sig !== primarySig) ordered.push(sig)
    }
    row.path_sigs = ordered
    row.path_sig = ordered.join(' || ')
  }
  return row
}

function buildSampleSummary(s: Session, sg: SampleGraph, baseNs: bigint): SampleSummary {
  const rootObj = s.objects.get(sg.root_object_ids[0]!)
  const initSum = primarySummary(s, sg)
  const firstStep = rootObj && rootObj.steps.length > 0 ? rootObj.steps[0] : undefined

  let ifidx = 0n
  if (initSum && initSum.u('ifindex') !== 0n) ifidx = initSum.u('ifindex')
  else if (firstStep) ifidx = firstStep.u('ifindex')

  let dirVal = DIR_TX
  if (initSum && initSum.has('dir')) dirVal = initSum.num('dir')
  else if (firstStep && firstStep.has('dir')) dirVal = firstStep.num('dir')

  const devName = s.resolveDevName(ifidx)
  const dirLbl = DIR_LABELS_ZH[dirVal] ?? 'TX'

  const sm: SampleSummary = {
    sample_id: sg.sample_id.toString(),
    uid: optStr(sg.attr.uid),
    tgid: optStr(sg.attr.tgid),
    comm: sg.attr.comm ?? '',
    enqueue_tid: (sg.attr.enqueue_tid ?? 0n).toString(),
    proto: protoLabel(initSum),
    src: '',
    dst: '',
    tcp_seq: null,
    pkt_len: '0',
    max_sojourn_us: sampleMaxSojournUs(sg),
    total_us: durUs(sg.first_ts_ns, sg.last_ts_ns),
    complete: sg.complete,
    completeness: sg.completeness,
    endpoint: '',
    branch_count: sg.branches.length,
    requeued: false,
    path_sig: '',
    dev_name: devName,
    dir_label: dirLbl,
    gap_reasons: [...sg.gap_reasons],
  }
  if (sg.attr.xmit_tid !== undefined) sm.xmit_tid = sg.attr.xmit_tid.toString()
  if (sg.attr.skb_create_ts !== undefined) sm.skb_create_rel_us = relUs(sg.attr.skb_create_ts, baseNs)
  if (sg.attr.plugin_vals && sg.attr.plugin_vals.size > 0) {
    const labels = new Map<number, string>()
    const pfs = s.dict['plugin_fields']
    if (Array.isArray(pfs)) {
      for (const raw of pfs) {
        if (typeof raw === 'object' && raw !== null && !Array.isArray(raw)) {
          const m = raw as Record<string, unknown>
          const slot = asInt(m['slot'])
          if (slot !== undefined) {
            const lbl = jstr(m['label'])
            if (lbl !== '') labels.set(slot, lbl)
          }
        }
      }
    }
    const tags: Record<string, string> = {}
    for (const [slot, val] of sg.attr.plugin_vals.entries()) {
      const lbl = labels.get(slot) || `ext${slot}`
      tags[lbl] = val.toString()
    }
    sm.plugin_tags = tags
  }
  if (initSum) {
    const protoOpt = evOpt(initSum, 'l4_proto')
    const sip = initSum.str('src_ip') ?? ''
    const dip = initSum.str('dst_ip') ?? ''
    const sp = evOpt(initSum, 'src_port')
    const dp = evOpt(initSum, 'dst_port')
    sm.src = formatEndpointAddr(sip, sp, protoOpt)
    sm.dst = formatEndpointAddr(dip, dp, protoOpt)
    sm.tcp_seq = optStr(evOpt(initSum, 'tcp_seq'))
    const te = evOpt(initSum, 'tcp_seq_end')
    if (te !== undefined) sm.tcp_seq_end = te.toString()
    sm.pkt_len = initSum.u('pkt_len').toString()
    const ll = evOpt(initSum, 'linear_len')
    if (ll !== undefined) sm.linear_len = ll.toString()
    const sh = evOpt(initSum, 'skb_hash')
    if (sh !== undefined) sm.skb_hash = sh.toString()
    const mk = evOpt(initSum, 'skb_mark')
    if (mk !== undefined) sm.skb_mark = mk.toString()
    const pr = evOpt(initSum, 'skb_priority')
    if (pr !== undefined) sm.skb_priority = pr.toString()
  }
  for (const br of sg.branches) {
    if (br.requeue_count > 0) sm.requeued = true
  }
  const pb = primaryBranch(sg.branches)
  if (pb) {
    sm.endpoint = pb.end_reason_name
    sm.path_sig = branchPathSignature(s, pb)
  }

  const uidStr = sm.uid !== null ? `UID ${sm.uid}` : 'UID unknown'
  let owner = uidStr
  if (sm.tgid !== null || sm.comm !== '') {
    const tg = sm.tgid !== null ? sm.tgid : '?'
    const cm = sm.comm !== '' ? sm.comm : '?'
    owner = `${uidStr} (pid ${tg}/${cm})`
  }
  const flow = formatSummaryBrief(initSum)
  sm.headline = `样本 ${sg.sample_id.toString()}  ${dirLbl} → ${devName}  ${owner}  ${flow}`.trim()
  return sm
}

function buildBranchDetail(s: Session, sg: SampleGraph, br: BranchPath, baseNs: bigint): BranchDetail {
  const scope = manifestStr(s.manifest, 'scope', 'tc-egress')
  let relDesc = '主路径'
  if (br.relation_chain.length > 0) {
    relDesc = br.relation_chain
      .map((r) => `${r.rel_type_name}(#${r.src_object_id.toString()}→#${r.dst_object_id.toString()})`)
      .join(' / ')
  }
  const bd: BranchDetail = {
    branch_id: br.branch_id,
    branch_index: br.branch_index,
    label: relDesc,
    path_sig: branchPathSignature(s, br),
    complete: br.complete,
    completeness: br.completeness,
    gap_reasons: [...br.gap_reasons],
    endpoint: br.end_reason_name,
    end_reason: br.end_reason,
    drop_reason: optStr(br.drop_reason),
    boundary_note: boundaryMessage(scope, br),
    object_chain: br.object_ids.map((id) => id.toString()),
    requeue_count: br.requeue_count,
    start_rel_us: relUs(br.start_ts_ns, baseNs),
    end_rel_us: relUs(br.end_ts_ns, baseNs),
    total_us: durUs(br.start_ts_ns, br.end_ts_ns),
    max_sojourn_us: branchMaxSojournUs(br),
    timeline: [],
  }

  const addEv = (te: TimelineEvent): void => {
    bd.timeline.push(te)
  }

  if (br.branch_index === 1 && sg.attr.skb_create_ts !== undefined && baseNs >= sg.attr.skb_create_ts) {
    const cts = sg.attr.skb_create_ts
    const pre = fmtDurUsText(baseNs - cts)
    addEv(
      makeEmptyTimelineEvent({
        rel_us: relUs(cts, baseNs),
        ts_ns: cts.toString(),
        evidence_level: EVIDENCE_DIRECT,
        evidence_label: evLabel(EVIDENCE_DIRECT),
        stage: 'SOCK_CREATE_TS',
        title: 'Socket 发包创建',
        detail: `skb_create_ts 距协议栈入口 ${pre}`,
        tid: optStr(sg.attr.enqueue_tid),
        object_id: br.object_ids[0]!.toString(),
      }),
    )
  }

  const visitByEntry = new Map<string, QueueVisit>()
  const visitByExit = new Map<string, QueueVisit>()
  for (const v of br.visits) {
    if (v.entry) visitByEntry.set(v.entry.eventId(), v)
    if (v.exit) visitByExit.set(v.exit.eventId(), v)
  }

  for (const rel of br.relation_chain) {
    let extra = ''
    if (rel.stream_offset !== undefined || rel.span_len !== undefined) {
      extra = ` (stream_offset=${(rel.stream_offset ?? 0n).toString()}, span_len=${(rel.span_len ?? 0n).toString()})`
    }
    const te = makeEmptyTimelineEvent({
      rel_us: relUs(rel.ts_ns, baseNs),
      ts_ns: rel.ts_ns.toString(),
      evidence_level: rel.event.evidence_level,
      evidence_label: evLabel(rel.event.evidence_level),
      stage: 'RELATION',
      title: `对象派生/交接 (${rel.rel_type_name})`,
      detail: `${rel.rel_type_name} #${rel.src_object_id.toString()} → #${rel.dst_object_id.toString()}${extra}`,
      object_id: rel.dst_object_id.toString(),
    })
    fillProbeMeta(s, te, rel.event)
    addEv(te)
    if (rel.unknown_predecessors) {
      addEv(
        makeEmptyTimelineEvent({
          rel_us: relUs(rel.ts_ns, baseNs),
          ts_ns: rel.ts_ns.toString(),
          evidence_level: EVIDENCE_GAP,
          evidence_label: evLabel(EVIDENCE_GAP),
          stage: 'GAP',
          title: '合并前驱缺失',
          detail: '存在未追踪到的输入前驱 (UNKNOWN_PREDECESSORS)',
          object_id: rel.dst_object_id.toString(),
        }),
      )
    }
    if (rel.successor_truncated) {
      addEv(
        makeEmptyTimelineEvent({
          rel_us: relUs(rel.ts_ns, baseNs),
          ts_ns: rel.ts_ns.toString(),
          evidence_level: EVIDENCE_GAP,
          evidence_label: evLabel(EVIDENCE_GAP),
          stage: 'GAP',
          title: '分段遍历截断',
          detail: '超出最大遍历步长，部分后继段未追踪 (SUCCESSOR_TRUNCATED)',
          object_id: rel.dst_object_id.toString(),
        }),
      )
    }
  }

  for (const oid of br.object_ids) {
    const on = s.objects.get(oid)
    if (on && on.incoming.length > 1) {
      const preds = on.incoming.map((r) => `#${r.src_object_id.toString()}`)
      addEv(
        makeEmptyTimelineEvent({
          rel_us: relUs(on.first_ts_ns, baseNs),
          ts_ns: on.first_ts_ns.toString(),
          evidence_level: EVIDENCE_DIRECT,
          evidence_label: evLabel(EVIDENCE_DIRECT),
          stage: 'MERGE',
          title: '多前驱合并',
          detail: `对象 #${oid.toString()} 汇聚自前驱 [${preds.join(', ')}]`,
          object_id: oid.toString(),
        }),
      )
    }
  }

  const rewrites = br.summaries.length > 1 ? br.summaries.slice(1) : []
  let rwIdx = 0
  const emitRewrite = (rws: WireEvent): void => {
    const te = makeEmptyTimelineEvent({
      rel_us: relUs(rws.ts_ns, baseNs),
      ts_ns: rws.ts_ns.toString(),
      evidence_level: rws.evidence_level,
      evidence_label: evLabel(rws.evidence_level),
      stage: 'SUMMARY_REWRITE',
      title: '原地包头改写',
      detail: `object_id=#${rws.object_id.toString()}  ${formatSummaryBrief(rws)}`,
      object_id: rws.object_id.toString(),
    })
    fillProbeMeta(s, te, rws)
    addEv(te)
  }

  let lastClassID = 0n
  const emitClassStep = (ev: WireEvent, cid: bigint, direct: boolean): void => {
    const cStr = formatTCHandle(cid)
    const ci = s.resolveClassInfo(ev.u('ifindex'), cid, evOpt(ev, 'dev_gen'), ev.ts_ns)
    const lvl = direct ? (ev.evidence_level === 0 ? EVIDENCE_DIRECT : ev.evidence_level) : EVIDENCE_CONTRACT_DERIVED
    const detailParts: string[] = []
    const sum = formatClassSummary(ci)
    if (sum !== '') detailParts.push(sum)
    if (direct) {
      const rc = ev.i('raw_ret')
      if (rc !== undefined) detailParts.push(`tcf_classify verdict=${rc}`)
      else detailParts.push(`TC 过滤器直接命中子类 ${cStr}`)
    } else {
      detailParts.push(`由下级队列 parent=${cStr} 推导归属子类`)
    }
    const te = makeEmptyTimelineEvent({
      rel_us: relUs(ev.ts_ns, baseNs),
      ts_ns: ev.ts_ns.toString(),
      evidence_level: lvl,
      evidence_label: evLabel(lvl),
      stage: 'CLASSIFY',
      stage_code: STAGE_CLASSIFY,
      title: `TC 规则命中子类 CLASS ${cStr}`,
      detail: detailParts.join(' · '),
      object_id: ev.object_id.toString(),
      qdisc_handle: cStr,
    })
    fillProbeMeta(s, te, ev)
    addEv(te)
    lastClassID = cid
  }

  const steps = br.steps
  for (let i = 0; i < steps.length; ) {
    const st = steps[i]!
    while (rwIdx < rewrites.length && rewrites[rwIdx]!.ts_ns <= st.ts_ns) {
      emitRewrite(rewrites[rwIdx]!)
      rwIdx++
    }
    const stage = st.num('stage')
    const dev = s.resolveDevName(st.u('ifindex'), evOpt(st, 'dev_gen'), evOpt(st, 'netns_inum'))

    if (stage === STAGE_CLASSIFY && st.u('qdisc_handle') === 0n && st.u('classid') !== 0n) {
      emitClassStep(st, st.u('classid'), true)
      i++
      continue
    }

    if (stage === STAGE_CLASSIFY || (stage === STAGE_QDISC_ENQ && st.u('visit_id') === 0n)) {
      const cid = st.u('classid')
      if (cid !== 0n && cid !== lastClassID) emitClassStep(st, cid, false)
      const chain: WireEvent[] = [st]
      let j = i + 1
      while (j < steps.length) {
        const nx = steps[j]!
        const ns = nx.num('stage')
        if (nx.object_id === st.object_id && (ns === STAGE_CLASSIFY || (ns === STAGE_QDISC_ENQ && nx.u('visit_id') === 0n))) {
          if (ns === STAGE_CLASSIFY && nx.u('qdisc_handle') === 0n && nx.u('classid') !== 0n) break
          const ncid = nx.u('classid')
          if (ncid !== 0n && ncid !== lastClassID) break
          chain.push(nx)
          j++
        } else {
          break
        }
      }
      const lbls = chain.map((e) => qdiscStepLabelWithHint(s, e, ''))
      const eids = chain.map((e) => e.eventId())
      const te = makeEmptyTimelineEvent({
        rel_us: relUs(st.ts_ns, baseNs),
        ts_ns: st.ts_ns.toString(),
        evidence_level: st.evidence_level,
        evidence_label: evLabel(st.evidence_level),
        stage: 'CLASSIFY',
        stage_code: stage,
        title: lbls.join(' → '),
        detail: '实读各级 Qdisc 分类层级 handle/parent',
        object_id: st.object_id.toString(),
        qdisc_handle: formatTCHandle(evOpt(st, 'qdisc_handle')),
      })
      fillProbeMeta(s, te, st)
      te.event_id = eids.join(',')
      addEv(te)
      i = j
      continue
    }

    if (stage === STAGE_ENTRY) {
      let tid = st.u('ctx_tid')
      if (!st.has('ctx_tid') && sg.attr.enqueue_tid !== undefined) tid = sg.attr.enqueue_tid
      const inTask = (st.flags & EV_FLAG_IN_TASK) !== 0
      const ctxTag = inTask && tid !== 0n ? 'in_task' : 'softirq'
      const te = makeEmptyTimelineEvent({
        rel_us: relUs(st.ts_ns, baseNs),
        ts_ns: st.ts_ns.toString(),
        evidence_level: st.evidence_level,
        evidence_label: evLabel(st.evidence_level),
        stage: 'ENTRY',
        stage_code: stage,
        title: `入口准入 (${dev})`,
        detail: `dev=${dev}, object_id=#${st.object_id.toString()}, enqueue_tid=${tid.toString()} (${ctxTag})`,
        object_id: st.object_id.toString(),
      })
      fillProbeMeta(s, te, st)
      te.tid = tid.toString()
      addEv(te)
      i++
      continue
    }

    const vEntry = visitByEntry.get(st.eventId())
    if (vEntry) {
      const cid = st.u('classid')
      if (cid !== 0n && cid !== lastClassID) emitClassStep(st, cid, false)
      else if (cid === 0n && vEntry.qdisc_handle === 0n && isParentTCClass(vEntry.qdisc_parent) && vEntry.qdisc_parent !== lastClassID) {
        emitClassStep(st, vEntry.qdisc_parent, false)
      }
      const qlbl = visitQueueLabel(s, vEntry, st)
      const act = vEntry.visit_kind !== 'qdisc' ? '重新排队入队' : '接收入队'
      let note = ''
      if (vEntry.enq_dropped) note = ' -> 入队即丢弃 (NET_XMIT_DROP)'
      else if (vEntry.enq_cn) note = ' [NET_XMIT_CN 拥塞提示]'
      if (isParentTCClass(vEntry.qdisc_parent)) {
        const ci = s.resolveClassInfo(vEntry.ifindex, vEntry.qdisc_parent, vEntry.dev_gen, st.ts_ns)
        const sum = formatClassSummary(ci)
        if (sum !== '') note += ` · ${sum}`
      }
      const te = makeEmptyTimelineEvent({
        rel_us: relUs(st.ts_ns, baseNs),
        ts_ns: st.ts_ns.toString(),
        evidence_level: st.evidence_level,
        evidence_label: evLabel(st.evidence_level),
        stage: stageName(stage),
        stage_code: stage,
        title: `${qlbl} ${act}`,
        detail: `visit #${vEntry.visit_id.toString()} 开始${note}`,
        object_id: st.object_id.toString(),
        visit_id: vEntry.visit_id.toString(),
        qdisc_handle: formatTCHandle(vEntry.qdisc_handle),
        ...(vEntry.txq !== undefined ? { txq: vEntry.txq.toString() } : {}),
      })
      fillProbeMeta(s, te, st)
      if (te.tid === null && sg.attr.enqueue_tid !== undefined) te.tid = sg.attr.enqueue_tid.toString()
      addEv(te)
      if (!vEntry.paired && !vEntry.enq_dropped) {
        addEv(
          makeEmptyTimelineEvent({
            rel_us: relUs(st.ts_ns, baseNs),
            ts_ns: st.ts_ns.toString(),
            evidence_level: EVIDENCE_GAP,
            evidence_label: evLabel(EVIDENCE_GAP),
            stage: 'GAP',
            title: '队列访问未闭合',
            detail: `visit #${vEntry.visit_id.toString()} 缺少匹配出队/丢弃事件，不计算伪驻留时间`,
            object_id: st.object_id.toString(),
            visit_id: vEntry.visit_id.toString(),
          }),
        )
      }
      i++
      continue
    }

    const vExit = visitByExit.get(st.eventId())
    if (vExit) {
      const qlbl = visitQueueLabel(s, vExit, st)
      const sojVal = vExit.sojourn_ns !== undefined ? round3(Number(vExit.sojourn_ns) / 1000.0) : null
      let lvl = st.evidence_level
      let title: string
      let detail: string
      if (stage === STAGE_DROP) {
        title = `${qlbl} 队列内淘汰丢弃`
        const sojTxt = vExit.sojourn_ns !== undefined ? `，丢弃前停留 ${fmtDurUsText(vExit.sojourn_ns)}` : ''
        detail = `visit #${vExit.visit_id.toString()} 闭合${sojTxt}`
      } else if (vExit.sojourn_ns !== undefined) {
        title = `${qlbl} 出队`
        const xth = vExit.cross_thread_dequeue ? '，由另一线程出队' : ''
        detail = `本次停留 ${fmtDurUsText(vExit.sojourn_ns)} (visit #${vExit.visit_id.toString()} 闭合${xth})`
      } else {
        lvl = EVIDENCE_GAP
        title = `${qlbl} 出队 (未配对)`
        detail = `visit #${vExit.visit_id.toString()} 缺少唯一入队，不计算驻留`
      }
      const te = makeEmptyTimelineEvent({
        rel_us: relUs(st.ts_ns, baseNs),
        ts_ns: st.ts_ns.toString(),
        evidence_level: lvl,
        evidence_label: evLabel(lvl),
        stage: stageName(stage),
        stage_code: stage,
        title,
        detail,
        sojourn_us: sojVal,
        cross_thread: vExit.cross_thread_dequeue,
        object_id: st.object_id.toString(),
        visit_id: vExit.visit_id.toString(),
        qdisc_handle: formatTCHandle(vExit.qdisc_handle),
        ...(vExit.txq !== undefined ? { txq: vExit.txq.toString() } : {}),
      })
      fillProbeMeta(s, te, st)
      if (vExit.entry) {
        if (vExit.entry.cpu !== USERSPACE_CPU) {
          te.enqueue_cpu = vExit.entry.cpu
          if (te.cpu !== null && te.cpu !== vExit.entry.cpu) te.cross_cpu = true
        }
        const et = vExit.entry.get('ctx_tid')
        if (et !== undefined) te.enqueue_tid = et.toString()
        else if (sg.attr.enqueue_tid !== undefined) te.enqueue_tid = sg.attr.enqueue_tid.toString()
      }
      addEv(te)
      i++
      continue
    }

    switch (stage) {
      case STAGE_QDISC_ENQ_RET: {
        const rc = st.i('raw_ret')
        if (rc !== undefined && rc !== 0) {
          const te = makeEmptyTimelineEvent({
            rel_us: relUs(st.ts_ns, baseNs),
            ts_ns: st.ts_ns.toString(),
            evidence_level: st.evidence_level,
            evidence_label: evLabel(st.evidence_level),
            stage: 'QDISC_ENQ_RET',
            stage_code: stage,
            title: '入队返回',
            detail: `call_id=${st.u('call_id').toString()}, rc=${rc}`,
            object_id: st.object_id.toString(),
          })
          fillProbeMeta(s, te, st)
          addEv(te)
        }
        break
      }
      case STAGE_BYPASS_DIRECT: {
        const te = makeEmptyTimelineEvent({
          rel_us: relUs(st.ts_ns, baseNs),
          ts_ns: st.ts_ns.toString(),
          evidence_level: st.evidence_level,
          evidence_label: evLabel(st.evidence_level),
          stage: 'BYPASS_DIRECT',
          stage_code: stage,
          title: `直接旁路发送 (${dev})`,
          detail: `${dev} sch_direct_xmit (空队列旁路，0 队列驻留)`,
          object_id: st.object_id.toString(),
        })
        fillProbeMeta(s, te, st)
        addEv(te)
        break
      }
      case STAGE_HANDOFF_LAYER: {
        const te = makeEmptyTimelineEvent({
          rel_us: relUs(st.ts_ns, baseNs),
          ts_ns: st.ts_ns.toString(),
          evidence_level: st.evidence_level,
          evidence_label: evLabel(st.evidence_level),
          stage: 'HANDOFF_LAYER',
          stage_code: stage,
          title: `跨层/设备交接 (${dev})`,
          detail: `${dev} (合法延续 object_id=#${st.object_id.toString()})`,
          object_id: st.object_id.toString(),
        })
        fillProbeMeta(s, te, st)
        addEv(te)
        break
      }
      case STAGE_XMIT_START: {
        const txq = st.u('txq')
        const xtid = st.u('ctx_tid')
        let pairedRet: WireEvent | undefined
        if (st.u('call_id') !== 0n) {
          for (const cp of br.calls) {
            if (cp.entry === st && cp.ret) {
              pairedRet = cp.ret
              break
            }
          }
        }
        let detail: string
        if (pairedRet) {
          const rc = pairedRet.i('raw_ret')
          const rcStr = rc !== undefined && rc !== 0 ? `NETDEV_TX_BUSY/rc=${rc}` : 'NETDEV_TX_OK, 驱动接受'
          detail = `${fmtRelUsText(pairedRet.ts_ns, baseNs)} 返回 (${rcStr}, xmit_tid=${xtid.toString()})`
        } else {
          detail = `ndo_start_xmit (xmit_tid=${xtid.toString()})`
        }
        const te = makeEmptyTimelineEvent({
          rel_us: relUs(st.ts_ns, baseNs),
          ts_ns: st.ts_ns.toString(),
          evidence_level: st.evidence_level,
          evidence_label: evLabel(st.evidence_level),
          stage: 'XMIT_START',
          stage_code: stage,
          title: `TX queue ${txq.toString()} 提交驱动 (${dev})`,
          detail,
          object_id: st.object_id.toString(),
          txq: txq.toString(),
        })
        fillProbeMeta(s, te, st)
        addEv(te)
        break
      }
      case STAGE_XMIT_RET: {
        let shown = false
        for (const cp of br.calls) {
          if (cp.ret === st && steps.includes(cp.entry!)) {
            shown = true
            break
          }
        }
        if (!shown) {
          const rc = st.i('raw_ret')
          const rcStr = rc !== undefined && rc !== 0 ? `NETDEV_TX_BUSY/rc=${rc}` : 'NETDEV_TX_OK'
          const te = makeEmptyTimelineEvent({
            rel_us: relUs(st.ts_ns, baseNs),
            ts_ns: st.ts_ns.toString(),
            evidence_level: st.evidence_level,
            evidence_label: evLabel(st.evidence_level),
            stage: 'XMIT_RET',
            stage_code: stage,
            title: '驱动发送返回',
            detail: `${rcStr} (call_id=${st.u('call_id').toString()})`,
            object_id: st.object_id.toString(),
          })
          fillProbeMeta(s, te, st)
          addEv(te)
        }
        break
      }
      default: {
        const sname = stageName(stage)
        const te = makeEmptyTimelineEvent({
          rel_us: relUs(st.ts_ns, baseNs),
          ts_ns: st.ts_ns.toString(),
          evidence_level: st.evidence_level,
          evidence_label: evLabel(st.evidence_level),
          stage: sname,
          stage_code: stage,
          title: sname,
          detail: `dev=${dev}, object_id=#${st.object_id.toString()}`,
          object_id: st.object_id.toString(),
        })
        fillProbeMeta(s, te, st)
        addEv(te)
      }
    }
    i++
  }

  while (rwIdx < rewrites.length) {
    emitRewrite(rewrites[rwIdx]!)
    rwIdx++
  }

  for (const cand of br.tcpdump) {
    addEv(
      makeEmptyTimelineEvent({
        rel_us: relUs(cand.est_boottime_ns, baseNs),
        ts_ns: cand.est_boottime_ns.toString(),
        evidence_level: EVIDENCE_ANNOTATION,
        evidence_label: evLabel(EVIDENCE_ANNOTATION),
        stage: 'TCPDUMP_CANDIDATE',
        title: `外部抓包候选 #${cand.frame_index} (${cand.match_kind})`,
        detail: `len=${cand.orig_len}B, Δt=${(Number(cand.delta_from_xmit_ns) / 1000.0).toFixed(1)} µs (±${fmtDurUsText(cand.clock_err_ns < 0n ? 0n : cand.clock_err_ns)}) — ${cand.note}`,
        object_id: branchLeafObjectId(br).toString(),
      }),
    )
  }

  for (const g of br.gap_reasons) {
    if (g === 'UNCLOSED_VISIT') continue
    addEv(
      makeEmptyTimelineEvent({
        rel_us: relUs(br.end_ts_ns, baseNs),
        ts_ns: br.end_ts_ns.toString(),
        evidence_level: EVIDENCE_GAP,
        evidence_label: evLabel(EVIDENCE_GAP),
        stage: 'GAP',
        title: `完整性缺口 (${g})`,
        detail: `受影响支路标记为 ${br.completeness}: ${g}`,
        object_id: branchLeafObjectId(br).toString(),
      }),
    )
  }

  addEv(
    makeEmptyTimelineEvent({
      rel_us: relUs(br.end_ts_ns, baseNs),
      ts_ns: br.end_ts_ns.toString(),
      evidence_level: EVIDENCE_CONTRACT_DERIVED,
      evidence_label: evLabel(EVIDENCE_CONTRACT_DERIVED),
      stage: 'BOUNDARY',
      title: `本次观测终点 (${br.end_reason_name})`,
      detail: bd.boundary_note,
      object_id: branchLeafObjectId(br).toString(),
    }),
  )

  return bd
}

export function buildOverview(s: Session): SessionOverview {
  const stats = computeStats(s, 'path')
  const samples = s.sample_order.map((sid) => buildSampleRow(s, s.samples.get(sid)!))
  return {
    manifest: s.manifest,
    dict: s.dict,
    stats,
    samples,
  }
}

export function buildSampleDetail(s: Session, sampleId: bigint): SampleDetail {
  const sg = s.samples.get(sampleId)
  if (!sg) throw new Error(`sample ${sampleId.toString()} not found`)
  const baseNs = sg.first_ts_ns
  const summary = buildSampleSummary(s, sg, baseNs)

  const branches: BranchDetail[] = []
  const qstateSeen = new Set<QStateAnnotation>()
  const qstates: QStateSpan[] = []

  for (const br of sg.branches) {
    branches.push(buildBranchDetail(s, sg, br, baseNs))
    for (const qs of br.qstates) {
      if (!qstateSeen.has(qs)) {
        qstateSeen.add(qs)
        qstates.push({
          ifindex: qs.ifindex.toString(),
          dev_name: s.resolveDevName(qs.ifindex),
          txq: qs.txq.toString(),
          queue_gen: qs.queue_gen.toString(),
          state_op: qs.state_name,
          state_op_code: qs.state_op,
          start_rel_us: relUs(qs.start_ns, baseNs),
          end_rel_us: qs.end_ns !== undefined ? relUs(qs.end_ns, baseNs) : null,
          start_ns: qs.start_ns.toString(),
          end_ns: qs.end_ns !== undefined ? qs.end_ns.toString() : null,
          open: qs.end_ns === undefined,
          value: qs.value.toString(),
        })
      }
    }
  }

  const relations: RelationEdge[] = sg.relations.map((r) => {
    const edge: RelationEdge = {
      op_id: r.op_id.toString(),
      rel_type: r.rel_type_name,
      rel_type_code: r.rel_type,
      src_object_id: r.src_object_id.toString(),
      dst_object_id: r.dst_object_id.toString(),
      rel_us: relUs(r.ts_ns, baseNs),
      ts_ns: r.ts_ns.toString(),
      successor_truncated: r.successor_truncated,
      unknown_predecessors: r.unknown_predecessors,
    }
    if (r.stream_offset !== undefined) edge.stream_offset = r.stream_offset.toString()
    if (r.span_len !== undefined) edge.span_len = r.span_len.toString()
    return edge
  })

  return {
    sample_id: sampleId.toString(),
    summary,
    branches,
    relations,
    qstates,
  }
}
