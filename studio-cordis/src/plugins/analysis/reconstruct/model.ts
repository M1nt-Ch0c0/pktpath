// Pure TypeScript port of studio/pkg/reconstruct/model.go + reconstruct.go (erasableSyntaxOnly).

import {
  END_CONFLICT_TRUNCATED,
  END_CONSUME,
  END_DROP,
  END_OPEN,
  END_REASON_NAMES,
  END_SOCK_ENQUEUE,
  END_TIMEOUT_TRUNCATED,
  END_TX_OK,
  EV_FLAG_IN_TASK,
  EV_FLAG_PARTIAL_COVERAGE,
  EVIDENCE_GAP,
  KIND_OBJECT,
  KIND_QSTATE,
  KIND_QUALITY,
  KIND_RELATION,
  KIND_STEP,
  KIND_SUMMARY,
  OBJ_APP_MSG,
  OBJ_SKB,
  QSTATE_OP_NAMES,
  QSTATE_TXQ_STOP,
  QSTATE_TXQ_WAKE,
  QUAL_IDENTITY_CONFLICT,
  QUAL_KIND_NAMES,
  QUAL_MISSED_DELTA,
  QUAL_RB_DROP_DELTA,
  QUAL_RET_UNMATCHED,
  QUAL_RING_EVICTED_PREFIX,
  QUAL_TOPO_DESYNC,
  REL_CLONE,
  REL_COPY,
  REL_FLAG_SUCCESSOR_TRUNCATED,
  REL_FLAG_UNKNOWN_PREDECESSORS,
  REL_SPAN_MAP,
  REL_TYPE_NAMES,
  STAGE_BYPASS_DIRECT,
  STAGE_CLASSIFY,
  STAGE_CONSUME,
  STAGE_DELIVER_SOCK,
  STAGE_DROP,
  STAGE_ENTRY,
  STAGE_HANDOFF_LAYER,
  STAGE_NAMES,
  STAGE_QDISC_DEQ,
  STAGE_QDISC_ENQ,
  STAGE_QDISC_ENQ_RET,
  STAGE_REQUEUE_BAD_TXQ,
  STAGE_REQUEUE_GSO,
  STAGE_XMIT_RET,
  STAGE_XMIT_START,
} from '../wire/consts.ts'
import { isUncleanTail, loadSession, truthy } from '../wire/wire.ts'
import type { LoadedSession, UnknownTlv, WireEvent } from '../wire/wire.ts'
import {
  evOpt,
  inferQdiscKindFromSite,
  isParentTCClass,
  jstr,
  mergeManifestSites,
  parseCalibrations,
  parseSites,
  parseTopology,
  resolveDevInfoFromTopo,
  resolveDevLinktypeFromTopo,
} from './topo.ts'
import type { Calibration, ClassInfo, QdiscInfo, Site, TopoEpoch } from './topo.ts'
import { matchBranchPackets } from './tcpdump.ts'
import type { PcapPacket, TcpdumpCandidate } from './tcpdump.ts'

export const NETDEV_TX_OK = 0x00n
export const NETDEV_TX_BUSY = 0x10n

export const NET_XMIT_SUCCESS = 0x00n
export const NET_XMIT_DROP = 0x01n
export const NET_XMIT_CN = 0x02n

export interface SeqGap {
  producer_type: number
  cpu: number
  prev_seq: bigint
  next_seq: bigint
  missing_count: bigint
  win_start_ns: bigint
  win_end_ns: bigint
  prev_object_id: bigint
  next_object_id: bigint
}

export interface CallPair {
  call_id: bigint
  object_id: bigint
  entry?: WireEvent
  ret?: WireEvent
  paired: boolean
  ambiguous: boolean
  raw_ret?: bigint
  cross_cpu_late: boolean
}

export interface QStateAnnotation {
  ifindex: bigint
  txq: bigint
  queue_gen: bigint
  state_op: number
  state_name: string
  start_ns: bigint
  end_ns?: bigint
  value: bigint
  event_ids: string[]
}

export interface QueueVisit {
  object_id: bigint
  queue_gen: bigint
  visit_id: bigint
  visit_kind: string // qdisc | requeue_gso | requeue_bad_txq
  netns_inum: bigint
  ifindex: bigint
  dev_gen: bigint
  qdisc_handle: bigint
  qdisc_parent: bigint
  classid: bigint
  bucket?: bigint
  txq?: bigint
  entry?: WireEvent
  enq_ret?: WireEvent
  exit?: WireEvent
  paired: boolean
  ambiguous: boolean
  enq_dropped: boolean
  enq_cn: boolean
  enq_ret_code?: bigint
  sojourn_ns?: bigint
  cross_thread_dequeue: boolean
  backpressure: QStateAnnotation[]
}

export interface Relation {
  event: WireEvent
  op_id: bigint
  rel_type: number
  rel_type_name: string
  src_object_id: bigint
  dst_object_id: bigint
  rel_flags: bigint
  successor_truncated: boolean
  unknown_predecessors: boolean
  stream_offset?: bigint
  span_len?: bigint
  ts_ns: bigint
}

export interface Attribution {
  uid?: bigint
  tgid?: bigint
  comm?: string
  enqueue_tid?: bigint
  skb_create_ts?: bigint
  plugin_vals?: Map<number, bigint>
  in_task?: boolean
  xmit_tid?: bigint
  xmit_in_task?: boolean
}

function mergeAttributionMissing(a: Attribution, o: Attribution): void {
  if (a.uid === undefined) a.uid = o.uid
  if (a.tgid === undefined) a.tgid = o.tgid
  if (a.comm === undefined) a.comm = o.comm
  if (a.enqueue_tid === undefined) a.enqueue_tid = o.enqueue_tid
  if (a.skb_create_ts === undefined) a.skb_create_ts = o.skb_create_ts
  if (o.plugin_vals && o.plugin_vals.size > 0) {
    if (!a.plugin_vals) a.plugin_vals = new Map<number, bigint>()
    for (const [slot, val] of o.plugin_vals) {
      if (!a.plugin_vals.has(slot)) a.plugin_vals.set(slot, val)
    }
  }
  if (a.in_task === undefined) a.in_task = o.in_task
  if (a.xmit_tid === undefined) a.xmit_tid = o.xmit_tid
  if (a.xmit_in_task === undefined) a.xmit_in_task = o.xmit_in_task
}

export interface ObjectNode {
  object_id: bigint
  object_type: number
  sample_ids: Set<bigint>
  primary_sample_id: bigint
  object_events: WireEvent[]
  steps: WireEvent[]
  summaries: WireEvent[]
  visits: QueueVisit[]
  calls: CallPair[]
  outgoing: Relation[]
  incoming: Relation[]
  explicit_end_reason: number
  effective_end_reason: number
  drop_reason?: bigint
  unknown_must: UnknownTlv[]
  unknown_optional: UnknownTlv[]
  successor_truncated: boolean
  unknown_predecessors: boolean
  identity_conflict: boolean
  attr: Attribution
  first_ts_ns: bigint
  last_ts_ns: bigint
}

export function objectInitialSummary(o: ObjectNode): WireEvent | undefined {
  return o.summaries.length > 0 ? o.summaries[0] : undefined
}

export function objectLatestSummary(o: ObjectNode): WireEvent | undefined {
  return o.summaries.length > 0 ? o.summaries[o.summaries.length - 1] : undefined
}

export interface ObjectSlice {
  object_id: bigint
  min_ts: bigint
  max_ts?: bigint
}

export interface BranchPath {
  branch_id: string
  sample_id: bigint
  branch_index: number
  object_ids: bigint[]
  slices: ObjectSlice[]
  relation_chain: Relation[]
  events: WireEvent[]
  steps: WireEvent[]
  summaries: WireEvent[]
  visits: QueueVisit[]
  calls: CallPair[]
  qstates: QStateAnnotation[]
  tcpdump: TcpdumpCandidate[]
  end_reason: number
  end_reason_name: string
  drop_reason?: bigint
  complete: boolean
  completeness: string
  gap_reasons: string[]
  unknown_must: UnknownTlv[]
  successor_truncated: boolean
  unknown_predecessors: boolean
  requeue_count: number
  start_ts_ns: bigint
  end_ts_ns: bigint
}

export function branchLeafObjectId(b: BranchPath): bigint {
  return b.object_ids[b.object_ids.length - 1]!
}

export interface SampleGraph {
  sample_id: bigint
  root_object_ids: bigint[]
  object_ids: bigint[]
  relations: Relation[]
  branches: BranchPath[]
  complete: boolean
  completeness: string
  gap_reasons: string[]
  successor_truncated: boolean
  unknown_predecessors: boolean
  attr: Attribution
  first_ts_ns: bigint
  last_ts_ns: bigint
}

export class Session {
  readonly loaded: LoadedSession
  readonly manifest: Record<string, unknown>
  readonly dict: Record<string, unknown>
  events: WireEvent[] = []
  dedup_dropped = 0
  seq_gaps: SeqGap[] = []
  quality_events: WireEvent[] = []
  qstate_events: WireEvent[] = []
  qstates: QStateAnnotation[] = []
  readonly objects = new Map<bigint, ObjectNode>()
  object_order: bigint[] = []
  relations: Relation[] = []
  readonly samples = new Map<bigint, SampleGraph>()
  sample_order: bigint[] = []
  branches: BranchPath[] = []
  unmatched_returns: WireEvent[] = []
  has_unobservable_missed_src = false
  unobservable_adapters: string[] = []
  topo_desync_windows: Array<[bigint, bigint]> = []
  requeue_count = 0
  requeue_gso_count = 0
  requeue_bad_txq_count = 0
  reorder_count = 0

  readonly sites: Map<number, Site>
  readonly topo: TopoEpoch[]
  readonly calibs: Calibration[]

  constructor(ls: LoadedSession) {
    this.loaded = ls
    this.manifest = ls.manifest
    this.dict = ls.dictionary
    this.sites = parseSites(ls.dictionary)
    mergeManifestSites(this.sites, ls.manifest)
    this.topo = parseTopology(ls.dictionary)
    this.calibs = parseCalibrations(ls.manifest)
  }

  resolveSite(idx: number): Site | undefined {
    return this.sites.get(idx)
  }

  inferQdiscKind(siteIdx: number): string {
    return inferQdiscKindFromSite(this.resolveSite(siteIdx))
  }

  isTopoDesyncedAt(ts: bigint): boolean {
    for (const [lo, hi] of this.topo_desync_windows) {
      if (lo <= ts && ts <= hi) return true
    }
    return false
  }

  resolveDevName(ifindex: bigint, devGen?: bigint, netns?: bigint): string {
    if (ifindex === 0n) return 'if0'
    const d = resolveDevInfoFromTopo(this.topo, ifindex, devGen, netns)
    if (d && d.name !== '') return d.name
    return `if${ifindex.toString()}`
  }

  resolveDevLinktype(ifindex: bigint, devGen?: bigint): number {
    return resolveDevLinktypeFromTopo(this.topo, ifindex, devGen)
  }

  resolveQdiscInfo(
    ifindex: bigint,
    queueGen?: bigint,
    handle?: bigint,
    parent?: bigint,
    devGen?: bigint,
    ts?: bigint,
  ): QdiscInfo | undefined {
    if (ts !== undefined && this.isTopoDesyncedAt(ts)) return undefined
    if (queueGen !== undefined && queueGen > 0n) {
      let bestAtOrBefore: QdiscInfo | undefined
      let bestAny: QdiscInfo | undefined
      for (const ep of this.topo) {
        for (const q of ep.qdiscs) {
          if (q.has_ifindex && q.ifindex === ifindex && q.has_queue_gen && q.queue_gen === queueGen) {
            if (devGen !== undefined && devGen !== 0n && q.dev_gen !== 0n && q.dev_gen !== devGen) continue
            const cand: QdiscInfo = { kind: q.kind, handle: q.handle, parent: q.parent, queue_gen: q.queue_gen }
            bestAny = cand
            if (ts === undefined || ep.ts_ns <= ts) bestAtOrBefore = cand
          }
        }
      }
      if (bestAtOrBefore) return bestAtOrBefore
      if (bestAny) return bestAny
    }
    if (handle !== undefined) {
      const h32 = Number(handle & 0xffffffffn) >>> 0
      let bestAtOrBefore: QdiscInfo | undefined
      let bestAny: QdiscInfo | undefined
      for (const ep of this.topo) {
        for (const q of ep.qdiscs) {
          if (q.has_ifindex && q.ifindex === ifindex && q.has_handle && (Number(q.handle & 0xffffffffn) >>> 0) === h32) {
            if (
              parent !== undefined &&
              parent !== 0n &&
              q.has_parent &&
              (Number(q.parent & 0xffffffffn) >>> 0) !== (Number(parent & 0xffffffffn) >>> 0)
            ) {
              continue
            }
            if (h32 === 0 && (parent === undefined || parent === 0n) && q.has_parent && isParentTCClass(q.parent)) {
              continue
            }
            const cand: QdiscInfo = { kind: q.kind, handle: q.handle, parent: q.parent, queue_gen: q.queue_gen }
            bestAny = cand
            if (ts === undefined || ep.ts_ns <= ts) bestAtOrBefore = cand
          }
        }
      }
      if (bestAtOrBefore) return bestAtOrBefore
      if (bestAny) return bestAny
    }
    return undefined
  }

  resolveVisitQdiscKind(v: QueueVisit): string {
    const qi = this.resolveQdiscInfo(v.ifindex, v.queue_gen, v.qdisc_handle, v.qdisc_parent, v.dev_gen)
    if (qi && qi.kind !== '') return qi.kind
    if (v.entry) {
      const k = this.inferQdiscKind(v.entry.site_dict_idx)
      if (k !== '') return k
    }
    if (v.exit) {
      const k = this.inferQdiscKind(v.exit.site_dict_idx)
      if (k !== '') return k
    }
    return ''
  }

  resolveClassInfo(ifindex: bigint, classid: bigint, devGen?: bigint, ts?: bigint): ClassInfo | undefined {
    const c32 = Number(classid & 0xffffffffn) >>> 0
    if (c32 === 0) return undefined
    if (ts !== undefined && this.isTopoDesyncedAt(ts)) return undefined
    let bestAtOrBefore: ClassInfo | undefined
    let bestAny: ClassInfo | undefined
    for (const ep of this.topo) {
      for (const c of ep.classes) {
        if (!c.has_handle || c.handle !== c32) continue
        if (ifindex !== 0n && c.has_ifindex && c.ifindex !== 0n && c.ifindex !== ifindex) continue
        if (devGen !== undefined && devGen !== 0n && c.dev_gen !== 0n && c.dev_gen !== devGen) continue
        const cp = { ...c }
        bestAny = cp
        if (ts === undefined || ep.ts_ns <= ts) bestAtOrBefore = cp
      }
    }
    return bestAtOrBefore ?? bestAny
  }

  calibrateBoottimeToRealtime(boottime: bigint): { realtime_ns: bigint; err_ns: bigint; calibrated: boolean } {
    if (this.calibs.length === 0) {
      return { realtime_ns: boottime, err_ns: 0n, calibrated: false }
    }
    let best = 0
    let bestD: bigint | undefined
    for (let i = 0; i < this.calibs.length; i++) {
      const c = this.calibs[i]!
      let d = c.boottime_ns - boottime
      if (d < 0n) d = -d
      if (bestD === undefined || d < bestD) {
        bestD = d
        best = i
      }
    }
    const c = this.calibs[best]!
    return {
      realtime_ns: c.realtime_ns + (boottime - c.boottime_ns),
      err_ns: c.err_ns,
      calibrated: true,
    }
  }

  adapterName(id: string): string {
    const arr = this.manifest['adapters']
    if (!Array.isArray(arr)) return id
    for (const a of arr) {
      if (typeof a !== 'object' || a === null || Array.isArray(a)) continue
      const m = a as Record<string, unknown>
      if (jstr(m['adapter_id']) === id) {
        const n = jstr(m['name'])
        if (n !== '') return n
      }
    }
    return id
  }

  attachTcpdumpCandidates(packets: PcapPacket[], windowMarginNs = 50_000_000n): TcpdumpCandidate[] {
    const margin = windowMarginNs > 0n ? windowMarginNs : 50_000_000n
    const all: TcpdumpCandidate[] = []
    for (const br of this.branches) {
      const cands = matchBranchPackets((bt) => this.calibrateBoottimeToRealtime(bt), br, packets, margin)
      br.tcpdump = cands
      for (const c of cands) all.push(c)
    }
    return all
  }
}

function cmpBigInt(a: bigint, b: bigint): number {
  return a < b ? -1 : a > b ? 1 : 0
}

function sortByTsSeq(evs: WireEvent[]): void {
  evs.sort((a, b) => {
    if (a.ts_ns !== b.ts_ns) return a.ts_ns < b.ts_ns ? -1 : 1
    return cmpBigInt(a.seq, b.seq)
  })
}

function sortByTsProdSeq(evs: WireEvent[]): void {
  evs.sort((a, b) => {
    if (a.ts_ns !== b.ts_ns) return a.ts_ns < b.ts_ns ? -1 : 1
    if (a.producer_type !== b.producer_type) return a.producer_type - b.producer_type
    return cmpBigInt(a.seq, b.seq)
  })
}

function dedupAndDetectSeqGaps(raw: WireEvent[]): { events: WireEvent[]; dropped: number; gaps: SeqGap[] } {
  const seen = new Set<string>()
  const deduped: WireEvent[] = []
  let dropped = 0
  const byStream = new Map<string, { p: number; c: number; evs: WireEvent[] }>()
  for (const ev of raw) {
    const k = ev.dedupKey()
    if (seen.has(k)) {
      dropped++
      continue
    }
    seen.add(k)
    deduped.push(ev)
    const sk = `${ev.producer_type}:${ev.cpu}`
    let entry = byStream.get(sk)
    if (!entry) {
      entry = { p: ev.producer_type, c: ev.cpu, evs: [] }
      byStream.set(sk, entry)
    }
    entry.evs.push(ev)
  }
  const streams = [...byStream.values()].sort((a, b) => (a.p !== b.p ? a.p - b.p : a.c - b.c))
  const gaps: SeqGap[] = []
  for (const st of streams) {
    const evs = [...st.evs].sort((a, b) => cmpBigInt(a.seq, b.seq))
    for (let i = 1; i < evs.length; i++) {
      const p = evs[i - 1]!
      const c = evs[i]!
      if (c.seq > p.seq + 1n) {
        gaps.push({
          producer_type: st.p,
          cpu: st.c,
          prev_seq: p.seq,
          next_seq: c.seq,
          missing_count: c.seq - p.seq - 1n,
          win_start_ns: p.ts_ns,
          win_end_ns: c.ts_ns,
          prev_object_id: p.object_id,
          next_object_id: c.object_id,
        })
      }
    }
  }
  sortByTsProdSeq(deduped)
  return { events: deduped, dropped, gaps }
}

function buildQStateAnnotations(evs: WireEvent[]): QStateAnnotation[] {
  const sorted = [...evs]
  sortByTsSeq(sorted)
  const out: QStateAnnotation[] = []
  const open = new Map<string, QStateAnnotation>()
  const openOrder: string[] = []
  const removeOpen = (k: string): void => {
    open.delete(k)
    const idx = openOrder.indexOf(k)
    if (idx >= 0) openOrder.splice(idx, 1)
  }
  for (const ev of sorted) {
    const ifidx = ev.u('ifindex')
    const txq = ev.u('txq')
    const qgen = ev.u('queue_gen')
    const op = ev.num('state_op')
    const val = ev.u('value')
    const k = `${ifidx.toString()}:${txq.toString()}`
    if (op === QSTATE_TXQ_STOP) {
      const prev = open.get(k)
      if (prev) {
        out.push(prev)
        removeOpen(k)
      }
      open.set(k, {
        ifindex: ifidx,
        txq,
        queue_gen: qgen,
        state_op: op,
        state_name: 'TXQ_STOP_WAKE',
        start_ns: ev.ts_ns,
        value: val,
        event_ids: [ev.eventId()],
      })
      openOrder.push(k)
    } else if (op === QSTATE_TXQ_WAKE) {
      const prev = open.get(k)
      if (prev) {
        removeOpen(k)
        prev.end_ns = ev.ts_ns
        prev.event_ids.push(ev.eventId())
        out.push(prev)
      } else {
        out.push({
          ifindex: ifidx,
          txq,
          queue_gen: qgen,
          state_op: op,
          state_name: 'TXQ_WAKE',
          start_ns: ev.ts_ns,
          end_ns: ev.ts_ns,
          value: val,
          event_ids: [ev.eventId()],
        })
      }
    } else {
      const name = QSTATE_OP_NAMES[op] ?? `QSTATE_${op}`
      out.push({
        ifindex: ifidx,
        txq,
        queue_gen: qgen,
        state_op: op,
        state_name: name,
        start_ns: ev.ts_ns,
        end_ns: ev.ts_ns,
        value: val,
        event_ids: [ev.eventId()],
      })
    }
  }
  for (const k of openOrder) {
    const a = open.get(k)
    if (a) out.push(a)
  }
  out.sort((a, b) => cmpBigInt(a.start_ns, b.start_ns))
  return out
}

function matchingQStates(
  all: QStateAnnotation[],
  ifindex: bigint,
  txq: bigint | undefined,
  ws: bigint,
  we: bigint,
): QStateAnnotation[] {
  const out: QStateAnnotation[] = []
  for (const qs of all) {
    if (ifindex !== 0n && qs.ifindex !== 0n && qs.ifindex !== ifindex) continue
    if (txq !== undefined && qs.txq !== txq) continue
    const qend = qs.end_ns !== undefined ? qs.end_ns : we
    if (qs.start_ns <= we && qend >= ws) out.push(qs)
  }
  return out
}

const ENTRY_CALL_STAGES = new Set<number>([
  STAGE_QDISC_ENQ,
  STAGE_REQUEUE_GSO,
  STAGE_REQUEUE_BAD_TXQ,
  STAGE_XMIT_START,
  STAGE_CLASSIFY,
  STAGE_ENTRY,
  STAGE_HANDOFF_LAYER,
])
const RET_CALL_STAGES = new Set<number>([STAGE_QDISC_ENQ_RET, STAGE_XMIT_RET])
const VISIT_ENTRY_STAGES: Readonly<Record<number, string>> = {
  [STAGE_QDISC_ENQ]: 'qdisc',
  [STAGE_REQUEUE_GSO]: 'requeue_gso',
  [STAGE_REQUEUE_BAD_TXQ]: 'requeue_bad_txq',
}

function pairCallsAndVisits(s: Session): WireEvent[] {
  const unmatched: WireEvent[] = []
  const byID = new Map<bigint, CallPair[]>()
  const byObj = new Map<string, CallPair[]>()

  for (const oid of s.object_order) {
    const obj = s.objects.get(oid)!
    for (const st of obj.steps) {
      const stage = st.num('stage')
      if (stage === STAGE_CLASSIFY && st.has('raw_ret')) continue
      const cid = st.get('call_id')
      if (cid !== undefined && cid > 0n && ENTRY_CALL_STAGES.has(stage)) {
        const cp: CallPair = {
          call_id: cid,
          object_id: oid,
          entry: st,
          paired: false,
          ambiguous: false,
          cross_cpu_late: false,
        }
        obj.calls.push(cp)
        const g = byID.get(cid) ?? []
        g.push(cp)
        byID.set(cid, g)
        const ok = `${oid.toString()}:${cid.toString()}`
        const og = byObj.get(ok) ?? []
        og.push(cp)
        byObj.set(ok, og)
      }
    }
  }

  for (const oid of s.object_order) {
    const obj = s.objects.get(oid)!
    const reassigned: WireEvent[] = []
    const steps = obj.steps
    for (let i = 0; i < steps.length; i++) {
      const st = steps[i]!
      if (!RET_CALL_STAGES.has(st.num('stage'))) {
        reassigned.push(st)
        continue
      }
      const cid = st.get('call_id')
      if (cid === undefined || cid === 0n) {
        reassigned.push(st)
        continue
      }
      let cands = byObj.get(`${oid.toString()}:${cid.toString()}`) ?? []
      if (cands.length === 0) {
        const global = byID.get(cid) ?? []
        if (global.length === 1) {
          cands = global
          const target = global[0]!.object_id
          if (target !== oid) {
            s.objects.get(target)!.steps.push(st)
          } else {
            reassigned.push(st)
          }
        } else {
          unmatched.push(st)
          continue
        }
      } else {
        reassigned.push(st)
      }
      if (cands.length !== 1 || cands[0]!.ret !== undefined) {
        for (const c of cands) {
          c.ambiguous = true
          c.paired = false
        }
        unmatched.push(st)
      } else {
        const cp = cands[0]!
        cp.ret = st
        cp.paired = true
        cp.raw_ret = evOpt(st, 'raw_ret')
      }
    }
    obj.steps = reassigned
  }

  for (const oid of s.object_order) {
    const obj = s.objects.get(oid)!
    sortByTsSeq(obj.steps)
    for (const cp of obj.calls) {
      if (cp.paired && cp.entry && cp.ret) {
        for (const other of obj.steps) {
          if (other === cp.entry || other === cp.ret) continue
          if (cp.entry.ts_ns <= other.ts_ns && other.ts_ns <= cp.ret.ts_ns && other.cpu !== cp.entry.cpu) {
            cp.cross_cpu_late = true
            break
          }
        }
      }
    }
  }

  for (const oid of s.object_order) {
    const obj = s.objects.get(oid)!
    const seen = new Set<string>()
    let handoff = false
    for (const st of obj.steps) {
      const stage = st.num('stage')
      if (stage === STAGE_HANDOFF_LAYER) {
        handoff = true
      } else if (stage === STAGE_ENTRY) {
        const sig = `${st.u('netns_inum')}:${st.u('ifindex')}:${st.u('dev_gen')}:${st.u('dir')}`
        if (seen.has(sig) && !handoff) obj.identity_conflict = true
        seen.add(sig)
        handoff = false
      }
    }
  }

  for (const oid of s.object_order) {
    if (oid === 0n) continue
    const obj = s.objects.get(oid)!
    const entries = new Map<string, WireEvent[]>()
    const entriesByVid = new Map<bigint, Array<{ qgen: bigint; ev: WireEvent }>>()
    const enqRets = new Map<string, WireEvent[]>()
    const exits = new Map<string, WireEvent[]>()
    const unkeyedExits: WireEvent[] = []
    const callMap = new Map<bigint, CallPair>()
    for (const cp of obj.calls) {
      if (!cp.ambiguous) callMap.set(cp.call_id, cp)
    }
    let knownTxq: bigint | undefined
    for (const st of obj.steps) {
      const stg = st.num('stage')
      const t = st.get('txq')
      if (t !== undefined && (stg === STAGE_XMIT_START || stg === STAGE_QDISC_ENQ || stg === STAGE_QDISC_DEQ)) {
        knownTxq = t
        break
      }
    }
    const keyOrder: Array<{ qgen: bigint; vid: bigint; key: string }> = []
    const seenKey = new Set<string>()
    const noteKey = (qgen: bigint, vid: bigint): string => {
      const key = `${qgen.toString()}:${vid.toString()}`
      if (!seenKey.has(key)) {
        seenKey.add(key)
        keyOrder.push({ qgen, vid, key })
      }
      return key
    }

    for (const st of obj.steps) {
      const stage = st.num('stage')
      const vid = st.get('visit_id')
      if (vid === undefined || vid === 0n) continue
      const qraw = st.get('queue_gen')
      const qgen = qraw ?? 0n
      if (stage in VISIT_ENTRY_STAGES) {
        const key = noteKey(qgen, vid)
        const list = entries.get(key) ?? []
        list.push(st)
        entries.set(key, list)
        const byV = entriesByVid.get(vid) ?? []
        byV.push({ qgen, ev: st })
        entriesByVid.set(vid, byV)
      } else if (stage === STAGE_QDISC_ENQ_RET) {
        const key = `${qgen.toString()}:${vid.toString()}`
        const list = enqRets.get(key) ?? []
        list.push(st)
        enqRets.set(key, list)
      } else if (stage === STAGE_QDISC_DEQ || stage === STAGE_DROP) {
        if (qraw === undefined || qraw === 0n) {
          unkeyedExits.push(st)
        } else {
          const key = noteKey(qgen, vid)
          const list = exits.get(key) ?? []
          list.push(st)
          exits.set(key, list)
        }
      }
    }

    const ambiguousVids = new Set<bigint>()
    for (const ex of unkeyedExits) {
      const vid = ex.u('visit_id')
      const cands = entriesByVid.get(vid) ?? []
      const uniq = new Set<bigint>()
      for (const c of cands) uniq.add(c.qgen)
      if (uniq.size === 1) {
        const [only] = uniq
        const key = noteKey(only!, vid)
        const list = exits.get(key) ?? []
        list.push(ex)
        exits.set(key, list)
      } else if (uniq.size > 1) {
        ambiguousVids.add(vid)
      } else {
        const key = noteKey(0n, vid)
        const list = exits.get(key) ?? []
        list.push(ex)
        exits.set(key, list)
      }
    }

    const refTs = (key: string): bigint => {
      const en = entries.get(key)
      if (en && en.length > 0) return en[0]!.ts_ns
      return exits.get(key)![0]!.ts_ns
    }

    keyOrder.sort((a, b) => {
      const ti = refTs(a.key)
      const tj = refTs(b.key)
      if (ti !== tj) return ti < tj ? -1 : 1
      if (a.vid !== b.vid) return a.vid < b.vid ? -1 : 1
      return cmpBigInt(a.qgen, b.qgen)
    })

    const enqueueTid = obj.attr.enqueue_tid
    for (const ko of keyOrder) {
      const en = entries.get(ko.key) ?? []
      const ex = exits.get(ko.key) ?? []
      const ref = en.length > 0 ? en[0]! : ex[0]!
      let refStage = ref.num('stage')
      if (!ref.has('stage') || refStage === 0) refStage = STAGE_QDISC_ENQ
      const vkind = VISIT_ENTRY_STAGES[refStage] ?? 'qdisc'
      const v: QueueVisit = {
        object_id: oid,
        queue_gen: ko.qgen,
        visit_id: ko.vid,
        visit_kind: vkind,
        netns_inum: ref.u('netns_inum'),
        ifindex: ref.u('ifindex'),
        dev_gen: ref.u('dev_gen'),
        qdisc_handle: ref.u('qdisc_handle'),
        qdisc_parent: ref.u('qdisc_parent'),
        classid: ref.u('classid'),
        bucket: evOpt(ref, 'bucket'),
        txq: evOpt(ref, 'txq'),
        entry: en.length === 1 ? en[0] : undefined,
        exit: ex.length === 1 ? ex[0] : undefined,
        paired: false,
        ambiguous: ambiguousVids.has(ko.vid) || en.length > 1 || ex.length > 1,
        enq_dropped: false,
        enq_cn: false,
        cross_thread_dequeue: false,
        backpressure: [],
      }
      if (v.entry) {
        let retEv: WireEvent | undefined
        const cid = v.entry.get('call_id')
        const cp = cid !== undefined ? callMap.get(cid) : undefined
        if (cp) {
          retEv = cp.ret
        } else {
          const er = enqRets.get(ko.key)
          if (er && er.length === 1) retEv = er[0]
        }
        if (retEv) {
          v.enq_ret = retEv
          const rc = retEv.i('raw_ret')
          if (rc !== undefined) {
            v.enq_ret_code = rc
            if (rc === NET_XMIT_DROP || rc < 0n) v.enq_dropped = true
            else if (rc === NET_XMIT_CN) v.enq_cn = true
          }
        }
      }
      if (!v.ambiguous && !v.enq_dropped && v.entry && v.exit) {
        if (v.exit.ts_ns >= v.entry.ts_ns) {
          v.paired = true
          v.sojourn_ns = v.exit.ts_ns - v.entry.ts_ns
          if (enqueueTid !== undefined && enqueueTid !== 0n) {
            const exTid = v.exit.get('ctx_tid')
            if (exTid !== undefined && exTid !== enqueueTid) v.cross_thread_dequeue = true
          }
        }
      }
      const ws = v.entry ? v.entry.ts_ns : ref.ts_ns
      let we = obj.last_ts_ns
      if (ws > we) we = ws
      if (v.exit) we = v.exit.ts_ns
      const txqFilter = v.txq !== undefined ? v.txq : knownTxq
      v.backpressure = matchingQStates(s.qstates, v.ifindex, txqFilter, ws, we)
      obj.visits.push(v)
    }
  }
  return unmatched
}

function extractAttribution(obj: ObjectNode): Attribution {
  const a: Attribution = {}
  for (const sm of obj.summaries) {
    if (a.uid === undefined) a.uid = sm.get('uid')
    if (a.tgid === undefined) a.tgid = sm.get('tgid')
    if (a.comm === undefined) a.comm = sm.str('comm')
    if (a.enqueue_tid === undefined) a.enqueue_tid = sm.get('enqueue_tid')
    if (a.skb_create_ts === undefined) a.skb_create_ts = sm.get('skb_create_ts')
    for (let slot = 0; slot < 16; slot++) {
      const v = sm.get(`plugin_val${slot}`)
      if (v !== undefined) {
        if (!a.plugin_vals) a.plugin_vals = new Map<number, bigint>()
        if (!a.plugin_vals.has(slot)) a.plugin_vals.set(slot, v)
      }
    }
    if (a.in_task === undefined) a.in_task = (sm.flags & EV_FLAG_IN_TASK) !== 0
  }
  for (const st of obj.steps) {
    const stage = st.num('stage')
    if (stage === STAGE_ENTRY) {
      if (a.enqueue_tid === undefined) a.enqueue_tid = st.get('ctx_tid')
      if (a.in_task === undefined) a.in_task = (st.flags & EV_FLAG_IN_TASK) !== 0
    } else if (stage === STAGE_XMIT_START) {
      const v = st.get('ctx_tid')
      if (v !== undefined) {
        a.xmit_tid = v
        a.xmit_in_task = (st.flags & EV_FLAG_IN_TASK) !== 0
      }
    }
  }
  return a
}

function computeEffectiveEndReason(obj: ObjectNode): number {
  if (obj.explicit_end_reason !== END_OPEN) return obj.explicit_end_reason
  for (const r of obj.outgoing) {
    if (r.rel_type !== REL_CLONE && r.rel_type !== REL_COPY) return END_CONSUME
  }
  for (let i = obj.steps.length - 1; i >= 0; i--) {
    const st = obj.steps[i]!
    const stage = st.num('stage')
    if (stage === STAGE_XMIT_RET) {
      const rc = st.i('raw_ret')
      if (rc === undefined || rc === NETDEV_TX_OK) return END_TX_OK
    } else if (stage === STAGE_DROP) {
      return END_DROP
    } else if (stage === STAGE_CONSUME) {
      return END_CONSUME
    } else if (stage === STAGE_DELIVER_SOCK) {
      return END_SOCK_ENQUEUE
    }
  }
  return END_OPEN
}

function seqGapOverlapsBranch(g: SeqGap, b: BranchPath): boolean {
  if (g.prev_object_id !== 0n) {
    for (const oid of b.object_ids) {
      if (oid === g.prev_object_id) {
        if (g.win_start_ns <= b.end_ts_ns) return true
        break
      }
    }
  }
  let minSeq = 0n
  let maxSeq = 0n
  let found = false
  for (const e of b.events) {
    if (e.producer_type === g.producer_type && e.cpu === g.cpu) {
      if (!found) {
        minSeq = e.seq
        maxSeq = e.seq
        found = true
      } else {
        if (e.seq < minSeq) minSeq = e.seq
        if (e.seq > maxSeq) maxSeq = e.seq
      }
    }
  }
  if (found) {
    if (minSeq >= g.next_seq && b.start_ts_ns >= g.win_end_ns) return false
    if (maxSeq <= g.prev_seq && b.end_ts_ns < g.win_start_ns) return false
    if (minSeq <= g.prev_seq && maxSeq >= g.next_seq) return true
  }
  return b.start_ts_ns < g.win_end_ns && b.end_ts_ns >= g.win_start_ns
}

function computeReorderCount(s: Session): number {
  interface TsSeq {
    ts: bigint
    seq: bigint
  }
  const lessTS = (a: TsSeq, b: TsSeq): number => {
    if (a.ts !== b.ts) return a.ts < b.ts ? -1 : 1
    return cmpBigInt(a.seq, b.seq)
  }
  const per = new Map<string, Array<{ entry: TsSeq; depart: TsSeq }>>()
  const portOrder: string[] = []
  for (const oid of s.object_order) {
    const obj = s.objects.get(oid)
    if (!obj || obj.object_type !== OBJ_SKB) continue
    let entry: WireEvent | undefined
    let depart: WireEvent | undefined
    for (const st of obj.steps) {
      const stg = st.num('stage')
      if (stg === STAGE_ENTRY && !entry) entry = st
      else if ((stg === STAGE_QDISC_DEQ || stg === STAGE_XMIT_START) && !depart) depart = st
    }
    if (entry && depart) {
      const k = `${entry.u('netns_inum')}:${entry.u('ifindex')}:${entry.u('dir')}`
      let list = per.get(k)
      if (!list) {
        list = []
        per.set(k, list)
        portOrder.push(k)
      }
      list.push({
        entry: { ts: entry.ts_ns, seq: entry.seq },
        depart: { ts: depart.ts_ns, seq: depart.seq },
      })
    }
  }
  let total = 0
  for (const k of portOrder) {
    const items = per.get(k)!
    if (items.length < 2) continue
    const byEntry = [...items].sort((a, b) => lessTS(a.entry, b.entry))
    const rs = byEntry.map((p, idx) => ({ rank: idx, depart: p.depart }))
    rs.sort((a, b) => lessTS(a.depart, b.depart))
    let maxSeen = -1
    for (const r of rs) {
      if (r.rank < maxSeen) total++
      else maxSeen = r.rank
    }
  }
  return total
}

function dedupStrings(inp: string[]): string[] {
  const seen = new Set<string>()
  const out: string[] = []
  for (const s of inp) {
    if (!seen.has(s)) {
      seen.add(s)
      out.push(s)
    }
  }
  return out
}

function orTs(v: bigint, def: bigint): bigint {
  return v === 0n ? def : v
}

export function endReasonName(r: number): string {
  return END_REASON_NAMES[r] ?? `END_${r}`
}

export function stageName(st: number): string {
  return STAGE_NAMES[st] ?? `STAGE_${st}`
}

export function reconstruct(ls: LoadedSession): Session {
  const s = new Session(ls)
  const deduped = dedupAndDetectSeqGaps(ls.events)
  s.events = deduped.events
  s.dedup_dropped = deduped.dropped
  s.seq_gaps = deduped.gaps

  if (Array.isArray(s.manifest['adapters'])) {
    for (const a of s.manifest['adapters']) {
      if (typeof a !== 'object' || a === null || Array.isArray(a)) continue
      const m = a as Record<string, unknown>
      if ('enabled' in m && !truthy(m['enabled'])) continue
      if (typeof m['required'] === 'boolean' && !m['required']) continue
      if (jstr(m['missed_source']).trim().toLowerCase() === 'none') {
        const id = jstr(m['adapter_id']) || jstr(m['name']) || 'unknown'
        s.unobservable_adapters.push(id)
      }
    }
  }
  s.has_unobservable_missed_src = s.unobservable_adapters.length > 0

  const getObj = (oid: bigint, otype: number): ObjectNode => {
    let n = s.objects.get(oid)
    if (!n) {
      n = {
        object_id: oid,
        object_type: otype,
        sample_ids: new Set<bigint>(),
        primary_sample_id: 0n,
        object_events: [],
        steps: [],
        summaries: [],
        visits: [],
        calls: [],
        outgoing: [],
        incoming: [],
        explicit_end_reason: END_OPEN,
        effective_end_reason: END_OPEN,
        unknown_must: [],
        unknown_optional: [],
        successor_truncated: false,
        unknown_predecessors: false,
        identity_conflict: false,
        attr: {},
        first_ts_ns: 0n,
        last_ts_ns: 0n,
      }
      s.objects.set(oid, n)
      s.object_order.push(oid)
    } else if (n.object_type === OBJ_SKB && otype !== OBJ_SKB) {
      n.object_type = otype
    }
    return n
  }

  for (const ev of s.events) {
    switch (ev.kind) {
      case KIND_OBJECT: {
        if (ev.object_id === 0n) continue
        const obj = getObj(ev.object_id, ev.object_type)
        obj.object_events.push(ev)
        const sid = ev.u('sample_id')
        if (sid > 0n) {
          obj.sample_ids.add(sid)
          if (obj.primary_sample_id === 0n) obj.primary_sample_id = sid
        }
        const er = ev.get('end_reason')
        if (er !== undefined && Number(er) !== END_OPEN) {
          obj.explicit_end_reason = Number(er)
          if (Number(er) === END_CONFLICT_TRUNCATED) obj.identity_conflict = true
        }
        const dr = ev.get('drop_reason')
        if (dr !== undefined) obj.drop_reason = dr
        obj.unknown_must.push(...ev.unknown_must)
        obj.unknown_optional.push(...ev.unknown_optional)
        break
      }
      case KIND_STEP: {
        if (ev.object_id !== 0n) {
          const obj = getObj(ev.object_id, ev.object_type)
          obj.steps.push(ev)
          obj.unknown_must.push(...ev.unknown_must)
          obj.unknown_optional.push(...ev.unknown_optional)
        } else {
          const d = getObj(0n, ev.object_type)
          d.steps.push(ev)
        }
        break
      }
      case KIND_SUMMARY: {
        if (ev.object_id === 0n) continue
        const obj = getObj(ev.object_id, ev.object_type)
        obj.summaries.push(ev)
        obj.unknown_must.push(...ev.unknown_must)
        obj.unknown_optional.push(...ev.unknown_optional)
        break
      }
      case KIND_RELATION: {
        const srcID = ev.get('src_object_id') ?? ev.object_id
        const dstID = ev.u('dst_object_id')
        const rtype = ev.num('rel_type')
        const rflags = ev.u('rel_flags')
        const name = REL_TYPE_NAMES[rtype] ?? `REL_${rtype}`
        const edge: Relation = {
          event: ev,
          op_id: ev.u('op_id'),
          rel_type: rtype,
          rel_type_name: name,
          src_object_id: srcID,
          dst_object_id: dstID,
          rel_flags: rflags,
          successor_truncated: (Number(rflags) & REL_FLAG_SUCCESSOR_TRUNCATED) !== 0,
          unknown_predecessors: (Number(rflags) & REL_FLAG_UNKNOWN_PREDECESSORS) !== 0,
          stream_offset: evOpt(ev, 'stream_offset'),
          span_len: evOpt(ev, 'span_len'),
          ts_ns: ev.ts_ns,
        }
        s.relations.push(edge)
        if (srcID !== 0n) {
          let otype = ev.object_type
          if (rtype === REL_SPAN_MAP && !s.objects.has(srcID)) otype = OBJ_APP_MSG
          const so = getObj(srcID, otype)
          so.outgoing.push(edge)
          so.unknown_must.push(...ev.unknown_must)
          if (edge.successor_truncated) so.successor_truncated = true
        }
        if (dstID !== 0n) {
          const doObj = getObj(dstID, OBJ_SKB)
          doObj.incoming.push(edge)
          doObj.unknown_must.push(...ev.unknown_must)
          if (edge.unknown_predecessors) doObj.unknown_predecessors = true
          if (edge.successor_truncated) doObj.successor_truncated = true
        }
        break
      }
      case KIND_QSTATE:
        s.qstate_events.push(ev)
        break
      case KIND_QUALITY: {
        s.quality_events.push(ev)
        const qkind = ev.num('qual_kind')
        const qcnt = ev.get('count') ?? 1n
        if (qkind === QUAL_TOPO_DESYNC && qcnt > 0n) {
          const ws = orTs(ev.u('win_start_ns'), ev.ts_ns)
          let we = orTs(ev.u('win_end_ns'), ev.ts_ns)
          if (we < ws) we = ws
          s.topo_desync_windows.push([ws, we])
        } else if (qkind === QUAL_IDENTITY_CONFLICT && qcnt > 0n && ev.object_id !== 0n) {
          getObj(ev.object_id, ev.object_type).identity_conflict = true
        }
        break
      }
    }
  }

  s.qstates = buildQStateAnnotations(s.qstate_events)

  const recomputeTs = (obj: ObjectNode): void => {
    let first = 0n
    let last = 0n
    let any = false
    for (const list of [obj.object_events, obj.steps, obj.summaries]) {
      for (const e of list) {
        if (!any) {
          first = e.ts_ns
          last = e.ts_ns
          any = true
        } else {
          if (e.ts_ns < first) first = e.ts_ns
          if (e.ts_ns > last) last = e.ts_ns
        }
      }
    }
    if (any) {
      obj.first_ts_ns = first
      obj.last_ts_ns = last
    }
  }

  for (const oid of s.object_order) {
    if (oid === 0n) continue
    const obj = s.objects.get(oid)!
    recomputeTs(obj)
    obj.attr = extractAttribution(obj)
  }

  s.unmatched_returns = pairCallsAndVisits(s)
  if (s.objects.has(0n)) {
    s.objects.delete(0n)
    const idx = s.object_order.indexOf(0n)
    if (idx >= 0) s.object_order.splice(idx, 1)
  }

  for (const oid of s.object_order) {
    const obj = s.objects.get(oid)!
    recomputeTs(obj)
    obj.attr = extractAttribution(obj)
    obj.effective_end_reason = computeEffectiveEndReason(obj)
    for (const st of obj.steps) {
      const stage = st.num('stage')
      if (stage === STAGE_REQUEUE_GSO) s.requeue_gso_count++
      else if (stage === STAGE_REQUEUE_BAD_TXQ) s.requeue_bad_txq_count++
    }
  }

  const minKey = (set: Set<bigint>): bigint => {
    let mn: bigint | undefined
    for (const k of set) {
      if (mn === undefined || k < mn) mn = k
    }
    return mn ?? 0n
  }

  let changed = true
  while (changed) {
    changed = false
    for (const rel of s.relations) {
      const src = s.objects.get(rel.src_object_id)
      const dst = s.objects.get(rel.dst_object_id)
      if (!src || !dst) continue
      const before = dst.sample_ids.size
      for (const k of src.sample_ids) dst.sample_ids.add(k)
      if (dst.sample_ids.size !== before) {
        if (dst.primary_sample_id === 0n) dst.primary_sample_id = minKey(dst.sample_ids)
        changed = true
      }
      if (src.sample_ids.size === 0 && dst.sample_ids.size > 0 && rel.rel_type === REL_SPAN_MAP) {
        for (const k of dst.sample_ids) src.sample_ids.add(k)
        src.primary_sample_id = minKey(src.sample_ids)
        changed = true
      }
    }
  }

  for (const oid of s.object_order) {
    const obj = s.objects.get(oid)!
    if (obj.sample_ids.size === 0) {
      obj.sample_ids.add(obj.object_id)
      obj.primary_sample_id = obj.object_id
    }
  }

  const sortedOids = [...s.object_order].sort(cmpBigInt)
  const sampleObjs = new Map<bigint, bigint[]>()
  for (const oid of sortedOids) {
    const sids = [...s.objects.get(oid)!.sample_ids].sort(cmpBigInt)
    for (const sid of sids) {
      const list = sampleObjs.get(sid) ?? []
      list.push(oid)
      sampleObjs.set(sid, list)
    }
  }
  s.sample_order = [...sampleObjs.keys()].sort(cmpBigInt)

  interface LossQual {
    kind: number
    name: string
    ws: bigint
    we: bigint
    oid: bigint
  }
  const loss: LossQual[] = []
  for (const q of s.quality_events) {
    const k = q.num('qual_kind')
    const cnt = q.get('count') ?? 1n
    if (
      (k === QUAL_MISSED_DELTA ||
        k === QUAL_RB_DROP_DELTA ||
        k === QUAL_RET_UNMATCHED ||
        k === QUAL_IDENTITY_CONFLICT ||
        k === QUAL_RING_EVICTED_PREFIX ||
        k === QUAL_TOPO_DESYNC) &&
      cnt > 0n
    ) {
      const ws = orTs(q.u('win_start_ns'), q.ts_ns)
      let we = orTs(q.u('win_end_ns'), q.ts_ns)
      if (we < ws) we = ws
      loss.push({ kind: k, name: QUAL_KIND_NAMES[k] ?? `QUAL_${k}`, ws, we, oid: q.object_id })
    }
  }

  const partialManifest = truthy(s.manifest['partial_coverage'])
  const uncleanTail = isUncleanTail(ls)

  for (const sid of s.sample_order) {
    const objList = sampleObjs.get(sid)!
    const sidSet = new Set<bigint>(objList)
    const sampleRels = s.relations.filter((r) => sidSet.has(r.src_object_id) || sidSet.has(r.dst_object_id))
    const roots: bigint[] = []
    for (const oid of objList) {
      const hasIn = s.objects.get(oid)!.incoming.some((r) => sidSet.has(r.src_object_id))
      if (!hasIn) roots.push(oid)
    }
    if (roots.length === 0) roots.push(objList[0]!)

    interface RawPath {
      slices: ObjectSlice[]
      rels: Relation[]
    }
    const paths: RawPath[] = []
    const dfs = (
      cur: bigint,
      minTs: bigint,
      prefixS: ObjectSlice[],
      prefixR: Relation[],
      visited: Set<bigint>,
    ): void => {
      const node = s.objects.get(cur)!
      const forks: Relation[] = []
      const xforms: Relation[] = []
      for (const r of node.outgoing) {
        if (!s.objects.has(r.dst_object_id) || visited.has(r.dst_object_id)) continue
        if (r.rel_type === REL_CLONE || r.rel_type === REL_COPY) forks.push(r)
        else xforms.push(r)
      }
      const nv = new Set<bigint>(visited)
      nv.add(cur)
      for (const fr of forks) {
        dfs(
          fr.dst_object_id,
          0n,
          [...prefixS, { object_id: cur, min_ts: minTs, max_ts: fr.ts_ns }],
          [...prefixR, fr],
          nv,
        )
      }
      if (xforms.length > 0) {
        for (const xr of xforms) {
          dfs(
            xr.dst_object_id,
            0n,
            [...prefixS, { object_id: cur, min_ts: minTs }],
            [...prefixR, xr],
            nv,
          )
        }
      } else {
        paths.push({
          slices: [...prefixS, { object_id: cur, min_ts: minTs }],
          rels: [...prefixR],
        })
      }
    }

    for (const r of roots) {
      dfs(r, 0n, [], [], new Set<bigint>())
    }

    const sbranches: BranchPath[] = []
    for (let bi = 0; bi < paths.length; bi++) {
      const p = paths[bi]!
      const bIdx = bi + 1
      const oids = p.slices.map((sl) => sl.object_id)
      const leaf = s.objects.get(oids[oids.length - 1]!)!
      const br: BranchPath = {
        branch_id: `s${sid.toString()}:b${bIdx}`,
        sample_id: sid,
        branch_index: bIdx,
        object_ids: oids,
        slices: p.slices,
        relation_chain: p.rels,
        events: [],
        steps: [],
        summaries: [],
        visits: [],
        calls: [],
        qstates: [],
        tcpdump: [],
        end_reason: leaf.effective_end_reason,
        end_reason_name: endReasonName(leaf.effective_end_reason),
        drop_reason: leaf.drop_reason,
        complete: false,
        completeness: 'complete',
        gap_reasons: [],
        unknown_must: [],
        successor_truncated: false,
        unknown_predecessors: false,
        requeue_count: 0,
        start_ts_ns: 0n,
        end_ts_ns: 0n,
      }

      let idConflict = false
      for (const r of p.rels) {
        if (r.successor_truncated) br.successor_truncated = true
        if (r.unknown_predecessors) br.unknown_predecessors = true
      }

      for (const sl of p.slices) {
        const on = s.objects.get(sl.object_id)!
        if (sl.max_ts === undefined && on.successor_truncated) br.successor_truncated = true
        if (on.unknown_predecessors) br.unknown_predecessors = true
        if (on.identity_conflict) idConflict = true
        const inSlice = (ts: bigint): boolean => {
          if (ts < sl.min_ts) return false
          if (sl.max_ts !== undefined && ts > sl.max_ts) return false
          return true
        }
        for (const ev of on.object_events) {
          if (inSlice(ev.ts_ns)) {
            br.events.push(ev)
            br.unknown_must.push(...ev.unknown_must)
          }
        }
        for (const ev of on.steps) {
          if (inSlice(ev.ts_ns)) {
            br.events.push(ev)
            br.steps.push(ev)
            br.unknown_must.push(...ev.unknown_must)
          }
        }
        for (const ev of on.summaries) {
          if (inSlice(ev.ts_ns)) {
            br.events.push(ev)
            br.summaries.push(ev)
            br.unknown_must.push(...ev.unknown_must)
          }
        }
        for (const v of on.visits) {
          const vts = v.entry ? v.entry.ts_ns : v.exit ? v.exit.ts_ns : 0n
          if (inSlice(vts)) br.visits.push(v)
        }
        for (const cp of on.calls) {
          const cts = cp.entry ? cp.entry.ts_ns : 0n
          if (inSlice(cts)) br.calls.push(cp)
        }
      }
      for (const r of p.rels) {
        br.events.push(r.event)
        br.unknown_must.push(...r.event.unknown_must)
      }
      sortByTsProdSeq(br.events)
      sortByTsSeq(br.steps)
      sortByTsSeq(br.summaries)
      if (br.events.length > 0) {
        br.start_ts_ns = br.events[0]!.ts_ns
        br.end_ts_ns = br.events[0]!.ts_ns
        for (const e of br.events) {
          if (e.ts_ns < br.start_ts_ns) br.start_ts_ns = e.ts_ns
          if (e.ts_ns > br.end_ts_ns) br.end_ts_ns = e.ts_ns
        }
      }

      const seenQS = new Set<QStateAnnotation>()
      for (const v of br.visits) {
        for (const qs of v.backpressure) {
          if (!seenQS.has(qs)) {
            seenQS.add(qs)
            br.qstates.push(qs)
          }
        }
      }
      const touched = new Set<bigint>()
      for (const list of [br.steps, br.summaries]) {
        for (const e of list) {
          const ifx = e.u('ifindex')
          if (ifx !== 0n) touched.add(ifx)
        }
      }
      const tl = [...touched].sort(cmpBigInt)
      for (const ifx of tl) {
        for (const qs of matchingQStates(s.qstates, ifx, undefined, br.start_ts_ns, br.end_ts_ns)) {
          if (!seenQS.has(qs)) {
            seenQS.add(qs)
            br.qstates.push(qs)
          }
        }
      }
      br.qstates.sort((a, b) => cmpBigInt(a.start_ns, b.start_ns))

      for (const st of br.steps) {
        const g = st.num('stage')
        if (g === STAGE_REQUEUE_GSO || g === STAGE_REQUEUE_BAD_TXQ) br.requeue_count++
      }

      const explicit: string[] = []
      const vc: string[] = []
      if (br.unknown_must.length > 0) explicit.push('INCOMPLETE_UNKNOWN_MUST_TLV')
      let partial = partialManifest
      if (!partial) {
        for (const e of br.events) {
          if ((e.flags & EV_FLAG_PARTIAL_COVERAGE) !== 0) {
            partial = true
            break
          }
        }
      }
      if (partial) explicit.push('PARTIAL_COVERAGE')
      for (const e of br.events) {
        if (e.kind !== KIND_QUALITY && e.evidence_level === EVIDENCE_GAP) {
          explicit.push('EVIDENCE_GAP')
          break
        }
      }
      if (idConflict) explicit.push('IDENTITY_CONFLICT')
      if (br.successor_truncated) explicit.push('SUCCESSOR_TRUNCATED')
      if (uncleanTail) {
        if (br.end_reason === END_OPEN || br.end_ts_ns > ls.last_quality_checkpoint_ts_ns) {
          explicit.push('UNKNOWN_TAIL')
          if (br.end_reason === END_OPEN) br.end_reason_name = 'UNKNOWN_TAIL'
        }
      }
      if (br.end_reason === END_OPEN) {
        if (!explicit.includes('UNKNOWN_TAIL')) explicit.push('OPEN_UNFINISHED')
      } else if (br.end_reason === END_TIMEOUT_TRUNCATED) {
        explicit.push('TIMEOUT_TRUNCATED')
      } else if (br.end_reason === END_CONFLICT_TRUNCATED) {
        explicit.push('CONFLICT_TRUNCATED')
      }
      for (const g of s.seq_gaps) {
        if (seqGapOverlapsBranch(g, br)) {
          explicit.push('SEQ_GAP')
          break
        }
      }
      const bset = new Set<bigint>(oids)
      for (const lq of loss) {
        if (lq.oid !== 0n) {
          if (bset.has(lq.oid) && !explicit.includes(lq.name)) explicit.push(lq.name)
        } else if (br.start_ts_ns <= lq.we && br.end_ts_ns >= lq.ws && !explicit.includes(lq.name)) {
          explicit.push(lq.name)
        }
      }
      for (const v of br.visits) {
        if (v.ambiguous) vc.push('AMBIGUOUS_VISIT')
        else if (!v.paired && !v.enq_dropped) vc.push('UNCLOSED_VISIT')
      }
      for (const cp of br.calls) {
        if (cp.ambiguous) vc.push('AMBIGUOUS_CALL')
        else if (!cp.paired) vc.push('UNMATCHED_CALL_RETURN')
      }

      if (explicit.length > 0) {
        br.completeness = 'incomplete'
        br.complete = false
        br.gap_reasons = dedupStrings([...explicit, ...vc])
      } else if (s.has_unobservable_missed_src) {
        br.completeness = 'unknown'
        br.complete = false
        br.gap_reasons = dedupStrings(['UNOBSERVABLE_MISSED_SOURCE', ...vc])
      } else if (vc.length > 0) {
        br.completeness = 'incomplete'
        br.complete = false
        br.gap_reasons = dedupStrings(vc)
      } else {
        br.completeness = 'complete'
        br.complete = true
        br.gap_reasons = []
      }
      sbranches.push(br)
      s.branches.push(br)
    }

    const sg: SampleGraph = {
      sample_id: sid,
      root_object_ids: roots,
      object_ids: objList,
      relations: sampleRels,
      branches: sbranches,
      complete: false,
      completeness: 'complete',
      gap_reasons: [],
      successor_truncated: false,
      unknown_predecessors: false,
      attr: {},
      first_ts_ns: 0n,
      last_ts_ns: 0n,
    }
    let firstSet = false
    for (const oid of objList) {
      const o = s.objects.get(oid)!
      if (o.first_ts_ns > 0n && (!firstSet || o.first_ts_ns < sg.first_ts_ns)) {
        sg.first_ts_ns = o.first_ts_ns
        firstSet = true
      }
      if (o.last_ts_ns > sg.last_ts_ns) sg.last_ts_ns = o.last_ts_ns
      mergeAttributionMissing(sg.attr, o.attr)
      if (o.successor_truncated) sg.successor_truncated = true
      if (o.unknown_predecessors) sg.unknown_predecessors = true
    }
    let anyIncomplete = false
    let anyUnknown = false
    for (const br of sbranches) {
      for (const g of br.gap_reasons) {
        if (!sg.gap_reasons.includes(g)) sg.gap_reasons.push(g)
      }
      if (br.successor_truncated) sg.successor_truncated = true
      if (br.unknown_predecessors) sg.unknown_predecessors = true
      if (br.completeness === 'incomplete') anyIncomplete = true
      if (br.completeness === 'unknown') anyUnknown = true
    }
    if (anyIncomplete || sg.successor_truncated) {
      sg.completeness = 'incomplete'
      sg.complete = false
    } else if (anyUnknown || s.has_unobservable_missed_src) {
      sg.completeness = 'unknown'
      sg.complete = false
    } else {
      sg.completeness = 'complete'
      sg.complete = sbranches.length > 0
    }
    s.samples.set(sid, sg)
  }

  s.reorder_count = computeReorderCount(s)
  s.requeue_count = s.requeue_gso_count + s.requeue_bad_txq_count
  return s
}

export function openReconstructedSession(dir: string): Session {
  const ls = loadSession(dir, false)
  return reconstruct(ls)
}
