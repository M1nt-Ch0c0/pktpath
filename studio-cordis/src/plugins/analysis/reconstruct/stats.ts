// Pure TypeScript port of studio/pkg/reconstruct/stats.go (erasableSyntaxOnly).
// All uint64 IDs/timestamps are stored as bigint internally and serialized as
// decimal strings in JSON views per WAVE1-CONTRACT.md v1.1.

import {
  DIR_RX,
  END_TX_OK,
  OBJ_SKB,
  QUAL_IDENTITY_CONFLICT,
  QUAL_MISSED_DELTA,
  QUAL_RB_DROP_DELTA,
  QUAL_RET_UNMATCHED,
  QUAL_TOPO_DESYNC,
  STAGE_BYPASS_DIRECT,
  STAGE_CLASSIFY,
  STAGE_DROP,
  STAGE_ENTRY,
  STAGE_HANDOFF_LAYER,
  STAGE_QDISC_ENQ,
  STAGE_REQUEUE_BAD_TXQ,
  STAGE_REQUEUE_GSO,
  STAGE_XMIT_START,
} from '../wire/consts.ts'
import { formatUUID, intOr, isUncleanTail } from '../wire/wire.ts'
import {
  branchLeafObjectId,
  objectInitialSummary,
  objectLatestSummary,
} from './model.ts'
import type { BranchPath, QueueVisit, Session } from './model.ts'
import {
  evOpt,
  formatClassRate,
  formatTCHandle,
  isParentTCClass,
  manifestStr,
} from './topo.ts'

export interface Admissions {
  filter_unknown: number
  matched: number
  selected: number
  created: number
  rejected: number
}

export interface BranchCounts {
  total: number
  complete: number
  incomplete: number
  unknown: number
  unknown_completeness: number
}

export interface SampleCounts {
  total: number
  objects_total: number
  events_total: number
  dedup_dropped: number
}

export interface QueueStat {
  label: string
  kind: string
  visit_kind: string
  handle: string
  parent: string
  class_id?: string
  class_rate?: string
  class_rate_bps?: string
  class_ceil_bps?: string
  class_prio?: number
  queue_gen: string
  netns_inum: string
  ifindex: string
  dev_gen: string
  dev_name: string
  txq: string | null
  n: number
  paired_n: number
  unpaired_n: number
  enq_drop_n: number
  drop_count: number
  p50_us: number | null
  p95_us: number | null
  p99_us: number | null
  min_us: number | null
  max_us: number | null
  mean_us: number | null
}

export interface PathGroup {
  path_sig: string
  tokens: string[]
  endpoint: string
  count: number
  complete_count: number
  incomplete_count: number
  unknown_count: number
  p50_us: number | null
  p95_us: number | null
  p99_us: number | null
  sojourn_p50_us: number | null
  sojourn_p95_us: number | null
  sojourn_p99_us: number | null
  wire_bytes: number
  skb_bytes: number
  endpoints: Record<string, number>
  sample_ids: string[]
}

export interface Group {
  key: string
  branch_count: number
  complete: number
  incomplete: number
  unknown_completeness: number
  skb_bytes: number
  wire_bytes: number
  endpoints: Record<string, number>
}

export interface QualitySummary {
  seq_gap_windows: number
  seq_gap_missing_events: number
  missed_delta: number
  rb_drop_delta: number
  ret_unmatched: number
  identity_conflict: number
  topo_desync: number
  unclean_tail: boolean
  unobservable_missed_source: boolean
}

export interface QualityAlert {
  kind: string
  severity: 'info' | 'warn' | 'error'
  count: number
  message: string
}

export interface Stats {
  session_uuid: string
  scope: string
  mode: string
  sample_rate: string
  group_by: string
  admissions: Admissions
  samples: SampleCounts
  branches: BranchCounts
  endpoints: Record<string, number>
  requeue_count: number
  requeue_gso_count: number
  requeue_bad_txq_count: number
  reorder_count: number
  skb_bytes: number
  wire_bytes: number
  skb_packets: number
  wire_packets: number
  queues: QueueStat[]
  paths: PathGroup[]
  groups: Group[]
  quality: QualitySummary
  unclean_tail: boolean
  tail_errors: string[]
  quality_alerts: QualityAlert[]
}

export function round3(x: number): number {
  return Math.round(x * 1000) / 1000
}

export function percentile(sorted: number[], pct: number): number | null {
  if (sorted.length === 0) return null
  if (sorted.length === 1) return round3(sorted[0]!)
  const rank = (pct / 100.0) * (sorted.length - 1)
  const lo = Math.floor(rank)
  const hi = Math.ceil(rank)
  if (lo === hi) return round3(sorted[lo]!)
  const w = rank - lo
  return round3(sorted[lo]! * (1 - w) + sorted[hi]! * w)
}

export function branchPathTokens(s: Session, br: BranchPath): string[] {
  const tokens: string[] = []
  const push = (tok: string): void => {
    if (tokens.length === 0 || tokens[tokens.length - 1] !== tok) tokens.push(tok)
  }
  for (const st of br.steps) {
    const stage = st.num('stage')
    const ifidx = st.u('ifindex')
    const dev = s.resolveDevName(ifidx, evOpt(st, 'dev_gen'))
    switch (stage) {
      case STAGE_ENTRY:
        tokens.push(`ENTRY(${dev})`)
        break
      case STAGE_CLASSIFY:
      case STAGE_QDISC_ENQ: {
        const qhandle = st.u('qdisc_handle')
        const qparent = st.u('qdisc_parent')
        const cid = st.u('classid')
        if (stage === STAGE_CLASSIFY && qhandle === 0n && cid !== 0n) {
          push('CLASS:' + formatTCHandle(cid))
          continue
        }
        if (cid !== 0n) push('CLASS:' + formatTCHandle(cid))
        const qi = s.resolveQdiscInfo(
          ifidx,
          evOpt(st, 'queue_gen'),
          evOpt(st, 'qdisc_handle'),
          evOpt(st, 'qdisc_parent'),
          evOpt(st, 'dev_gen'),
          st.ts_ns,
        )
        let kind = 'QDISC'
        if (qi && qi.kind !== '') {
          kind = qi.kind.toUpperCase()
        } else if (!s.isTopoDesyncedAt(st.ts_ns)) {
          const inf = s.inferQdiscKind(st.site_dict_idx)
          if (inf !== '') kind = inf.toUpperCase()
        }
        const lbl =
          qhandle === 0n && isParentTCClass(qparent)
            ? `${kind}@${formatTCHandle(qparent)}`
            : `${kind}:${formatTCHandle(evOpt(st, 'qdisc_handle'))}`
        push(lbl)
        break
      }
      case STAGE_BYPASS_DIRECT:
        tokens.push('BYPASS_DIRECT')
        break
      case STAGE_REQUEUE_GSO:
        tokens.push('REQUEUE_GSO')
        break
      case STAGE_REQUEUE_BAD_TXQ:
        tokens.push('REQUEUE_BAD_TXQ')
        break
      case STAGE_HANDOFF_LAYER:
        tokens.push(`HANDOFF(${dev})`)
        break
      case STAGE_XMIT_START:
        tokens.push(`XMIT(${dev}:txq${st.u('txq').toString()})`)
        break
    }
  }
  tokens.push(br.end_reason_name)
  return tokens
}

export function branchPathSignature(s: Session, br: BranchPath): string {
  return branchPathTokens(s, br).join(' -> ')
}

function branchLeafSignature(s: Session, br: BranchPath): string {
  if (br.visits.length > 0) {
    let v: QueueVisit | undefined
    for (const x of br.visits) {
      if (x.visit_kind === 'qdisc') v = x
    }
    if (!v) v = br.visits[br.visits.length - 1]!
    const dev = s.resolveDevName(v.ifindex, v.dev_gen)
    let kind = v.visit_kind
    if (v.visit_kind === 'qdisc') {
      const resolved = s.resolveVisitQdiscKind(v)
      if (resolved !== '') kind = resolved
    }
    const txq = v.txq !== undefined ? `:txq${v.txq.toString()}` : ''
    if (v.qdisc_handle === 0n && isParentTCClass(v.qdisc_parent)) {
      return `${dev}:${kind}@${formatTCHandle(v.qdisc_parent)}(gen=${v.queue_gen.toString()}${txq})`
    }
    return `${dev}:${kind}:${formatTCHandle(v.qdisc_handle)}(parent=${formatTCHandle(v.qdisc_parent)},gen=${v.queue_gen.toString()}${txq})`
  }
  for (const st of br.steps) {
    if (st.num('stage') === STAGE_BYPASS_DIRECT) return 'BYPASS_DIRECT'
  }
  return 'NO_QUEUE_VISIT'
}

function branchUIDKey(s: Session, br: BranchPath): string {
  const sg = s.samples.get(br.sample_id)
  if (sg && sg.attr.uid !== undefined) return sg.attr.uid.toString()
  for (const sm of br.summaries) {
    const v = sm.get('uid')
    if (v !== undefined) return v.toString()
  }
  return 'unknown'
}

function admissionVal(m: Record<string, unknown>, ...keys: string[]): number {
  for (const k of keys) {
    if (k in m) return intOr(m[k], 0)
  }
  return 0
}

function queueLabel(
  dev: string,
  kind: string,
  handle: bigint | undefined,
  parent: bigint | undefined,
  txq: bigint | undefined,
  qgen: bigint,
  vkind: string,
): string {
  let out = `${dev} `
  if (vkind === 'qdisc' && (handle === undefined || handle === 0n) && parent !== undefined && isParentTCClass(parent)) {
    out += `${kind.toUpperCase()} @ ${formatTCHandle(parent)}`
    if (qgen > 0n) out += ` (gen=${qgen.toString()})`
    return out
  }
  if (vkind === 'requeue_gso') out += 'gso_skb 重排队列'
  else if (vkind === 'requeue_bad_txq') out += 'skb_bad_txq 队列'
  else out += `${kind.toUpperCase()} ${formatTCHandle(handle)}`
  const extras: string[] = []
  if (handle === 0n && txq !== undefined) extras.push(`txq=${txq.toString()}`)
  if (qgen > 0n) extras.push(`gen=${qgen.toString()}`)
  if (extras.length > 0) out += ` (${extras.join(', ')})`
  return out
}

function branchSojournSumUs(br: BranchPath): number | undefined {
  let sum = 0
  let any = false
  for (const v of br.visits) {
    if (v.paired && v.sojourn_ns !== undefined) {
      sum += Number(v.sojourn_ns) / 1000.0
      any = true
    }
  }
  return any ? sum : undefined
}

function groupBytes(s: Session, bl: BranchPath[]): { skb: number; wireB: number } {
  let skb = 0
  let wireB = 0
  const roots = new Set<bigint>()
  const txs = new Set<bigint>()
  for (const b of bl) {
    const root = b.object_ids[0]!
    const rootObj = s.objects.get(root)
    if (!roots.has(root) && rootObj && rootObj.object_type === OBJ_SKB) {
      roots.add(root)
      const s0 = objectInitialSummary(rootObj)
      if (s0) skb += s0.num('pkt_len')
    }
    const leaf = branchLeafObjectId(b)
    if (b.end_reason === END_TX_OK && !txs.has(leaf)) {
      txs.add(leaf)
      const leafObj = s.objects.get(leaf)
      const sl = leafObj ? objectLatestSummary(leafObj) : undefined
      if (sl) wireB += sl.num('pkt_len')
    }
  }
  return { skb, wireB }
}

function groupBranches(s: Session, groupBy: string): Group[] {
  const groups = new Map<string, BranchPath[]>()
  const keys: string[] = []
  for (const br of s.branches) {
    let k: string
    if (groupBy === 'path') k = branchPathSignature(s, br)
    else if (groupBy === 'leaf') k = branchLeafSignature(s, br)
    else if (groupBy === 'status') k = `${br.completeness}:${br.end_reason_name}`
    else k = branchUIDKey(s, br)
    let list = groups.get(k)
    if (!list) {
      list = []
      groups.set(k, list)
      keys.push(k)
    }
    list.push(br)
  }
  keys.sort((a, b) => {
    const la = groups.get(a)!.length
    const lb = groups.get(b)!.length
    if (la !== lb) return lb - la
    return a < b ? -1 : a > b ? 1 : 0
  })
  const out: Group[] = []
  for (const k of keys) {
    const bl = groups.get(k)!
    const { skb, wireB } = groupBytes(s, bl)
    const endpoints: Record<string, number> = {}
    let complete = 0
    let incomplete = 0
    let unknownCompleteness = 0
    for (const b of bl) {
      endpoints[b.end_reason_name] = (endpoints[b.end_reason_name] ?? 0) + 1
      if (b.completeness === 'complete') complete++
      else if (b.completeness === 'incomplete') incomplete++
      else if (b.completeness === 'unknown') unknownCompleteness++
    }
    out.push({
      key: k,
      branch_count: bl.length,
      complete,
      incomplete,
      unknown_completeness: unknownCompleteness,
      skb_bytes: skb,
      wire_bytes: wireB,
      endpoints,
    })
  }
  return out
}

function buildPathGroups(s: Session): PathGroup[] {
  const groups = new Map<string, BranchPath[]>()
  const tokensOf = new Map<string, string[]>()
  const keys: string[] = []
  for (const br of s.branches) {
    const toks = branchPathTokens(s, br)
    const k = toks.join(' -> ')
    let list = groups.get(k)
    if (!list) {
      list = []
      groups.set(k, list)
      tokensOf.set(k, toks)
      keys.push(k)
    }
    list.push(br)
  }
  keys.sort((a, b) => {
    const la = groups.get(a)!.length
    const lb = groups.get(b)!.length
    if (la !== lb) return lb - la
    return a < b ? -1 : a > b ? 1 : 0
  })
  const out: PathGroup[] = []
  for (const k of keys) {
    const bl = groups.get(k)!
    const toks = tokensOf.get(k)!
    const endpoints: Record<string, number> = {}
    const sampleIds: string[] = []
    const seenS = new Set<bigint>()
    const totals: number[] = []
    const sojs: number[] = []
    let completeCount = 0
    let incompleteCount = 0
    let unknownCount = 0
    for (const b of bl) {
      endpoints[b.end_reason_name] = (endpoints[b.end_reason_name] ?? 0) + 1
      if (b.completeness === 'complete') completeCount++
      else if (b.completeness === 'incomplete') incompleteCount++
      else if (b.completeness === 'unknown') unknownCount++
      totals.push(Number(b.end_ts_ns - b.start_ts_ns) / 1000.0)
      const sj = branchSojournSumUs(b)
      if (sj !== undefined) sojs.push(sj)
      if (!seenS.has(b.sample_id)) {
        seenS.add(b.sample_id)
        sampleIds.push(b.sample_id.toString())
      }
    }
    totals.sort((a, b) => a - b)
    sojs.sort((a, b) => a - b)
    const { skb, wireB } = groupBytes(s, bl)
    out.push({
      path_sig: k,
      tokens: toks,
      endpoint: toks[toks.length - 1]!,
      count: bl.length,
      complete_count: completeCount,
      incomplete_count: incompleteCount,
      unknown_count: unknownCount,
      p50_us: percentile(totals, 50),
      p95_us: percentile(totals, 95),
      p99_us: percentile(totals, 99),
      sojourn_p50_us: percentile(sojs, 50),
      sojourn_p95_us: percentile(sojs, 95),
      sojourn_p99_us: percentile(sojs, 99),
      wire_bytes: wireB,
      skb_bytes: skb,
      endpoints,
      sample_ids: sampleIds,
    })
  }
  return out
}

function buildQualityAlerts(s: Session, st: Stats): QualityAlert[] {
  const out: QualityAlert[] = []
  const q = st.quality
  const add = (kind: string, severity: 'info' | 'warn' | 'error', count: number, message: string): void => {
    out.push({ kind, severity, count, message })
  }
  if (q.seq_gap_windows > 0) {
    add(
      'SEQ_GAP',
      'warn',
      q.seq_gap_missing_events,
      `检测到 ${q.seq_gap_windows} 个事件序号缺口（共缺失 ${q.seq_gap_missing_events} 个事件，ringbuf 导出丢失）`,
    )
  }
  if (q.missed_delta > 0) {
    add('MISSED_DELTA', 'warn', q.missed_delta, `探针漏触发 nmissed/recursion_misses 累计 ${q.missed_delta} 次，重叠支路已标记不完整`)
  }
  if (q.rb_drop_delta > 0) {
    add('RB_DROP_DELTA', 'warn', q.rb_drop_delta, `ringbuf 预留失败丢弃 ${q.rb_drop_delta} 个事件`)
  }
  if (q.ret_unmatched > 0) {
    add('RET_UNMATCHED', 'warn', q.ret_unmatched, `${q.ret_unmatched} 个函数返回事件未能与入口配对`)
  }
  if (q.identity_conflict > 0) {
    add('IDENTITY_CONFLICT', 'warn', q.identity_conflict, `${q.identity_conflict} 次地址身份冲突（已隔离，不污染其他样本）`)
  }
  if (q.topo_desync > 0) {
    add('TOPO_DESYNC', 'warn', q.topo_desync, `拓扑快照失步 ${q.topo_desync} 次，期间 Qdisc 种类标记为未知`)
  }
  if (q.unclean_tail) {
    let msg = '会话缺少 END_MARKER 或末尾数据块损坏 (UNKNOWN_TAIL)，已重放有效数据块'
    if (st.tail_errors.length > 0) msg += '：' + st.tail_errors.join('; ')
    add('UNCLEAN_TAIL', 'error', 1, msg)
  }
  if (q.unobservable_missed_source) {
    add(
      'UNOBSERVABLE_MISSED_SOURCE',
      'info',
      s.unobservable_adapters.length,
      '部分适配器无法观测漏报计数 (missed_source=none)，完整性记为未知: ' + s.unobservable_adapters.join(', '),
    )
  }
  if (st.branches.incomplete > 0) {
    add('INCOMPLETE_BRANCHES', 'info', st.branches.incomplete, `${st.branches.incomplete}/${st.branches.total} 条支路不完整`)
  }
  return out
}

export function computeStats(s: Session, groupBy = 'path'): Stats {
  const gb = groupBy === '' ? 'path' : groupBy
  if (gb !== 'path' && gb !== 'leaf' && gb !== 'status' && gb !== 'uid') {
    throw new Error(`unsupported group_by value: ${JSON.stringify(gb)}`)
  }
  const rawAdm =
    typeof s.manifest['admissions'] === 'object' &&
    s.manifest['admissions'] !== null &&
    !Array.isArray(s.manifest['admissions'])
      ? (s.manifest['admissions'] as Record<string, unknown>)
      : {}

  const endpoints: Record<string, number> = {}
  let complete = 0
  let incomplete = 0
  let unknown = 0
  for (const b of s.branches) {
    if (b.completeness === 'complete') complete++
    else if (b.completeness === 'incomplete') incomplete++
    else if (b.completeness === 'unknown') unknown++
    endpoints[b.end_reason_name] = (endpoints[b.end_reason_name] ?? 0) + 1
  }

  let skbBytes = 0
  let skbPackets = 0
  let rxWire = 0
  let rxPk = 0
  for (const oid of s.object_order) {
    const obj = s.objects.get(oid)!
    if (obj.object_type !== OBJ_SKB) continue
    let hasSkbParent = false
    for (const r of obj.incoming) {
      const p = s.objects.get(r.src_object_id)
      if (p && p.object_type === OBJ_SKB) {
        hasSkbParent = true
        break
      }
    }
    if (hasSkbParent) continue
    const init = objectInitialSummary(obj)
    const plen = init ? init.num('pkt_len') : 0
    skbBytes += plen
    skbPackets++
    if (init) {
      const d = init.get('dir')
      if (d !== undefined && Number(d) === DIR_RX) {
        rxWire += plen
        rxPk++
      }
    }
  }

  let txWire = 0
  let txPk = 0
  const counted = new Set<bigint>()
  for (const br of s.branches) {
    const leaf = branchLeafObjectId(br)
    if (br.end_reason === END_TX_OK && !counted.has(leaf)) {
      counted.add(leaf)
      const leafObj = s.objects.get(leaf)
      let last = leafObj ? objectLatestSummary(leafObj) : undefined
      if (!last && br.summaries.length > 0) last = br.summaries[br.summaries.length - 1]
      if (last) txWire += last.num('pkt_len')
      txPk++
    }
  }

  interface QKey {
    netns: bigint
    ifidx: bigint
    dgen: bigint
    qgen: bigint
    vkind: string
    handle: bigint
    parent: bigint
    txqOK: boolean
    txq: bigint
    str: string
  }
  const seenV = new Set<string>()
  const buckets = new Map<string, QueueVisit[]>()
  const bkeys: QKey[] = []
  for (const oid of s.object_order) {
    for (const v of s.objects.get(oid)!.visits) {
      const vu = `${v.object_id}:${v.queue_gen}:${v.visit_id}`
      if (seenV.has(vu)) continue
      seenV.add(vu)
      const txqOK = v.qdisc_handle === 0n && v.txq !== undefined
      const txqVal = txqOK ? v.txq! : 0n
      const str = `${v.netns_inum}:${v.ifindex}:${v.dev_gen}:${v.queue_gen}:${v.visit_kind}:${v.qdisc_handle}:${v.qdisc_parent}:${txqOK ? 1 : 0}:${txqVal}`
      let list = buckets.get(str)
      if (!list) {
        list = []
        buckets.set(str, list)
        bkeys.push({
          netns: v.netns_inum,
          ifidx: v.ifindex,
          dgen: v.dev_gen,
          qgen: v.queue_gen,
          vkind: v.visit_kind,
          handle: v.qdisc_handle,
          parent: v.qdisc_parent,
          txqOK,
          txq: txqVal,
          str,
        })
      }
      list.push(v)
    }
  }

  bkeys.sort((a, b) => {
    if (a.netns !== b.netns) return a.netns < b.netns ? -1 : 1
    if (a.ifidx !== b.ifidx) return a.ifidx < b.ifidx ? -1 : 1
    if (a.dgen !== b.dgen) return a.dgen < b.dgen ? -1 : 1
    if (a.qgen !== b.qgen) return a.qgen < b.qgen ? -1 : 1
    if (a.vkind !== b.vkind) return a.vkind < b.vkind ? -1 : 1
    if (a.handle !== b.handle) return a.handle < b.handle ? -1 : 1
    if (a.parent !== b.parent) return a.parent < b.parent ? -1 : 1
    if (a.txqOK !== b.txqOK) return a.txqOK ? 1 : -1
    return a.txq < b.txq ? -1 : a.txq > b.txq ? 1 : 0
  })

  const queues: QueueStat[] = []
  for (const k of bkeys) {
    const vl = buckets.get(k.str)!
    const dev = s.resolveDevName(k.ifidx, k.dgen, k.netns)
    const refTs = vl[0]!.entry ? vl[0]!.entry.ts_ns : vl[0]!.exit ? vl[0]!.exit.ts_ns : undefined
    const qi = s.resolveQdiscInfo(k.ifidx, k.qgen, k.handle, k.parent, k.dgen, refTs)
    let kind = 'qdisc'
    if (k.vkind !== 'qdisc') kind = k.vkind
    else if (qi && qi.kind !== '') kind = qi.kind
    else {
      const inf = s.resolveVisitQdiscKind(vl[0]!)
      if (inf !== '') kind = inf
    }
    const us: number[] = []
    let unpaired = 0
    let enqDrop = 0
    let qdrop = 0
    for (const v of vl) {
      if (v.paired && v.sojourn_ns !== undefined) us.push(Number(v.sojourn_ns) / 1000.0)
      if (!v.paired && !v.enq_dropped) unpaired++
      if (v.enq_dropped) enqDrop++
      if (v.exit && v.exit.num('stage') === STAGE_DROP) qdrop++
    }
    us.sort((a, b) => a - b)

    const txq = k.txqOK ? k.txq : vl[0]!.txq
    const q: QueueStat = {
      label: queueLabel(dev, kind, k.handle, k.parent, txq, k.qgen, k.vkind),
      kind,
      visit_kind: k.vkind,
      handle: formatTCHandle(k.handle),
      parent: formatTCHandle(k.parent),
      queue_gen: k.qgen.toString(),
      netns_inum: k.netns.toString(),
      ifindex: k.ifidx.toString(),
      dev_gen: k.dgen.toString(),
      dev_name: dev,
      txq: txq !== undefined ? txq.toString() : null,
      n: us.length,
      paired_n: us.length,
      unpaired_n: unpaired,
      enq_drop_n: enqDrop,
      drop_count: enqDrop + qdrop,
      p50_us: percentile(us, 50),
      p95_us: percentile(us, 95),
      p99_us: percentile(us, 99),
      min_us: us.length > 0 ? round3(us[0]!) : null,
      max_us: us.length > 0 ? round3(us[us.length - 1]!) : null,
      mean_us: us.length > 0 ? round3(us.reduce((acc, x) => acc + x, 0) / us.length) : null,
    }
    let cidLookup = 0n
    if (isParentTCClass(k.parent)) cidLookup = k.parent
    else if (vl[0]!.classid !== 0n) cidLookup = vl[0]!.classid
    if (cidLookup !== 0n) {
      q.class_id = formatTCHandle(cidLookup)
      const ci = s.resolveClassInfo(k.ifidx, cidLookup, k.dgen, refTs)
      if (ci) {
        const rate = formatClassRate(ci.rate_bps, ci.ceil_bps)
        if (rate !== '') q.class_rate = rate
        if (ci.rate_bps > 0n) q.class_rate_bps = ci.rate_bps.toString()
        if (ci.ceil_bps > 0n) q.class_ceil_bps = ci.ceil_bps.toString()
        if (ci.has_prio) q.class_prio = ci.prio
      }
    }
    queues.push(q)
  }

  let missed = 0n
  let rbdrop = 0n
  let retun = 0n
  let idc = 0n
  let topo = 0n
  for (const q of s.quality_events) {
    const k = q.num('qual_kind')
    const c = q.u('count')
    const atLeast1 = c < 1n ? 1n : c
    if (k === QUAL_MISSED_DELTA) missed += c
    else if (k === QUAL_RB_DROP_DELTA) rbdrop += c
    else if (k === QUAL_RET_UNMATCHED) retun += atLeast1
    else if (k === QUAL_IDENTITY_CONFLICT) idc += atLeast1
    else if (k === QUAL_TOPO_DESYNC) topo += atLeast1
  }
  let gapMissing = 0n
  for (const g of s.seq_gaps) gapMissing += g.missing_count

  const uncleanTail = isUncleanTail(s.loaded)
  const st: Stats = {
    session_uuid: formatUUID(s.loaded.session_uuid),
    scope: manifestStr(s.manifest, 'scope', 'tc-egress'),
    mode: manifestStr(s.manifest, 'mode', 'oneshot'),
    sample_rate: manifestStr(s.manifest, 'sample_rate', '1/1'),
    group_by: gb,
    admissions: {
      filter_unknown: admissionVal(rawAdm, 'filter_unknown'),
      matched: admissionVal(rawAdm, 'matched', 'admission_matched'),
      selected: admissionVal(rawAdm, 'selected', 'admission_selected'),
      created: admissionVal(rawAdm, 'created', 'admission_created'),
      rejected: admissionVal(rawAdm, 'rejected', 'admission_rejected'),
    },
    samples: {
      total: s.samples.size,
      objects_total: s.objects.size,
      events_total: s.events.length,
      dedup_dropped: s.dedup_dropped,
    },
    branches: {
      total: s.branches.length,
      complete,
      incomplete,
      unknown,
      unknown_completeness: unknown,
    },
    endpoints,
    requeue_count: s.requeue_count,
    requeue_gso_count: s.requeue_gso_count,
    requeue_bad_txq_count: s.requeue_bad_txq_count,
    reorder_count: s.reorder_count,
    skb_bytes: skbBytes,
    wire_bytes: txWire + rxWire,
    skb_packets: skbPackets,
    wire_packets: txPk + rxPk,
    queues,
    paths: buildPathGroups(s),
    groups: groupBranches(s, gb),
    quality: {
      seq_gap_windows: s.seq_gaps.length,
      seq_gap_missing_events: Number(gapMissing),
      missed_delta: Number(missed),
      rb_drop_delta: Number(rbdrop),
      ret_unmatched: Number(retun) + s.unmatched_returns.length,
      identity_conflict: Number(idc),
      topo_desync: Number(topo),
      unclean_tail: uncleanTail,
      unobservable_missed_source: s.has_unobservable_missed_src,
    },
    unclean_tail: uncleanTail,
    tail_errors: [...s.loaded.tail_errors],
    quality_alerts: [],
  }
  st.quality_alerts = buildQualityAlerts(s, st)
  return st
}
